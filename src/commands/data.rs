#![forbid(unsafe_code)]

use crate::agent::agent_get_decryption_key;
use crate::blob::{Account, Blob};
use crate::config::{
    config_exists, config_mtime, config_read_buffer, config_read_encrypted_buffer, config_touch,
    config_write_buffer, config_write_encrypted_buffer,
};
use crate::crypto::{aes_encrypt_lastpass, base64_lastpass_encode, decrypt_private_key};
use crate::error::{LpassError, Result};
use crate::http::HttpClient;
use crate::kdf::KDF_HASH_LEN;
use crate::session::Session;
use serde_json;
use std::time::{Duration, SystemTime};

const BLOB_JSON_NAME: &str = "blob.json";

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SyncMode {
    Auto,
    Now,
    No,
}

impl SyncMode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "now" => Some(Self::Now),
            "no" => Some(Self::No),
            _ => None,
        }
    }
}

pub(crate) fn load_blob(sync_mode: SyncMode) -> Result<Blob> {
    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
        return load_mock_blob();
    }

    let key = agent_get_decryption_key().map_err(map_decryption_key_error)?;
    let mut session = crate::session::session_load(&key)
        .map_err(map_decryption_key_error)?
        .ok_or(LpassError::User(
            "Could not find session. Perhaps you need to login with `lpass login`.",
        ))?;
    let private_key = load_private_key(&key)?;
    let client = HttpClient::from_env()?;

    let blob = match sync_mode {
        SyncMode::No => load_local_blob(&key, private_key.as_deref())?,
        SyncMode::Now => load_latest_blob(&client, &mut session, &key, private_key.as_deref())?,
        SyncMode::Auto => {
            if local_blob_is_fresh(auto_sync_time())? {
                load_local_blob(&key, private_key.as_deref())?
            } else {
                load_latest_blob(&client, &mut session, &key, private_key.as_deref())?
            }
        }
    };
    Ok(blob)
}

fn load_local_blob(key: &[u8; KDF_HASH_LEN], private_key: Option<&[u8]>) -> Result<Blob> {
    if let Some(buffer) = config_read_encrypted_buffer(BLOB_JSON_NAME, key)? {
        let blob = serde_json::from_slice::<Blob>(&buffer)
            .map_err(|_| LpassError::Crypto("invalid blob"))?;
        return Ok(blob);
    }

    let blob_bytes = config_read_encrypted_buffer("blob", key)?.ok_or(LpassError::Crypto(
        "Unable to fetch blob. Either your session is invalid and you need to login with `lpass login`, you need to synchronize, your blob is empty, or there is something wrong with your internet connection.",
    ))?;
    if !looks_like_blob(&blob_bytes) {
        return Err(LpassError::Crypto(
            "blob response was not a blob; try logging in again",
        ));
    }
    crate::blob::blob_parse(&blob_bytes, key, private_key)
}

fn load_latest_blob(
    client: &HttpClient,
    session: &mut Session,
    key: &[u8; KDF_HASH_LEN],
    private_key: Option<&[u8]>,
) -> Result<Blob> {
    let local = load_local_blob(key, private_key).ok();
    if let Some(local_blob) = local {
        let remote_version = fetch_remote_blob_version(client, session, key)?;
        if remote_version == 0 {
            return Err(blob_fetch_error());
        }
        if remote_version <= local_blob.version {
            touch_local_blob_cache()?;
            return Ok(local_blob);
        }
    }

    fetch_and_store_blob(client, session, key, private_key)
}

fn fetch_remote_blob_version(
    client: &HttpClient,
    session: &mut Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<u64> {
    let response =
        client.post_lastpass(None, "login_check.php", Some(session), &[("method", "cli")])?;
    if response.status >= 400 {
        return Ok(0);
    }
    let version = crate::xml::parse_login_check(&response.body, session).unwrap_or(0);
    if version > 0 {
        let _ = crate::session::session_save(session, key);
    }
    Ok(version)
}

fn fetch_and_store_blob(
    client: &HttpClient,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
    private_key: Option<&[u8]>,
) -> Result<Blob> {
    let params = [
        ("mobile", "1"),
        ("requestsrc", "cli"),
        ("hasplugin", env!("CARGO_PKG_VERSION")),
    ];
    let response = client.post_lastpass_bytes(None, "getaccts.php", Some(session), &params)?;
    if response.body.is_empty() {
        return Err(blob_fetch_error());
    }
    config_write_encrypted_buffer("blob", &response.body, key)?;
    let _ = crate::config::config_unlink(BLOB_JSON_NAME);
    crate::blob::blob_parse(&response.body, key, private_key)
}

fn touch_local_blob_cache() -> Result<()> {
    if config_exists("blob") {
        config_touch("blob")?;
    }
    if config_exists(BLOB_JSON_NAME) {
        config_touch(BLOB_JSON_NAME)?;
    }
    Ok(())
}

fn local_blob_is_fresh(max_age: Duration) -> Result<bool> {
    let now = SystemTime::now();
    let mut freshest: Option<SystemTime> = None;

    if let Some(mtime) = config_mtime("blob")? {
        freshest = Some(mtime);
    }
    if let Some(mtime) = config_mtime(BLOB_JSON_NAME)? {
        freshest = match freshest {
            Some(existing) if existing >= mtime => Some(existing),
            _ => Some(mtime),
        };
    }

    let Some(mtime) = freshest else {
        return Ok(false);
    };
    match now.duration_since(mtime) {
        Ok(age) => Ok(age < max_age),
        Err(_) => Ok(true),
    }
}

fn auto_sync_time() -> Duration {
    let secs = crate::lpenv::var("LPASS_AUTO_SYNC_TIME")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5);
    Duration::from_secs(secs)
}

fn blob_fetch_error() -> LpassError {
    LpassError::User(
        "Unable to fetch blob. Either your session is invalid and you need to login with `lpass login`, you need to synchronize, your blob is empty, or there is something wrong with your internet connection.",
    )
}

pub(crate) fn save_blob(blob: &Blob) -> Result<()> {
    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
        return save_mock_blob(blob);
    }
    let key = agent_get_decryption_key()?;
    let buffer = serde_json::to_vec_pretty(blob).map_err(|_| LpassError::Crypto("invalid blob"))?;
    config_write_encrypted_buffer(BLOB_JSON_NAME, &buffer, &key)
}

pub(crate) fn maybe_push_account_update(account: &Account, sync_mode: SyncMode) -> Result<()> {
    if matches!(sync_mode, SyncMode::No) {
        return Ok(());
    }
    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
        return Ok(());
    }

    let key = agent_get_decryption_key().map_err(map_decryption_key_error)?;
    let session = crate::session::session_load(&key)
        .map_err(map_decryption_key_error)?
        .ok_or(LpassError::User(
            "Could not find session. Perhaps you need to login with `lpass login`.",
        ))?;
    let client = HttpClient::from_env()?;

    push_account_update_with_client(&client, &session, &key, account, sync_mode)
}

fn push_account_update_with_client(
    client: &HttpClient,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
    account: &Account,
    sync_mode: SyncMode,
) -> Result<()> {
    let params = build_show_website_params(account, session, key)?;
    let params_ref: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let response = client.post_lastpass(None, "show_website.php", Some(session), &params_ref)?;
    ensure_success_status(response.status)?;

    if matches!(sync_mode, SyncMode::Now) {
        refresh_blob_from_server(client, session, key)?;
    } else if should_refresh_after_update(sync_mode, &account.id) {
        let _ = refresh_blob_from_server(client, session, key);
    }

    Ok(())
}

pub(crate) fn maybe_push_account_remove(account: &Account, sync_mode: SyncMode) -> Result<()> {
    if matches!(sync_mode, SyncMode::No) {
        return Ok(());
    }
    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
        return Ok(());
    }

    let key = agent_get_decryption_key().map_err(map_decryption_key_error)?;
    let session = crate::session::session_load(&key)
        .map_err(map_decryption_key_error)?
        .ok_or(LpassError::User(
            "Could not find session. Perhaps you need to login with `lpass login`.",
        ))?;
    let client = HttpClient::from_env()?;

    push_account_remove_with_client(&client, &session, &key, account, sync_mode)
}

fn push_account_remove_with_client(
    client: &HttpClient,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
    account: &Account,
    sync_mode: SyncMode,
) -> Result<()> {
    let params = build_show_website_delete_params(account, session);
    let params_ref: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let response = client.post_lastpass(None, "show_website.php", Some(session), &params_ref)?;
    ensure_success_status(response.status)?;

    if matches!(sync_mode, SyncMode::Now) {
        refresh_blob_from_server(client, session, key)?;
    }

    Ok(())
}

fn build_show_website_delete_params(account: &Account, session: &Session) -> Vec<(String, String)> {
    let mut params = vec![
        ("extjs".to_string(), "1".to_string()),
        ("token".to_string(), session.token.clone()),
        ("delete".to_string(), "1".to_string()),
        ("aid".to_string(), account.id.clone()),
    ];
    if let Some(share_id) = &account.share_id {
        params.push(("sharedfolderid".to_string(), share_id.clone()));
    }
    if session.url_logging_enabled {
        params.push(("recordUrl".to_string(), hex::encode(account.url.as_bytes())));
    }
    params
}

fn map_decryption_key_error(err: LpassError) -> LpassError {
    match err {
        LpassError::Crypto("missing iterations")
        | LpassError::Crypto("missing username")
        | LpassError::Crypto("missing verify") => LpassError::User(
            "Could not find decryption key. Perhaps you need to login with `lpass login`.",
        ),
        _ => err,
    }
}

fn refresh_blob_from_server(
    client: &HttpClient,
    session: &crate::session::Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<()> {
    let params = [
        ("mobile", "1"),
        ("requestsrc", "cli"),
        ("hasplugin", env!("CARGO_PKG_VERSION")),
    ];
    let response = client.post_lastpass_bytes(None, "getaccts.php", Some(session), &params)?;
    if response.body.is_empty() {
        return Err(blob_fetch_error());
    }
    config_write_encrypted_buffer("blob", &response.body, key)?;
    let _ = crate::config::config_unlink(BLOB_JSON_NAME);
    Ok(())
}

fn build_show_website_params(
    account: &Account,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<Vec<(String, String)>> {
    let mut params = vec![
        ("extjs".to_string(), "1".to_string()),
        ("token".to_string(), session.token.clone()),
        ("method".to_string(), "cli".to_string()),
        ("name".to_string(), encrypt_and_encode(&account.name, key)?),
        (
            "grouping".to_string(),
            encrypt_and_encode(&account.group, key)?,
        ),
        (
            "pwprotect".to_string(),
            if account.pwprotect { "on" } else { "off" }.to_string(),
        ),
        (
            "aid".to_string(),
            if account.id.is_empty() {
                "0".to_string()
            } else {
                account.id.clone()
            },
        ),
        (
            "username".to_string(),
            encrypt_and_encode(&account.username, key)?,
        ),
        (
            "password".to_string(),
            encrypt_and_encode(&account.password, key)?,
        ),
        ("extra".to_string(), encrypt_and_encode(&account.note, key)?),
        (
            "url".to_string(),
            if session.url_encryption_enabled && !is_secure_note(account) {
                encrypt_and_encode(&account.url, key)?
            } else {
                hex::encode(account.url.as_bytes())
            },
        ),
    ];

    if let Some(share_id) = &account.share_id {
        params.push(("sharedfolderid".to_string(), share_id.clone()));
    }

    if let Some(field_data) = stringify_fields_data(&account.fields, key)? {
        params.push(("save_all".to_string(), "1".to_string()));
        params.push(("data".to_string(), field_data));
    }
    if session.url_logging_enabled {
        params.push(("recordUrl".to_string(), hex::encode(account.url.as_bytes())));
    }

    Ok(params)
}

fn is_secure_note(account: &Account) -> bool {
    account.url == "http://sn"
}

fn should_refresh_after_update(sync_mode: SyncMode, account_id: &str) -> bool {
    matches!(sync_mode, SyncMode::Auto) && account_id == "0"
}

fn ensure_success_status(status: u16) -> Result<()> {
    if status >= 400 {
        Err(LpassError::User("Server rejected account update."))
    } else {
        Ok(())
    }
}

fn encrypt_and_encode(value: &str, key: &[u8; KDF_HASH_LEN]) -> Result<String> {
    let encrypted = aes_encrypt_lastpass(value.as_bytes(), key)?;
    Ok(base64_lastpass_encode(&encrypted))
}

fn stringify_fields_data(
    fields: &[crate::blob::Field],
    key: &[u8; KDF_HASH_LEN],
) -> Result<Option<String>> {
    if fields.is_empty() {
        return Ok(None);
    }

    let mut raw = String::new();
    for field in fields {
        let value = upload_field_value(field, key)?;
        raw.push_str("0\t");
        raw.push_str(&url_encode_component(&field.name));
        raw.push('\t');
        raw.push_str(&url_encode_component(&value));
        raw.push('\t');
        raw.push_str(&url_encode_component(&field.field_type));
        raw.push('\n');
    }
    raw.push_str("0\taction\t\taction\n0\tmethod\t\tmethod\n");

    Ok(Some(hex::encode(raw.as_bytes())))
}

fn upload_field_value(field: &crate::blob::Field, key: &[u8; KDF_HASH_LEN]) -> Result<String> {
    if let Some(value) = &field.value_encrypted {
        return Ok(value.clone());
    }

    if matches!(
        field.field_type.as_str(),
        "email" | "tel" | "text" | "password" | "textarea"
    ) {
        return encrypt_and_encode(&field.value, key);
    }

    if matches!(field.field_type.as_str(), "checkbox" | "radio") {
        let checked = if field.checked { "1" } else { "0" };
        return Ok(format!("{}-{checked}", field.value));
    }

    Ok(field.value.clone())
}

fn url_encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let byte = *byte;
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            out.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    out
}

pub(crate) fn ensure_mock_blob() -> Result<()> {
    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() != Ok("1") {
        return Ok(());
    }
    let _ = load_mock_blob()?;
    Ok(())
}

fn load_mock_blob() -> Result<Blob> {
    if let Some(buffer) = config_read_buffer("blob")? {
        if let Ok(blob) = serde_json::from_slice::<Blob>(&buffer) {
            return Ok(blob);
        }
    }

    let blob = mock_blob();
    let _ = save_mock_blob(&blob);
    Ok(blob)
}

fn load_private_key(key: &[u8; KDF_HASH_LEN]) -> Result<Option<Vec<u8>>> {
    if let Some(private_key) = config_read_encrypted_buffer("session_privatekey", key)? {
        return Ok(Some(private_key));
    }

    let private_key_enc =
        crate::config::config_read_encrypted_string("session_privatekeyenc", key)?;
    let Some(private_key_enc) = private_key_enc else {
        return Ok(None);
    };

    let private_key = decrypt_private_key(&private_key_enc, key)?;
    config_write_encrypted_buffer("session_privatekey", &private_key, key)?;
    Ok(Some(private_key))
}

fn looks_like_blob(bytes: &[u8]) -> bool {
    bytes.starts_with(b"LPAV")
}

fn save_mock_blob(blob: &Blob) -> Result<()> {
    let buffer = serde_json::to_vec_pretty(blob).map_err(|_| LpassError::Crypto("invalid blob"))?;
    config_write_buffer("blob", &buffer)
}

fn mock_blob() -> Blob {
    let mut blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: Vec::new(),
    };

    blob.accounts.push(mock_account(
        "0001",
        "test-account",
        "test-group",
        "https://test-url.example.com/",
        "xyz@example.com",
        "test-account-password",
        "",
        false,
    ));

    blob.accounts.push(mock_account(
        "0002",
        "test-note",
        "test-group",
        "http://sn",
        "",
        "",
        "NoteType: Server\nHostname: foo.example.com\nUsername: test-note-user\nPassword: test-note-password",
        false,
    ));

    blob.accounts.push(mock_account(
        "0003",
        "test-reprompt-account",
        "test-group",
        "https://test-url.example.com/",
        "xyz@example.com",
        "test-account-password",
        "",
        true,
    ));

    blob.accounts.push(mock_account(
        "0004",
        "test-reprompt-note",
        "test-group",
        "http://sn",
        "",
        "",
        "NoteType: Server\nHostname: foo.example.com\nUsername: test-note-user\nPassword: test-note-password",
        true,
    ));

    blob
}

fn mock_account(
    id: &str,
    name: &str,
    group: &str,
    url: &str,
    username: &str,
    password: &str,
    note: &str,
    pwprotect: bool,
) -> Account {
    let fullname = if !group.is_empty() {
        format!("{}/{}", group, name)
    } else {
        name.to_string()
    };

    Account {
        id: id.to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name: name.to_string(),
        name_encrypted: None,
        group: group.to_string(),
        group_encrypted: None,
        fullname,
        url: url.to_string(),
        url_encrypted: None,
        username: username.to_string(),
        username_encrypted: None,
        password: password.to_string(),
        password_encrypted: None,
        note: note.to_string(),
        note_encrypted: None,
        last_touch: "skipped".to_string(),
        last_modified_gmt: "skipped".to_string(),
        fav: false,
        pwprotect,
        attachkey: String::new(),
        attachkey_encrypted: None,
        attachpresent: false,
        fields: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_decryption_key_error_maps_missing_inputs_to_user_error() {
        let mapped = map_decryption_key_error(LpassError::Crypto("missing iterations"));
        assert!(matches!(mapped, LpassError::User(_)));
        let mapped = map_decryption_key_error(LpassError::Crypto("missing username"));
        assert!(matches!(mapped, LpassError::User(_)));
        let mapped = map_decryption_key_error(LpassError::Crypto("missing verify"));
        assert!(matches!(mapped, LpassError::User(_)));

        let passthrough = map_decryption_key_error(LpassError::Crypto("other"));
        assert!(matches!(passthrough, LpassError::Crypto("other")));
    }

    #[test]
    fn looks_like_blob_detects_signature() {
        assert!(looks_like_blob(b"LPAVabc"));
        assert!(!looks_like_blob(b"XXXXabc"));
    }

    #[test]
    fn mock_blob_contains_expected_sample_entries() {
        let blob = mock_blob();
        assert_eq!(blob.accounts.len(), 4);
        assert!(
            blob.accounts
                .iter()
                .any(|account| account.fullname == "test-group/test-account")
        );
        assert!(
            blob.accounts
                .iter()
                .any(|account| account.pwprotect && account.name == "test-reprompt-account")
        );
    }

    #[test]
    fn sync_mode_parse_accepts_expected_values() {
        assert_eq!(SyncMode::parse("auto"), Some(SyncMode::Auto));
        assert_eq!(SyncMode::parse("now"), Some(SyncMode::Now));
        assert_eq!(SyncMode::parse("no"), Some(SyncMode::No));
        assert_eq!(SyncMode::parse("AUTO"), Some(SyncMode::Auto));
        assert_eq!(SyncMode::parse("No"), Some(SyncMode::No));
        assert_eq!(SyncMode::parse("bad"), None);
    }

    #[test]
    fn auto_sync_time_defaults_and_respects_env() {
        crate::lpenv::clear_overrides_for_tests();
        assert_eq!(auto_sync_time(), Duration::from_secs(5));

        crate::lpenv::set_override_for_tests("LPASS_AUTO_SYNC_TIME", "17");
        assert_eq!(auto_sync_time(), Duration::from_secs(17));

        crate::lpenv::set_override_for_tests("LPASS_AUTO_SYNC_TIME", "0");
        assert_eq!(auto_sync_time(), Duration::from_secs(5));

        crate::lpenv::set_override_for_tests("LPASS_AUTO_SYNC_TIME", "invalid");
        assert_eq!(auto_sync_time(), Duration::from_secs(5));
        crate::lpenv::clear_overrides_for_tests();
    }

    #[test]
    fn url_encode_component_escapes_reserved_bytes() {
        assert_eq!(url_encode_component("a b/c"), "a%20b%2Fc");
        assert_eq!(url_encode_component("alpha-_.~"), "alpha-_.~");
    }

    #[test]
    fn stringify_fields_data_encodes_and_adds_action_method() {
        let fields = vec![crate::blob::Field {
            name: "Name With Space".to_string(),
            field_type: "text".to_string(),
            value: "abc".to_string(),
            value_encrypted: None,
            checked: false,
        }];
        let key = [9u8; KDF_HASH_LEN];
        let hex_data = stringify_fields_data(&fields, &key)
            .expect("stringify")
            .expect("field data");
        let raw = hex::decode(hex_data).expect("hex decode");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(text.contains("0\tName%20With%20Space\t"));
        assert!(text.contains("\taction\n0\tmethod\t\tmethod\n"));
    }

    #[test]
    fn build_show_website_params_contains_required_keys() {
        let account = Account {
            id: "0".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: "entry".to_string(),
            name_encrypted: None,
            group: "group".to_string(),
            group_encrypted: None,
            fullname: "group/entry".to_string(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: "user".to_string(),
            username_encrypted: None,
            password: "pass".to_string(),
            password_encrypted: None,
            note: String::new(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        };
        let key = [3u8; KDF_HASH_LEN];
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let params = build_show_website_params(&account, &session, &key).expect("params");
        assert!(params.iter().any(|(k, _)| k == "extjs"));
        assert!(params.iter().any(|(k, _)| k == "token"));
        assert!(params.iter().any(|(k, _)| k == "aid"));
        assert!(params.iter().any(|(k, _)| k == "name"));
        assert!(params.iter().any(|(k, _)| k == "password"));
        assert!(params.iter().any(|(k, _)| k == "url"));
    }

    #[test]
    fn build_show_website_params_includes_sharedfolderid() {
        let account = Account {
            id: "0".to_string(),
            share_name: Some("Team".to_string()),
            share_id: Some("4321".to_string()),
            share_readonly: false,
            name: "entry".to_string(),
            name_encrypted: None,
            group: "group".to_string(),
            group_encrypted: None,
            fullname: "Team/group/entry".to_string(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: "user".to_string(),
            username_encrypted: None,
            password: "pass".to_string(),
            password_encrypted: None,
            note: String::new(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        };
        let key = [3u8; KDF_HASH_LEN];
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let params = build_show_website_params(&account, &session, &key).expect("params");
        assert!(
            params
                .iter()
                .any(|(k, v)| k == "sharedfolderid" && v == "4321")
        );
    }

    #[test]
    fn build_show_website_params_uses_encrypted_url_when_feature_enabled() {
        let account = Account {
            id: "0".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: "entry".to_string(),
            name_encrypted: None,
            group: String::new(),
            group_encrypted: None,
            fullname: "entry".to_string(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: String::new(),
            username_encrypted: None,
            password: String::new(),
            password_encrypted: None,
            note: String::new(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        };
        let key = [6u8; KDF_HASH_LEN];
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: true,
            url_logging_enabled: true,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let params = build_show_website_params(&account, &session, &key).expect("params");
        let url = params
            .iter()
            .find(|(k, _)| k == "url")
            .map(|(_, v)| v.clone())
            .expect("url param");
        assert!(url.starts_with('!'));
        assert!(params.iter().any(|(k, _)| k == "recordUrl"));
    }

    #[test]
    fn upload_field_value_uses_checkbox_suffix_and_encrypted_preference() {
        let key = [1u8; KDF_HASH_LEN];
        let checkbox = crate::blob::Field {
            name: "c".to_string(),
            field_type: "checkbox".to_string(),
            value: "yes".to_string(),
            value_encrypted: None,
            checked: true,
        };
        assert_eq!(
            upload_field_value(&checkbox, &key).expect("checkbox"),
            "yes-1"
        );

        let encrypted = crate::blob::Field {
            name: "e".to_string(),
            field_type: "text".to_string(),
            value: "x".to_string(),
            value_encrypted: Some("!abc|def".to_string()),
            checked: false,
        };
        assert_eq!(
            upload_field_value(&encrypted, &key).expect("encrypted"),
            "!abc|def"
        );
    }

    #[test]
    fn should_refresh_after_update_only_for_auto_new_accounts() {
        assert!(should_refresh_after_update(SyncMode::Auto, "0"));
        assert!(!should_refresh_after_update(SyncMode::Auto, "1234"));
        assert!(!should_refresh_after_update(SyncMode::Now, "0"));
        assert!(!should_refresh_after_update(SyncMode::No, "0"));
    }

    #[test]
    fn is_secure_note_checks_sn_url_only() {
        let mut account = Account {
            id: "0".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: String::new(),
            name_encrypted: None,
            group: String::new(),
            group_encrypted: None,
            fullname: String::new(),
            url: "http://sn".to_string(),
            url_encrypted: None,
            username: String::new(),
            username_encrypted: None,
            password: String::new(),
            password_encrypted: None,
            note: String::new(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        };
        assert!(is_secure_note(&account));
        account.url = "https://example.com".to_string();
        assert!(!is_secure_note(&account));
    }

    #[test]
    fn ensure_success_status_checks_error_boundary() {
        assert!(ensure_success_status(200).is_ok());
        assert!(ensure_success_status(399).is_ok());
        let err = ensure_success_status(400).expect_err("must fail");
        assert!(format!("{err}").contains("Server rejected account update."));
    }

    #[test]
    fn build_show_website_delete_params_respects_record_url_flag() {
        let account = Account {
            id: "42".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: String::new(),
            name_encrypted: None,
            group: String::new(),
            group_encrypted: None,
            fullname: String::new(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: String::new(),
            username_encrypted: None,
            password: String::new(),
            password_encrypted: None,
            note: String::new(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        };
        let mut session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };

        let params = build_show_website_delete_params(&account, &session);
        assert!(params.iter().any(|(k, _)| k == "aid"));
        assert!(!params.iter().any(|(k, _)| k == "recordUrl"));
        assert!(!params.iter().any(|(k, _)| k == "sharedfolderid"));

        session.url_logging_enabled = true;
        let params = build_show_website_delete_params(&account, &session);
        assert!(params.iter().any(|(k, _)| k == "recordUrl"));

        let mut shared = account.clone();
        shared.share_id = Some("9988".to_string());
        let params = build_show_website_delete_params(&shared, &session);
        assert!(
            params
                .iter()
                .any(|(k, v)| k == "sharedfolderid" && v == "9988")
        );
    }

    #[test]
    fn push_account_update_with_client_handles_sync_modes() {
        let key = [5u8; KDF_HASH_LEN];
        let account = Account {
            id: "0".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: "entry".to_string(),
            name_encrypted: None,
            group: String::new(),
            group_encrypted: None,
            fullname: "entry".to_string(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: "u".to_string(),
            username_encrypted: None,
            password: "p".to_string(),
            password_encrypted: None,
            note: String::new(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        };
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let client = HttpClient::mock();

        push_account_update_with_client(&client, &session, &key, &account, SyncMode::Auto)
            .expect("auto should ignore refresh failure");
        let err = push_account_update_with_client(&client, &session, &key, &account, SyncMode::Now)
            .expect_err("now should fail because mock getaccts body is empty");
        assert!(format!("{err}").contains("Unable to fetch blob"));
    }

    #[test]
    fn push_account_remove_with_client_handles_sync_modes() {
        let key = [7u8; KDF_HASH_LEN];
        let account = Account {
            id: "42".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: String::new(),
            name_encrypted: None,
            group: String::new(),
            group_encrypted: None,
            fullname: String::new(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: String::new(),
            username_encrypted: None,
            password: String::new(),
            password_encrypted: None,
            note: String::new(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        };
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: true,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let client = HttpClient::mock();

        push_account_remove_with_client(&client, &session, &key, &account, SyncMode::Auto)
            .expect("auto delete");
        let err = push_account_remove_with_client(&client, &session, &key, &account, SyncMode::Now)
            .expect_err("now should fail because mock getaccts body is empty");
        assert!(format!("{err}").contains("Unable to fetch blob"));
    }
}
