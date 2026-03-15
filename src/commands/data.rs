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
use crate::upload_queue;
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
        ("hasplugin", crate::version::generated_version()),
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

pub(crate) fn maybe_push_account_update(
    account: &Account,
    blob: &Blob,
    sync_mode: SyncMode,
) -> Result<()> {
    let Some((key, session)) = load_queue_credentials()? else {
        return Ok(());
    };
    let params = build_show_website_params(account, blob, &session, &key)?;
    upload_queue::enqueue(
        &key,
        "show_website.php",
        params,
        !matches!(sync_mode, SyncMode::No),
    )
}

pub(crate) fn maybe_push_account_remove(account: &Account, sync_mode: SyncMode) -> Result<()> {
    let Some((key, session)) = load_queue_credentials()? else {
        return Ok(());
    };
    let params = build_show_website_delete_params(account, &session);
    upload_queue::enqueue(
        &key,
        "show_website.php",
        params,
        !matches!(sync_mode, SyncMode::No),
    )
}

pub(crate) fn maybe_log_access(account: &Account, sync_mode: SyncMode) -> Result<()> {
    if account.id == "0" {
        return Ok(());
    }

    let Some((key, session)) = load_queue_credentials()? else {
        return Ok(());
    };
    let params = build_log_access_params(account, &session);
    upload_queue::enqueue(
        &key,
        "loglogin.php",
        params,
        !matches!(sync_mode, SyncMode::No),
    )
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

fn build_log_access_params(account: &Account, session: &Session) -> Vec<(String, String)> {
    let mut params = vec![
        ("id".to_string(), account.id.clone()),
        ("method".to_string(), "cli".to_string()),
    ];

    if let Some(share_id) = &account.share_id {
        params.push(("sharedfolderid".to_string(), share_id.clone()));
    }
    if session.url_logging_enabled {
        params.push(("recordUrl".to_string(), hex::encode(account.url.as_bytes())));
    }

    params
}

fn load_queue_credentials() -> Result<Option<([u8; KDF_HASH_LEN], Session)>> {
    let key = match agent_get_decryption_key().map_err(map_decryption_key_error) {
        Ok(key) => key,
        Err(_) if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") => return Ok(None),
        Err(err) => return Err(err),
    };

    let session = crate::session::session_load(&key)
        .map_err(map_decryption_key_error)?
        .ok_or(LpassError::User(
            "Could not find session. Perhaps you need to login with `lpass login`.",
        ))?;
    Ok(Some((key, session)))
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

pub(crate) fn refresh_blob_from_server(
    client: &HttpClient,
    session: &crate::session::Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<()> {
    let params = [
        ("mobile", "1"),
        ("requestsrc", "cli"),
        ("hasplugin", crate::version::generated_version()),
    ];
    let response = client.post_lastpass_bytes(None, "getaccts.php", Some(session), &params)?;
    if response.body.is_empty() {
        return Err(blob_fetch_error());
    }
    config_write_encrypted_buffer("blob", &response.body, key)?;
    let _ = crate::config::config_unlink(BLOB_JSON_NAME);
    Ok(())
}

pub(crate) fn build_show_website_params(
    account: &Account,
    blob: &Blob,
    session: &Session,
    vault_key: &[u8; KDF_HASH_LEN],
) -> Result<Vec<(String, String)>> {
    let key = upload_key_for_account(account, blob, vault_key)?;
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

fn upload_key_for_account<'a>(
    account: &Account,
    blob: &'a Blob,
    vault_key: &'a [u8; KDF_HASH_LEN],
) -> Result<&'a [u8; KDF_HASH_LEN]> {
    let Some(share_id) = account
        .share_id
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return Ok(vault_key);
    };

    let share = blob
        .shares
        .iter()
        .find(|share| share.id == share_id)
        .or_else(|| {
            account.share_name.as_deref().and_then(|share_name| {
                blob.shares
                    .iter()
                    .find(|share| share.name.eq_ignore_ascii_case(share_name))
            })
        })
        .ok_or(LpassError::User(
            "Unable to find shared folder key. Please sync and try again.",
        ))?;

    share.key.as_ref().ok_or(LpassError::User(
        "Unable to find shared folder key. Please sync and try again.",
    ))
}

fn is_secure_note(account: &Account) -> bool {
    account.url == "http://sn"
}

pub(crate) fn encrypt_and_encode(value: &str, key: &[u8; KDF_HASH_LEN]) -> Result<String> {
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
    if let Some(buffer) = config_read_buffer("blob")?
        && let Ok(blob) = serde_json::from_slice::<Blob>(&buffer)
    {
        return Ok(blob);
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
        attachments: Vec::new(),
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

#[allow(clippy::too_many_arguments)]
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
    use crate::config::{
        ConfigEnv, config_path, config_read_encrypted_buffer, config_unlink, config_write_buffer,
        config_write_encrypted_buffer, config_write_encrypted_string, set_test_env,
    };
    use crate::crypto::{aes_encrypt_lastpass, base64_lastpass_encode};
    use crate::session::{session_load, session_save};
    use filetime::{FileTime, set_file_mtime};
    use tempfile::TempDir;

    fn minimal_blob_bytes(version: u32) -> Vec<u8> {
        let version = version.to_string();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"LPAV");
        bytes.extend_from_slice(&(version.len() as u32).to_be_bytes());
        bytes.extend_from_slice(version.as_bytes());
        bytes
    }

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
        let root = mock_account("9999", "root-entry", "", "", "", "", "", false);
        assert_eq!(root.fullname, "root-entry");
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
        let _guard = crate::lpenv::begin_test_overrides();
        assert_eq!(auto_sync_time(), Duration::from_secs(5));

        crate::lpenv::set_override_for_tests("LPASS_AUTO_SYNC_TIME", "17");
        assert_eq!(auto_sync_time(), Duration::from_secs(17));

        crate::lpenv::set_override_for_tests("LPASS_AUTO_SYNC_TIME", "0");
        assert_eq!(auto_sync_time(), Duration::from_secs(5));

        crate::lpenv::set_override_for_tests("LPASS_AUTO_SYNC_TIME", "invalid");
        assert_eq!(auto_sync_time(), Duration::from_secs(5));
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
        let blob = Blob::default();
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
        let params = build_show_website_params(&account, &blob, &session, &key).expect("params");
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
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: vec![crate::blob::Share {
                id: "4321".to_string(),
                name: "Team".to_string(),
                readonly: false,
                key: Some([7u8; KDF_HASH_LEN]),
            }],
            accounts: Vec::new(),
            attachments: Vec::new(),
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
        let params = build_show_website_params(&account, &blob, &session, &key).expect("params");
        assert!(
            params
                .iter()
                .any(|(k, v)| k == "sharedfolderid" && v == "4321")
        );
    }

    #[test]
    fn build_show_website_params_uses_share_key_for_shared_entries() {
        let share_key = [7u8; KDF_HASH_LEN];
        let vault_key = [3u8; KDF_HASH_LEN];
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
            note: "note".to_string(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: vec![crate::blob::Field {
                name: "Environment".to_string(),
                field_type: "text".to_string(),
                value: "prod".to_string(),
                value_encrypted: None,
                checked: false,
            }],
        };
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: vec![crate::blob::Share {
                id: "4321".to_string(),
                name: "Team".to_string(),
                readonly: false,
                key: Some(share_key),
            }],
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: true,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };

        let params =
            build_show_website_params(&account, &blob, &session, &vault_key).expect("params");
        let values: std::collections::HashMap<_, _> = params.into_iter().collect();

        let name = crate::crypto::aes_decrypt_base64_lastpass(values["name"].as_str(), &share_key)
            .expect("decrypt name");
        let password =
            crate::crypto::aes_decrypt_base64_lastpass(values["password"].as_str(), &share_key)
                .expect("decrypt password");
        let url = crate::crypto::aes_decrypt_base64_lastpass(values["url"].as_str(), &share_key)
            .expect("decrypt url");

        assert_eq!(String::from_utf8_lossy(&name), "entry");
        assert_eq!(String::from_utf8_lossy(&password), "pass");
        assert_eq!(String::from_utf8_lossy(&url), "https://example.com");
        assert!(
            crate::crypto::aes_decrypt_base64_lastpass(values["name"].as_str(), &vault_key)
                .is_err()
        );
    }

    #[test]
    fn build_show_website_params_reports_missing_shared_folder_key() {
        let account = Account {
            id: "0".to_string(),
            share_name: Some("Team".to_string()),
            share_id: Some("4321".to_string()),
            share_readonly: false,
            name: "entry".to_string(),
            name_encrypted: None,
            group: String::new(),
            group_encrypted: None,
            fullname: "Team/entry".to_string(),
            url: String::new(),
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
        let blob = Blob::default();
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

        let err = build_show_website_params(&account, &blob, &session, &key)
            .expect_err("missing share key");
        assert!(format!("{err}").contains("Unable to find shared folder key"));
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
        let blob = Blob::default();
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
        let params = build_show_website_params(&account, &blob, &session, &key).expect("params");
        let url = params
            .iter()
            .find(|(k, _)| k == "url")
            .map(|(_, v)| v.clone())
            .expect("url param");
        assert!(url.starts_with('!'));
        assert!(params.iter().any(|(k, _)| k == "recordUrl"));
    }

    #[test]
    fn build_show_website_params_secure_note_uses_hex_url_and_field_payload() {
        let account = Account {
            id: String::new(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: "note".to_string(),
            name_encrypted: None,
            group: String::new(),
            group_encrypted: None,
            fullname: "note".to_string(),
            url: "http://sn".to_string(),
            url_encrypted: None,
            username: String::new(),
            username_encrypted: None,
            password: String::new(),
            password_encrypted: None,
            note: "extra".to_string(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: true,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: vec![crate::blob::Field {
                name: "otp".to_string(),
                field_type: "text".to_string(),
                value: "123456".to_string(),
                value_encrypted: None,
                checked: false,
            }],
        };
        let blob = Blob::default();
        let key = [6u8; KDF_HASH_LEN];
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: true,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };

        let params = build_show_website_params(&account, &blob, &session, &key).expect("params");
        assert!(params.iter().any(|(k, v)| k == "aid" && v == "0"));
        assert!(params.iter().any(|(k, v)| k == "pwprotect" && v == "on"));
        assert!(
            params
                .iter()
                .any(|(k, v)| k == "url" && v == "687474703a2f2f736e")
        );
        assert!(params.iter().any(|(k, v)| k == "save_all" && v == "1"));
        assert!(params.iter().any(|(k, _)| k == "data"));
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
    fn upload_field_value_returns_plain_value_for_unknown_types() {
        let key = [2u8; KDF_HASH_LEN];
        let field = crate::blob::Field {
            name: "select".to_string(),
            field_type: "select".to_string(),
            value: "plain".to_string(),
            value_encrypted: None,
            checked: false,
        };
        assert_eq!(
            upload_field_value(&field, &key).expect("plain field"),
            "plain"
        );
    }

    #[test]
    fn build_log_access_params_includes_share_and_record_url() {
        let mut account = Account {
            id: "42".to_string(),
            share_name: None,
            share_id: Some("77".to_string()),
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

        let params = build_log_access_params(&account, &session);
        assert!(
            params
                .iter()
                .any(|(key, value)| key == "id" && value == "42")
        );
        assert!(
            params
                .iter()
                .any(|(key, value)| key == "method" && value == "cli")
        );
        assert!(
            params
                .iter()
                .any(|(key, value)| key == "sharedfolderid" && value == "77")
        );
        assert!(params.iter().any(|(key, value)| {
            key == "recordUrl" && value == "68747470733a2f2f6578616d706c652e636f6d"
        }));

        account.id = "0".to_string();
        assert_eq!(build_log_access_params(&account, &session)[0].1, "0");
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
    fn load_queue_credentials_returns_none_in_mock_mode_without_session() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        assert!(
            load_queue_credentials()
                .expect("load queue credentials")
                .is_none()
        );
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
    fn maybe_push_account_update_enqueues_request_when_session_exists() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let key = [5u8; KDF_HASH_LEN];
        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        session_save(
            &Session {
                uid: "u".to_string(),
                session_id: "s".to_string(),
                token: "tok".to_string(),
                url_encryption_enabled: false,
                url_logging_enabled: false,
                server: None,
                private_key: None,
                private_key_enc: None,
            },
            &key,
        )
        .expect("save session");

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
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![account.clone()],
            attachments: Vec::new(),
        };

        maybe_push_account_update(&account, &blob, SyncMode::No).expect("queue update");

        let queue_dir = config_path("upload-queue/.marker")
            .expect("queue marker")
            .parent()
            .expect("queue dir")
            .to_path_buf();
        let name = std::fs::read_dir(queue_dir)
            .expect("read queue")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .find(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            .expect("queued file");
        let queued = config_read_encrypted_buffer(&format!("upload-queue/{name}"), &key)
            .expect("read queue entry")
            .expect("queue data");
        let text = String::from_utf8(queued).expect("queue utf8");
        assert!(text.contains("show_website.php"));
    }

    #[test]
    fn maybe_push_account_remove_enqueues_request_when_session_exists() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let key = [7u8; KDF_HASH_LEN];
        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        session_save(
            &Session {
                uid: "u".to_string(),
                session_id: "s".to_string(),
                token: "tok".to_string(),
                url_encryption_enabled: false,
                url_logging_enabled: true,
                server: None,
                private_key: None,
                private_key_enc: None,
            },
            &key,
        )
        .expect("save session");

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

        maybe_push_account_remove(&account, SyncMode::No).expect("queue remove");

        let queue_dir = config_path("upload-queue/.marker")
            .expect("queue marker")
            .parent()
            .expect("queue dir")
            .to_path_buf();
        let name = std::fs::read_dir(queue_dir)
            .expect("read queue")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .find(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            .expect("queued file");
        let queued = config_read_encrypted_buffer(&format!("upload-queue/{name}"), &key)
            .expect("read queue entry")
            .expect("queue data");
        let text = String::from_utf8(queued).expect("queue utf8");
        assert!(text.contains("\"delete\":\"1\"") || text.contains("\"delete\",\"1\""));
    }

    #[test]
    fn maybe_log_access_enqueues_request_when_session_exists() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let key = [3u8; KDF_HASH_LEN];
        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        session_save(
            &Session {
                uid: "u".to_string(),
                session_id: "s".to_string(),
                token: "tok".to_string(),
                url_encryption_enabled: false,
                url_logging_enabled: false,
                server: None,
                private_key: None,
                private_key_enc: None,
            },
            &key,
        )
        .expect("save session");

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

        maybe_log_access(&account, SyncMode::No).expect("log access");

        let queue_dir = config_path("upload-queue/.marker")
            .expect("queue marker")
            .parent()
            .expect("queue dir")
            .to_path_buf();
        let name = std::fs::read_dir(queue_dir)
            .expect("read queue")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .find(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
            .expect("queued file");
        let queued = config_read_encrypted_buffer(&format!("upload-queue/{name}"), &key)
            .expect("read queue entry")
            .expect("queue data");
        let text = String::from_utf8(queued).expect("queue utf8");
        assert!(text.contains("loglogin.php"));
    }

    #[test]
    fn mock_mode_paths_cover_load_save_and_push_helpers() {
        let _env_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        ensure_mock_blob().expect("ensure");
        let mut blob = load_blob(SyncMode::Auto).expect("load auto");
        assert!(!blob.accounts.is_empty());
        blob.version = 99;
        save_blob(&blob).expect("save");
        let loaded = load_blob(SyncMode::No).expect("load no");
        assert_eq!(loaded.version, 99);

        let account = loaded.accounts[0].clone();
        maybe_push_account_update(&account, &loaded, SyncMode::Auto).expect("mock update");
        maybe_push_account_remove(&account, SyncMode::Now).expect("mock remove");
    }

    #[test]
    fn ensure_mock_blob_is_noop_without_mock_env() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        ensure_mock_blob().expect("noop");
        assert!(!config_exists("blob"));
    }

    #[test]
    fn load_local_blob_reports_invalid_json_and_non_blob_errors() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [4u8; KDF_HASH_LEN];

        config_write_encrypted_buffer(BLOB_JSON_NAME, b"not-json", &key).expect("write blob json");
        let err = load_local_blob(&key, None).expect_err("invalid json");
        assert!(format!("{err}").contains("invalid blob"));

        let _ = config_unlink(BLOB_JSON_NAME);
        config_write_encrypted_buffer("blob", b"not-a-blob", &key).expect("write blob");
        let err = load_local_blob(&key, None).expect_err("invalid blob bytes");
        assert!(format!("{err}").contains("blob response was not a blob"));

        let _ = config_unlink("blob");
        let err = load_local_blob(&key, None).expect_err("missing blob");
        assert!(format!("{err}").contains("Unable to fetch blob"));
    }

    #[test]
    fn load_queue_credentials_reports_missing_key_without_mock_mode() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let err = load_queue_credentials().expect_err("missing key");
        assert!(format!("{err}").contains("Could not find decryption key"));
    }

    #[test]
    fn load_private_key_prefers_cached_then_decodes_encrypted_variant() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [2u8; KDF_HASH_LEN];

        config_write_encrypted_buffer("session_privatekey", b"CACHED", &key).expect("cache key");
        let cached = load_private_key(&key).expect("load cached");
        assert_eq!(cached.as_deref(), Some(b"CACHED".as_ref()));

        let _ = config_unlink("session_privatekey");
        let payload = b"LastPassPrivateKey<414243>LastPassPrivateKey";
        let encrypted = aes_encrypt_lastpass(payload, &key).expect("encrypt");
        let encoded = base64_lastpass_encode(&encrypted);
        config_write_encrypted_string("session_privatekeyenc", &encoded, &key).expect("write enc");
        let loaded = load_private_key(&key).expect("load encoded");
        assert_eq!(loaded.as_deref(), Some(b"ABC".as_ref()));

        let cached_after = config_read_encrypted_buffer("session_privatekey", &key).expect("read");
        assert_eq!(cached_after.as_deref(), Some(b"ABC".as_ref()));
    }

    #[test]
    fn local_blob_freshness_and_touch_cover_mtime_paths() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        assert!(!local_blob_is_fresh(Duration::from_secs(10)).expect("fresh check"));
        config_write_buffer("blob", b"blob-bytes").expect("write blob");
        assert!(local_blob_is_fresh(Duration::from_secs(10)).expect("fresh blob"));
        assert!(!local_blob_is_fresh(Duration::from_secs(0)).expect("age boundary"));

        let blob_path = config_path("blob").expect("blob path");
        let future = FileTime::from_unix_time(i64::MAX / 2, 0);
        set_file_mtime(&blob_path, future).expect("set future mtime");
        assert!(local_blob_is_fresh(Duration::from_secs(1)).expect("future mtime"));

        touch_local_blob_cache().expect("touch");
    }

    #[test]
    fn local_blob_freshness_prefers_newer_blob_over_older_blob_json() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        config_write_buffer("blob", b"blob-bytes").expect("write blob");
        config_write_buffer(BLOB_JSON_NAME, b"json-bytes").expect("write blob json");
        let blob_path = config_path("blob").expect("blob path");
        let json_path = config_path(BLOB_JSON_NAME).expect("blob json path");
        set_file_mtime(&blob_path, FileTime::from_unix_time(200, 0)).expect("blob mtime");
        set_file_mtime(&json_path, FileTime::from_unix_time(100, 0)).expect("json mtime");

        assert!(local_blob_is_fresh(Duration::from_secs(u64::MAX)).expect("fresh"));
    }

    fn test_session() -> Session {
        Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        }
    }

    #[test]
    fn fetch_remote_blob_version_and_load_latest_prefer_newest_local_blob() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [8u8; KDF_HASH_LEN];
        let client = HttpClient::mock();
        let mut session = test_session();

        session_save(&session, &key).expect("save session");
        let version = fetch_remote_blob_version(&client, &mut session, &key).expect("version");
        assert_eq!(version, 123);
        let saved_session = session_load(&key)
            .expect("session load")
            .expect("has session");
        assert_eq!(saved_session.uid, "57747756");

        let local = Blob {
            version: 999,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![mock_account(
                "0001",
                "local-only",
                "team",
                "https://example.com",
                "u",
                "p",
                "",
                false,
            )],
            attachments: Vec::new(),
        };
        let buffer = serde_json::to_vec_pretty(&local).expect("json");
        config_write_encrypted_buffer(BLOB_JSON_NAME, &buffer, &key).expect("write local blob");
        let loaded = load_latest_blob(&client, &mut session, &key, None).expect("load latest");
        assert_eq!(loaded.version, 999);
        assert_eq!(loaded.accounts[0].name, "local-only");
    }

    #[test]
    fn fetch_remote_blob_version_returns_zero_on_http_error() {
        let key = [4u8; KDF_HASH_LEN];
        let client = HttpClient::mock_with_overrides(&[("login_check.php", 500, "server error")]);
        let mut session = test_session();

        let version = fetch_remote_blob_version(&client, &mut session, &key).expect("version");
        assert_eq!(version, 0);
    }

    #[test]
    fn load_latest_blob_returns_error_when_remote_version_is_zero() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [3u8; KDF_HASH_LEN];
        let local = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        let buffer = serde_json::to_vec_pretty(&local).expect("json");
        config_write_encrypted_buffer(BLOB_JSON_NAME, &buffer, &key).expect("write local blob");
        let client = HttpClient::mock_with_overrides(&[("login_check.php", 500, "server error")]);

        let err = load_latest_blob(&client, &mut test_session(), &key, None).expect_err("error");
        assert!(format!("{err}").contains("Unable to fetch blob"));
    }

    #[test]
    fn load_latest_blob_fetches_and_stores_newer_remote_blob() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [2u8; KDF_HASH_LEN];
        let local = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        let buffer = serde_json::to_vec_pretty(&local).expect("json");
        config_write_encrypted_buffer(BLOB_JSON_NAME, &buffer, &key).expect("write local blob");
        let remote_bytes = minimal_blob_bytes(2);
        let remote_text = String::from_utf8(remote_bytes.clone()).expect("blob text");
        let client = HttpClient::mock_with_overrides(&[
            (
                "login_check.php",
                200,
                "<response><ok uid=\"1\" sessionid=\"2\" token=\"3\" accts_version=\"123\"/></response>",
            ),
            ("getaccts.php", 200, &remote_text),
        ]);

        let loaded = load_latest_blob(&client, &mut test_session(), &key, None).expect("loaded");
        assert_eq!(loaded.version, 2);
        assert_eq!(
            config_read_encrypted_buffer("blob", &key)
                .expect("read blob")
                .expect("blob exists"),
            remote_bytes
        );
        assert!(
            config_read_encrypted_buffer(BLOB_JSON_NAME, &key)
                .expect("read blob json")
                .is_none()
        );
    }

    #[test]
    fn fetch_and_store_blob_reports_empty_body() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [9u8; KDF_HASH_LEN];
        let client = HttpClient::mock();
        let session = test_session();

        let err = fetch_and_store_blob(&client, &session, &key, None).expect_err("must fail");
        assert!(format!("{err}").contains("Unable to fetch blob"));
    }

    #[test]
    fn load_blob_auto_uses_latest_when_cache_is_stale() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [6u8; KDF_HASH_LEN];

        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        session_save(
            &Session {
                uid: "u".to_string(),
                session_id: "s".to_string(),
                token: "tok".to_string(),
                url_encryption_enabled: false,
                url_logging_enabled: false,
                server: Some("127.0.0.1:1".to_string()),
                private_key: None,
                private_key_enc: None,
            },
            &key,
        )
        .expect("save session");
        config_write_encrypted_buffer("blob", &minimal_blob_bytes(1), &key).expect("write blob");
        let blob_path = config_path("blob").expect("blob path");
        set_file_mtime(&blob_path, FileTime::from_unix_time(1, 0)).expect("set old mtime");
        crate::lpenv::set_override_for_tests("LPASS_AUTO_SYNC_TIME", "1");

        let err = load_blob(SyncMode::Auto).expect_err("stale cache should sync");
        assert!(format!("{err}").contains("IO error while http post"));
    }

    #[test]
    fn load_local_blob_parses_minimal_blob_bytes() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [1u8; KDF_HASH_LEN];
        let mut blob_bytes = Vec::new();
        blob_bytes.extend_from_slice(b"LPAV");
        blob_bytes.extend_from_slice(&1u32.to_be_bytes());
        blob_bytes.extend_from_slice(b"1");
        config_write_encrypted_buffer("blob", &blob_bytes, &key).expect("write blob bytes");

        let loaded = load_local_blob(&key, None).expect("load local blob");
        assert_eq!(loaded.version, 1);
        assert!(loaded.accounts.is_empty());
    }

    #[test]
    fn save_blob_writes_encrypted_json_in_non_mock_mode() {
        let _env_guard = crate::lpenv::begin_test_overrides();
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [7u8; KDF_HASH_LEN];
        config_write_buffer("plaintext_key", &key).expect("write plaintext key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");

        let blob = Blob {
            version: 5,
            local_version: false,
            shares: Vec::new(),
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        save_blob(&blob).expect("save blob");

        let stored = config_read_encrypted_buffer(BLOB_JSON_NAME, &key)
            .expect("read")
            .expect("exists");
        let decoded: Blob = serde_json::from_slice(&stored).expect("decode");
        assert_eq!(decoded.version, 5);
    }

    #[test]
    fn refresh_blob_from_server_writes_blob_and_clears_json_cache() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let key = [8u8; KDF_HASH_LEN];
        let blob_bytes = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"LPAV");
            bytes.extend_from_slice(&1u32.to_be_bytes());
            bytes.extend_from_slice(b"1");
            bytes
        };
        let blob_text = String::from_utf8(blob_bytes.clone()).expect("blob text");
        let client = HttpClient::mock_with_overrides(&[("getaccts.php", 200, &blob_text)]);
        config_write_encrypted_buffer(BLOB_JSON_NAME, b"{}", &key).expect("write blob json");

        refresh_blob_from_server(&client, &test_session(), &key).expect("refresh");

        let blob = config_read_encrypted_buffer("blob", &key)
            .expect("read blob")
            .expect("blob exists");
        assert_eq!(blob, blob_bytes);
        assert!(
            config_read_encrypted_buffer(BLOB_JSON_NAME, &key)
                .expect("read blob json")
                .is_none()
        );
    }

    #[test]
    fn refresh_blob_from_server_reports_empty_body() {
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let key = [7u8; KDF_HASH_LEN];
        let err =
            refresh_blob_from_server(&HttpClient::mock(), &test_session(), &key).expect_err("err");
        assert!(format!("{err}").contains("Unable to fetch blob"));
    }
}
