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
    if response.body.is_empty() { return Err(blob_fetch_error()); }
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
    let Some((key, session)) = load_queue_credentials()? else { return Ok(()); };
    let params = build_show_website_params(account, blob, &session, &key)?;
    upload_queue::enqueue(&key, "show_website.php", params, !matches!(sync_mode, SyncMode::No))
}

pub(crate) fn maybe_push_account_share_move(
    account: &Account,
    blob: &Blob,
    original_share_id: Option<&str>,
) -> Result<()> {
    let Some((key, session)) = load_queue_credentials()? else { return Ok(()); };
    let client = HttpClient::from_env()?;
    push_account_share_move_with_client(&client, &session, &key, account, blob, original_share_id)
}

pub(crate) fn maybe_push_account_remove(account: &Account, sync_mode: SyncMode) -> Result<()> {
    let Some((key, session)) = load_queue_credentials()? else { return Ok(()); };
    let params = build_show_website_delete_params(account, &session);
    upload_queue::enqueue(&key, "show_website.php", params, !matches!(sync_mode, SyncMode::No))
}

pub(crate) fn maybe_log_access(account: &Account, sync_mode: SyncMode) -> Result<()> {
    if account.id == "0" {
        return Ok(());
    }

    let Some((key, session)) = load_queue_credentials()? else { return Ok(()); };
    let params = build_log_access_params(account, &session);
    upload_queue::enqueue(&key, "loglogin.php", params, !matches!(sync_mode, SyncMode::No))
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

fn push_account_share_move_with_client(
    client: &HttpClient,
    session: &Session,
    vault_key: &[u8; KDF_HASH_LEN],
    account: &Account,
    blob: &Blob,
    original_share_id: Option<&str>,
) -> Result<()> {
    let params = build_share_move_params(account, blob, session, vault_key, original_share_id)?;
    if params.is_empty() {
        return Ok(());
    }

    let params_ref: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let response = client.post_lastpass(None, "lastpass/api.php", Some(session), &params_ref)?;
    if response.status >= 400 {
        return Err(LpassError::User("Move to/from shared folder failed (-22)"));
    }

    match crate::xml::parse_lastpass_api_ok(&response.body) {
        Some(true) => Ok(()),
        Some(false) => Err(LpassError::User("Move to/from shared folder failed (-1)")),
        None => Err(LpassError::User("Move to/from shared folder failed (-22)")),
    }
}

fn build_share_move_params(
    account: &Account,
    blob: &Blob,
    session: &Session,
    vault_key: &[u8; KDF_HASH_LEN],
    original_share_id: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let current_share_id = normalize_share_id(account.share_id.as_deref());
    let original_share_id = normalize_share_id(original_share_id);
    if current_share_id.is_none() && original_share_id.is_none() { return Ok(Vec::new()); }

    let key = upload_key_for_account(account, blob, vault_key)?;
    let mut params = Vec::with_capacity(13);
    params.push(("token".to_string(), session.token.clone()));
    params.push(("cmd".to_string(), "uploadaccounts".to_string()));
    params.push(("aid0".to_string(), account.id.clone()));
    params.push(("name0".to_string(), encrypt_and_encode(&account.name, key)?));
    params.push(("grouping0".to_string(), encrypt_and_encode(&account.group, key)?));
    params.push(("url0".to_string(), encode_upload_url(account, session, key)?));
    params.push(("username0".to_string(), encrypt_and_encode(&account.username, key)?));
    params.push(("password0".to_string(), encrypt_and_encode(&account.password, key)?));
    params.push(("pwprotect0".to_string(), on_off(account.pwprotect)));
    params.push(("extra0".to_string(), encrypt_and_encode(&account.note, key)?));
    params.push(("todelete".to_string(), account.id.clone()));

    if let Some(share_id) = current_share_id {
        params.push(("sharedfolderid".to_string(), share_id.to_string()));
    }
    if let Some(share_id) = original_share_id {
        params.push(("origsharedfolderid".to_string(), share_id.to_string()));
    }
    if session.url_logging_enabled {
        params.push(("recordUrl".to_string(), hex::encode(account.url.as_bytes())));
    }

    Ok(params)
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
        ("grouping".to_string(), encrypt_and_encode(&account.group, key)?),
        ("pwprotect".to_string(), on_off(account.pwprotect)),
        ("aid".to_string(), account_id_for_upload(account)),
        ("username".to_string(), encrypt_and_encode(&account.username, key)?),
        ("password".to_string(), encrypt_and_encode(&account.password, key)?),
        ("extra".to_string(), encrypt_and_encode(&account.note, key)?),
        ("url".to_string(), encode_upload_url(account, session, key)?),
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

fn on_off(value: bool) -> String {
    if value { "on" } else { "off" }.to_string()
}

fn normalize_share_id(value: Option<&str>) -> Option<&str> {
    match value {
        Some(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn account_id_for_upload(account: &Account) -> String {
    if account.id.is_empty() {
        "0".to_string()
    } else {
        account.id.clone()
    }
}

fn encode_upload_url(
    account: &Account,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<String> {
    if session.url_encryption_enabled && !is_secure_note(account) {
        encrypt_and_encode(&account.url, key)
    } else {
        Ok(hex::encode(account.url.as_bytes()))
    }
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
    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() != Ok("1") { return Ok(()); }
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
mod tests;
