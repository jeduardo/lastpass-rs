#![forbid(unsafe_code)]

use std::env;
use std::io::Read;

use crate::agent::agent_get_decryption_key;
use crate::blob::{Account, Blob};
use crate::config::{
    config_read_buffer, config_read_encrypted_buffer, config_write_buffer,
    config_write_encrypted_buffer,
};
use crate::crypto::{aes_encrypt_lastpass, base64_lastpass_encode, decrypt_private_key};
use crate::error::{LpassError, Result};
use crate::http::HttpClient;
use crate::kdf::KDF_HASH_LEN;
use crate::session::Session;
use brotli::Decompressor as BrotliDecoder;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use serde_json;

const BLOB_JSON_NAME: &str = "blob.json";

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SyncMode {
    Auto,
    Now,
    No,
}

impl SyncMode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "now" => Some(Self::Now),
            "no" => Some(Self::No),
            _ => None,
        }
    }
}

pub(crate) fn load_blob() -> Result<Blob> {
    if env::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
        return load_mock_blob();
    }

    let key = agent_get_decryption_key().map_err(map_decryption_key_error)?;
    let session = crate::session::session_load(&key).map_err(map_decryption_key_error)?;
    if session.is_none() {
        return Err(LpassError::User(
            "Could not find session. Perhaps you need to login with `lpass login`.",
        ));
    }

    if let Some(buffer) = config_read_encrypted_buffer(BLOB_JSON_NAME, &key)? {
        let blob = serde_json::from_slice::<Blob>(&buffer)
            .map_err(|_| LpassError::Crypto("invalid blob"))?;
        return Ok(blob);
    }

    let blob_bytes =
        config_read_encrypted_buffer("blob", &key)?.ok_or(LpassError::Crypto("missing blob"))?;
    let blob_bytes = maybe_decompress_blob(blob_bytes)?;
    if !looks_like_blob(&blob_bytes) {
        return Err(LpassError::Crypto(
            "blob response was not a blob; try logging in again",
        ));
    }
    let private_key = load_private_key(&key)?;
    crate::blob::blob_parse(&blob_bytes, &key, private_key.as_deref())
}

pub(crate) fn save_blob(blob: &Blob) -> Result<()> {
    if env::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
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
    if env::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
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
    if env::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
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
        return Err(LpassError::User(
            "Unable to fetch blob. Either your session is invalid and you need to login with `lpass login`, you need to synchronize, your blob is empty, or there is something wrong with your internet connection.",
        ));
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
    if env::var("LPASS_HTTP_MOCK").as_deref() != Ok("1") {
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

fn maybe_decompress_blob(blob_bytes: Vec<u8>) -> Result<Vec<u8>> {
    if looks_like_blob(&blob_bytes) {
        return Ok(blob_bytes);
    }

    if let Some(decoded) = try_gzip(&blob_bytes)? {
        if looks_like_blob(&decoded) {
            return Ok(decoded);
        }
    }

    if let Some(decoded) = try_zlib(&blob_bytes)? {
        if looks_like_blob(&decoded) {
            return Ok(decoded);
        }
    }

    if let Some(decoded) = try_deflate(&blob_bytes)? {
        if looks_like_blob(&decoded) {
            return Ok(decoded);
        }
    }

    if let Some(decoded) = try_brotli(&blob_bytes)? {
        if looks_like_blob(&decoded) {
            return Ok(decoded);
        }
    }

    Ok(blob_bytes)
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

fn try_gzip(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Ok(None);
    }
    let mut decoder = GzDecoder::new(bytes);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|err| LpassError::io("gzip decode", err))?;
    Ok(Some(decoded))
}

fn try_zlib(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    if bytes.len() < 2 || bytes[0] != 0x78 {
        return Ok(None);
    }
    let mut decoder = ZlibDecoder::new(bytes);
    let mut decoded = Vec::new();
    if decoder.read_to_end(&mut decoded).is_err() {
        return Ok(None);
    }
    Ok(Some(decoded))
}

fn try_deflate(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut decoder = DeflateDecoder::new(bytes);
    let mut decoded = Vec::new();
    if decoder.read_to_end(&mut decoded).is_err() {
        return Ok(None);
    }
    Ok(Some(decoded))
}

fn try_brotli(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut decoder = BrotliDecoder::new(bytes, 4096);
    let mut decoded = Vec::new();
    if decoder.read_to_end(&mut decoded).is_err() {
        return Ok(None);
    }
    Ok(Some(decoded))
}

fn save_mock_blob(blob: &Blob) -> Result<()> {
    let buffer = serde_json::to_vec_pretty(blob).map_err(|_| LpassError::Crypto("invalid blob"))?;
    config_write_buffer("blob", &buffer)
}

fn mock_blob() -> Blob {
    let mut blob = Blob {
        version: 1,
        local_version: false,
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
    use flate2::Compression;
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use std::io::Write;

    fn blob_bytes() -> Vec<u8> {
        b"LPAVtest-blob".to_vec()
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
    fn maybe_decompress_blob_handles_gzip_zlib_deflate_and_brotli() {
        let source = blob_bytes();

        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&source).expect("gzip write");
        let gzip = gz.finish().expect("gzip finish");
        assert_eq!(maybe_decompress_blob(gzip).expect("gzip decode"), source);

        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(&source).expect("zlib write");
        let zlib = z.finish().expect("zlib finish");
        assert_eq!(maybe_decompress_blob(zlib).expect("zlib decode"), source);

        let mut d = DeflateEncoder::new(Vec::new(), Compression::default());
        d.write_all(&source).expect("deflate write");
        let deflate = d.finish().expect("deflate finish");
        assert_eq!(
            maybe_decompress_blob(deflate).expect("deflate decode"),
            source
        );

        let mut brotli = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut brotli, 4096, 5, 20);
            writer.write_all(&source).expect("brotli write");
            writer.flush().expect("brotli flush");
        }
        assert_eq!(
            maybe_decompress_blob(brotli).expect("brotli decode"),
            source
        );
    }

    #[test]
    fn maybe_decompress_blob_returns_original_for_unknown_data() {
        let input = b"not-a-compressed-blob".to_vec();
        assert_eq!(maybe_decompress_blob(input.clone()).expect("decode"), input);
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
        assert_eq!(SyncMode::parse("bad"), None);
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
    fn build_show_website_params_uses_encrypted_url_when_feature_enabled() {
        let account = Account {
            id: "0".to_string(),
            share_name: None,
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

        session.url_logging_enabled = true;
        let params = build_show_website_delete_params(&account, &session);
        assert!(params.iter().any(|(k, _)| k == "recordUrl"));
    }

    #[test]
    fn push_account_update_with_client_handles_sync_modes() {
        let key = [5u8; KDF_HASH_LEN];
        let account = Account {
            id: "0".to_string(),
            share_name: None,
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
