#![forbid(unsafe_code)]

use std::env;
use std::io::Read;

use crate::agent::agent_get_decryption_key;
use crate::blob::{Account, Blob};
use crate::config::{
    config_read_buffer, config_read_encrypted_buffer, config_write_buffer,
    config_write_encrypted_buffer,
};
use crate::crypto::decrypt_private_key;
use crate::error::{LpassError, Result};
use crate::kdf::KDF_HASH_LEN;
use brotli::Decompressor as BrotliDecoder;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use serde_json;

const BLOB_JSON_NAME: &str = "blob.json";

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
