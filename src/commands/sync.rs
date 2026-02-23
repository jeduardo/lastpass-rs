#![forbid(unsafe_code)]

use crate::agent::agent_get_decryption_key;
use crate::commands::data::ensure_mock_blob;
use crate::config::ConfigStore;
use crate::error::LpassError;
use crate::http::HttpClient;
use crate::kdf::KDF_HASH_LEN;
use crate::session::{Session, session_load};
use crate::terminal;

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<i32, String> {
    let parsed = parse_args(args)?;

    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
        ensure_mock_blob().map_err(|err| format!("{err}"))?;
        let _ = parsed.background;
        return Ok(0);
    }

    let (key, session) = load_key_and_session()?;
    let client = HttpClient::from_env().map_err(|err| format!("{err}"))?;
    sync_session_blob(&client, &session, &key)?;
    let _ = parsed.background;
    Ok(0)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ParsedArgs {
    background: bool,
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    let usage = "usage: sync [--background, -b] [--color=auto|never|always]";
    let mut background = false;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            return Err(usage.to_string());
        }

        if arg == "--background" || arg == "-b" {
            background = true;
            continue;
        }
        if arg == "--color" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }

        return Err(usage.to_string());
    }

    Ok(ParsedArgs { background })
}

fn load_key_and_session() -> Result<([u8; KDF_HASH_LEN], Session), String> {
    let key = agent_get_decryption_key().map_err(map_decryption_key_error)?;
    let session = session_load(&key)
        .map_err(map_decryption_key_error)?
        .ok_or_else(|| {
            "Could not find session. Perhaps you need to login with `lpass login`.".to_string()
        })?;
    Ok((key, session))
}

fn sync_session_blob(
    client: &HttpClient,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<(), String> {
    let params = [
        ("mobile", "1"),
        ("requestsrc", "cli"),
        ("hasplugin", env!("CARGO_PKG_VERSION")),
    ];
    let response = client
        .post_lastpass_bytes(None, "getaccts.php", Some(session), &params)
        .map_err(|err| format!("{err}"))?;
    store_blob_bytes(&response.body, key)
}

fn store_blob_bytes(blob_bytes: &[u8], key: &[u8; KDF_HASH_LEN]) -> Result<(), String> {
    store_blob_bytes_with_store(&ConfigStore::from_current(), blob_bytes, key)
}

fn store_blob_bytes_with_store(
    store: &ConfigStore,
    blob_bytes: &[u8],
    key: &[u8; KDF_HASH_LEN],
) -> Result<(), String> {
    if blob_bytes.is_empty() {
        return Err("Unable to fetch blob. Please re-run login.".to_string());
    }
    store
        .write_encrypted_buffer("blob", blob_bytes, key)
        .map_err(|err| format!("{err}"))?;
    let _ = store.unlink("blob.json");
    Ok(())
}

fn map_decryption_key_error(err: LpassError) -> String {
    match err {
        LpassError::Crypto("missing iterations")
        | LpassError::Crypto("missing username")
        | LpassError::Crypto("missing verify") => {
            "Could not find decryption key. Perhaps you need to login with `lpass login`."
                .to_string()
        }
        _ => format!("{err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn run_inner_rejects_invalid_usage() {
        let err = run_inner(&["unexpected".to_string()]).expect_err("positional should fail");
        assert!(err.contains("usage: sync"));

        let err = run_inner(&["--color".to_string()]).expect_err("missing color value");
        assert!(err.contains("usage: sync"));

        let err = run_inner(&["--color=rainbow".to_string()]).expect_err("bad color mode");
        assert!(err.contains("usage: sync"));
    }

    #[test]
    fn map_decryption_key_error_maps_missing_values() {
        let mapped = map_decryption_key_error(LpassError::Crypto("missing iterations"));
        assert!(mapped.contains("Could not find decryption key"));

        let mapped = map_decryption_key_error(LpassError::Crypto("other"));
        assert!(mapped.contains("crypto error"));
    }

    #[test]
    fn parse_args_accepts_background_and_color_flags() {
        let parsed = parse_args(&["--background".to_string(), "--color=never".to_string()])
            .expect("parse args");
        assert!(parsed.background);

        let parsed = parse_args(&[
            "-b".to_string(),
            "--color".to_string(),
            "always".to_string(),
        ])
        .expect("parse args");
        assert!(parsed.background);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(&["--bogus".to_string()]).expect_err("unknown flag");
        assert!(err.contains("usage: sync"));
    }

    #[test]
    fn store_blob_bytes_rejects_empty_blob() {
        let key = [1u8; KDF_HASH_LEN];
        let err = store_blob_bytes(&[], &key).expect_err("empty blob must fail");
        assert!(err.contains("Unable to fetch blob"));
    }

    #[test]
    fn store_blob_bytes_writes_blob_file() {
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(crate::config::ConfigEnv {
            lpass_home: Some(Path::new(temp.path()).to_path_buf()),
            ..crate::config::ConfigEnv::default()
        });
        let key = [2u8; KDF_HASH_LEN];
        store_blob_bytes_with_store(&store, b"LPAVx", &key).expect("store blob");
        let encrypted_blob = store
            .read_buffer("blob")
            .expect("read blob")
            .expect("blob exists");
        assert!(!encrypted_blob.is_empty());
    }

    #[test]
    fn sync_session_blob_uses_client_and_surfaces_empty_response_error() {
        let key = [3u8; KDF_HASH_LEN];
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let client = HttpClient::mock();
        let err = sync_session_blob(&client, &session, &key).expect_err("empty mock body");
        assert!(err.contains("Unable to fetch blob"));
    }
}
