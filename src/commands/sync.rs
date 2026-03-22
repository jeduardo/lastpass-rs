#![forbid(unsafe_code)]

use crate::agent::agent_get_decryption_key;
use crate::commands::data::ensure_mock_blob;
use crate::error::LpassError;
use crate::kdf::KDF_HASH_LEN;
use crate::session::{Session, session_load};
use crate::terminal;
use crate::upload_queue;

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", terminal::cli_failure_text(&err));
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<i32, String> {
    let parsed = parse_args(args)?;

    let credentials = load_key_and_session();
    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") && credentials.is_err() {
        ensure_mock_blob().map_err(|err| format!("{err}"))?;
        return Ok(0);
    }

    let (key, session) = credentials?;
    if parsed.background {
        upload_queue::ensure_running(&key).map_err(|err| format!("{err}"))?;
        return Ok(0);
    }

    if upload_queue::is_running() {
        upload_queue::wait_for_completion();
        return Ok(0);
    }

    upload_queue::process_pending(&key, &session).map_err(|err| format!("{err}"))?;
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
    use crate::config::{
        ConfigEnv, config_write_buffer, config_write_encrypted_string, set_test_env,
    };
    use crate::session::session_save;
    use tempfile::TempDir;

    fn save_key_and_session(home: &TempDir, key: &[u8; KDF_HASH_LEN]) {
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        config_write_buffer("plaintext_key", key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", key)
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
            key,
        )
        .expect("save session");
    }

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
    fn run_inner_mock_mode_without_session_is_a_noop() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("tempdir");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");

        assert_eq!(run_inner(&[]).expect("mock sync"), 0);
    }

    #[test]
    #[cfg(unix)]
    fn run_inner_waits_for_existing_uploader_process() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("tempdir");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [7u8; KDF_HASH_LEN];
        save_key_and_session(&home, &key);

        let mut child = std::process::Command::new("sleep")
            .arg("0.2")
            .spawn()
            .expect("spawn uploader");
        let pid = child.id();
        let waiter = std::thread::spawn(move || {
            let _ = child.wait();
        });
        crate::config::config_write_string("uploader.pid", &pid.to_string()).expect("write pid");

        assert_eq!(run_inner(&[]).expect("sync"), 0);
        let _ = waiter.join();
        assert!(
            crate::config::config_read_string("uploader.pid")
                .expect("read pid")
                .is_none()
        );
    }
}
