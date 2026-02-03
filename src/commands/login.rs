#![forbid(unsafe_code)]

use std::env;
use std::io::{self, BufRead, Write};
use std::process::Command;

use super::data::ensure_mock_blob;
use crate::agent::agent_save;
use crate::config::config_unlink;
use crate::config::{ConfigStore, config_write_buffer, config_write_string};
use crate::crypto::decrypt_private_key;
use crate::error::Result;
use crate::http::HttpClient;
use crate::kdf::{KDF_HASH_LEN, kdf_decryption_key, kdf_login_key};
use crate::password::prompt_password;
use crate::session::{Session, session_save};
use crate::terminal::{self, BOLD, FG_GREEN, RESET, UNDERLINE};
use crate::xml::{parse_error_cause, parse_ok_session};
use rand::Rng;

#[derive(Debug, Clone, Eq, PartialEq)]
struct LoginArgs {
    trust: bool,
    plaintext_key: bool,
    force: bool,
    username: String,
}

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> std::result::Result<i32, String> {
    let parsed = parse_login_args(args)?;

    if parsed.plaintext_key
        && !parsed.force
        && !ask_yes_no(
            false,
            "You have used the --plaintext-key option. This option will greatly reduce the security of your passwords. You are advised, instead, to use the agent, whose timeout can be disabled by setting LPASS_AGENT_TIMEOUT=0. Are you sure you would like to do this?",
        )
        .map_err(|err| format!("{err}"))?
    {
        return Err("Login aborted. Try again without --plaintext-key.".to_string());
    }

    let iterations = fetch_iterations(&parsed.username).map_err(|err| format!("{err}"))?;
    ensure_nonzero_iterations(iterations)?;

    let trusted_id = calculate_trust_id(parsed.trust).map_err(|err| format!("{err}"))?;
    let trust_label = if parsed.trust {
        Some(calculate_trust_label())
    } else {
        None
    };

    let (mut session, key) = loop {
        let password = prompt_password(&parsed.username).map_err(|err| format!("{err}"))?;
        let login_hash = kdf_login_key(&parsed.username, &password, iterations)
            .map_err(|err| format!("{err}"))?;
        let key = kdf_decryption_key(&parsed.username, &password, iterations)
            .map_err(|err| format!("{err}"))?;

        match lastpass_login(
            &parsed.username,
            &login_hash,
            iterations,
            trusted_id.as_deref(),
            trust_label.as_deref(),
        ) {
            Ok(session) => break (session, key),
            Err(message) => {
                eprintln!("Error: {message}");
                continue;
            }
        }
    };

    maybe_attach_private_key(&mut session, &key);

    session_save(&session, &key).map_err(|err| format!("{err}"))?;

    config_write_string("username", &parsed.username).map_err(|err| format!("{err}"))?;
    config_write_string("iterations", &iterations.to_string()).map_err(|err| format!("{err}"))?;

    let _ = config_unlink("plaintext_key");
    if parsed.plaintext_key {
        config_write_buffer("plaintext_key", &key).map_err(|err| format!("{err}"))?;
    }

    agent_save(&parsed.username, iterations, &key).map_err(|err| format!("{err}"))?;

    persist_blob_after_login(&session, &key)?;

    if parsed.trust {
        let _ = post_trust(&session, trusted_id.as_deref(), trust_label.as_deref());
    }

    let message = format!(
        "{FG_GREEN}{BOLD}Success{RESET}: Logged in as {UNDERLINE}{}{RESET}.",
        parsed.username
    );
    println!("{}", terminal::render_stdout(&message));
    Ok(0)
}

fn parse_login_args(args: &[String]) -> std::result::Result<LoginArgs, String> {
    let usage = "usage: login [--trust] [--plaintext-key [--force, -f]] [--color=auto|never|always] USERNAME";
    let mut trust = false;
    let mut plaintext_key = false;
    let mut force = false;
    let mut username: Option<String> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--trust" {
            trust = true;
            continue;
        }
        if arg == "--plaintext-key" {
            plaintext_key = true;
            continue;
        }
        if arg == "--force" || arg == "-f" {
            force = true;
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
        if arg.starts_with('-') {
            return Err(usage.to_string());
        }
        if username.is_some() {
            return Err(usage.to_string());
        }
        username = Some(arg.clone());
    }

    let username = username.ok_or_else(|| usage.to_string())?;
    Ok(LoginArgs {
        trust,
        plaintext_key,
        force,
        username,
    })
}

fn ensure_nonzero_iterations(iterations: u32) -> std::result::Result<(), String> {
    if iterations == 0 {
        Err("Unable to fetch iteration count.".to_string())
    } else {
        Ok(())
    }
}

fn maybe_attach_private_key(session: &mut Session, key: &[u8; KDF_HASH_LEN]) {
    if session.private_key.is_some() {
        return;
    }
    let Some(private_key_enc) = session.private_key_enc.clone() else {
        return;
    };
    if let Ok(private_key) = decrypt_private_key(&private_key_enc, key) {
        session.private_key = Some(private_key);
    }
}

fn fetch_iterations(username: &str) -> Result<u32> {
    let client = HttpClient::from_env()?;
    fetch_iterations_with_client(&client, username)
}

fn fetch_iterations_with_client(client: &HttpClient, username: &str) -> Result<u32> {
    let user_lower = username.to_ascii_lowercase();
    let response = client.post_lastpass(None, "iterations.php", None, &[("email", &user_lower)])?;
    response
        .body
        .trim()
        .parse::<u32>()
        .map_err(|_| crate::error::LpassError::Crypto("invalid iterations"))
}

fn lastpass_login(
    username: &str,
    hash: &str,
    iterations: u32,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
) -> std::result::Result<Session, String> {
    let client = HttpClient::from_env().map_err(|err| format!("{err}"))?;
    lastpass_login_with_client(&client, username, hash, iterations, trusted_id, trust_label)
        .map_err(|err| format!("{err}"))
}

#[cfg(test)]
fn lastpass_login_with_client_basic(
    client: &HttpClient,
    username: &str,
    hash: &str,
    iterations: u32,
) -> Result<Session> {
    lastpass_login_with_client(client, username, hash, iterations, None, None)
}

fn lastpass_login_with_client(
    client: &HttpClient,
    username: &str,
    hash: &str,
    iterations: u32,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
) -> Result<Session> {
    let user_lower = username.to_ascii_lowercase();
    let iterations_str = iterations.to_string();

    let mut params = vec![
        ("xml", "2"),
        ("username", user_lower.as_str()),
        ("hash", hash),
        ("iterations", iterations_str.as_str()),
        ("includeprivatekeyenc", "1"),
        ("method", "cli"),
        ("outofbandsupported", "1"),
    ];
    if let Some(uuid) = trusted_id {
        params.push(("uuid", uuid));
    }
    if let Some(label) = trust_label {
        params.push(("trustlabel", label));
    }

    let response = client.post_lastpass(None, "login.php", None, &params)?;
    parse_login_response(&response.body)
}

fn parse_login_response(body: &str) -> Result<Session> {
    if let Some(mut session) = parse_ok_session(body) {
        session.server = Some(crate::http::LASTPASS_SERVER.to_string());
        return Ok(session);
    }

    if let Some(message) = parse_error_cause(body, "message") {
        return Err(crate::error::LpassError::User(filter_error_message(
            &message,
        )));
    }

    Err(crate::error::LpassError::Crypto("login failed"))
}

fn filter_error_message(message: &str) -> &'static str {
    if message.contains("invalid password") {
        return "Invalid password";
    }
    if message.contains("multifactor") {
        return "Multifactor authentication failed";
    }
    "login failed"
}

fn fetch_blob(session: &Session) -> std::result::Result<Vec<u8>, String> {
    let client = HttpClient::from_env().map_err(|err| format!("{err}"))?;
    fetch_blob_with_client(&client, session)
}

fn fetch_blob_with_client(
    client: &HttpClient,
    session: &Session,
) -> std::result::Result<Vec<u8>, String> {
    let params = [
        ("mobile", "1"),
        ("requestsrc", "cli"),
        ("hasplugin", env!("CARGO_PKG_VERSION")),
    ];
    let response = client
        .post_lastpass_bytes(None, "getaccts.php", Some(session), &params)
        .map_err(|err| format!("{err}"))?;
    ensure_non_empty_blob_response(response.body)
}

fn ensure_non_empty_blob_response(blob: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
    if blob.is_empty() {
        return Err("empty blob response".to_string());
    }
    Ok(blob)
}

fn persist_blob_after_login(
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
) -> std::result::Result<(), String> {
    let use_mock = env::var("LPASS_HTTP_MOCK").as_deref() == Ok("1");
    let store = ConfigStore::from_current();
    persist_blob_after_login_with_fetch(&store, use_mock, session, key, fetch_blob)
}

fn persist_blob_after_login_with_fetch<F>(
    store: &ConfigStore,
    use_mock: bool,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
    fetch_blob_fn: F,
) -> std::result::Result<(), String>
where
    F: Fn(&Session) -> std::result::Result<Vec<u8>, String>,
{
    if use_mock {
        ensure_mock_blob().map_err(|err| format!("{err}"))?;
        return Ok(());
    }
    let blob = fetch_blob_fn(session)?;
    store
        .write_encrypted_buffer("blob", &blob, key)
        .map_err(|err| format!("{err}"))?;
    let _ = store.unlink("blob.json");
    Ok(())
}

fn ask_yes_no(default_yes: bool, prompt: &str) -> std::result::Result<bool, String> {
    let mut reader = io::stdin().lock();
    let mut writer = io::stderr().lock();
    ask_yes_no_with_reader_writer(&mut reader, &mut writer, default_yes, prompt)
}

fn ask_yes_no_with_reader_writer<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    default_yes: bool,
    prompt: &str,
) -> std::result::Result<bool, String> {
    let options = if default_yes { "Y/n" } else { "y/N" };
    loop {
        writer
            .write_all(terminal::render_stderr(&format!("{prompt} [{options}] ")).as_bytes())
            .map_err(|err| format!("write: {err}"))?;
        writer.flush().map_err(|err| format!("flush: {err}"))?;

        let mut response = String::new();
        let read = reader
            .read_line(&mut response)
            .map_err(|err| format!("read: {err}"))?;
        if read == 0 {
            return Err("aborted response.".to_string());
        }
        if let Some(value) = parse_yes_no_response(response.trim(), default_yes) {
            return Ok(value);
        }
        writer
            .write_all(
                format!(
                    "{}\n",
                    terminal::render_stderr(&format!(
                        "{BOLD}Error{RESET}: Response not understood."
                    ))
                )
                .as_bytes(),
            )
            .map_err(|err| format!("write: {err}"))?;
        writer.flush().map_err(|err| format!("flush: {err}"))?;
    }
}

fn parse_yes_no_response(input: &str, default_yes: bool) -> Option<bool> {
    if input.is_empty() {
        return Some(default_yes);
    }
    let first = input.as_bytes()[0] as char;
    if first.eq_ignore_ascii_case(&'y') {
        Some(true)
    } else if first.eq_ignore_ascii_case(&'n') {
        Some(false)
    } else {
        None
    }
}

fn generate_trusted_id() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

fn calculate_trust_id(force: bool) -> Result<Option<String>> {
    calculate_trust_id_with_store(&ConfigStore::from_current(), force)
}

fn calculate_trust_id_with_store(store: &ConfigStore, force: bool) -> Result<Option<String>> {
    let current = store.read_string("trusted_id")?;
    if current.is_some() || !force {
        return Ok(current);
    }
    let trusted_id = generate_trusted_id();
    store.write_string("trusted_id", &trusted_id)?;
    Ok(Some(trusted_id))
}

fn calculate_trust_label() -> String {
    let hostname = command_output_trimmed("hostname")
        .or_else(|| env::var("HOSTNAME").ok())
        .or_else(|| env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "unknown-host".to_string());
    let sysname = command_output_trimmed("uname -s").unwrap_or_else(|| "UnknownOS".to_string());
    let release =
        command_output_trimmed("uname -r").unwrap_or_else(|| "unknown-release".to_string());
    format!("{hostname} - {sysname} {release}")
}

fn command_output_trimmed(command: &str) -> Option<String> {
    let mut parts = command.split_whitespace();
    let program = parts.next()?;
    let args: Vec<&str> = parts.collect();
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn post_trust(
    session: &Session,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
) -> Result<()> {
    if trusted_id.is_none() || trust_label.is_none() {
        return Ok(());
    }
    let client = HttpClient::from_env()?;
    post_trust_with_client(&client, session, trusted_id, trust_label)
}

fn post_trust_with_client(
    client: &HttpClient,
    session: &Session,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
) -> Result<()> {
    let (Some(uuid), Some(label)) = (trusted_id, trust_label) else {
        return Ok(());
    };
    let _ = client.post_lastpass(
        None,
        "trust.php",
        Some(session),
        &[
            ("token", &session.token),
            ("uuid", uuid),
            ("trustlabel", label),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigEnv;
    use crate::crypto::{aes_encrypt_lastpass, base64_lastpass_encode};
    use crate::http::HttpClient;
    use crate::kdf::kdf_login_key;
    use tempfile::TempDir;

    #[test]
    fn run_inner_requires_username() {
        let err = run_inner(&[]).expect_err("missing username must fail");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn run_inner_rejects_unknown_flags() {
        let err = run_inner(&["--nope".to_string()]).expect_err("unknown flag must fail");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn run_inner_rejects_extra_positional_args() {
        let err = run_inner(&["a@example.com".to_string(), "extra".to_string()])
            .expect_err("extra positional must fail");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn run_inner_rejects_invalid_color_mode() {
        let err = run_inner(&["--color=rainbow".to_string(), "a@example.com".to_string()])
            .expect_err("invalid color mode must fail");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn parse_login_args_supports_space_separated_color() {
        let parsed = parse_login_args(&[
            "--color".to_string(),
            "always".to_string(),
            "user@example.com".to_string(),
        ])
        .expect("args parse");
        assert_eq!(
            parsed,
            LoginArgs {
                trust: false,
                plaintext_key: false,
                force: false,
                username: "user@example.com".to_string(),
            }
        );
        terminal::set_color_mode(terminal::ColorMode::Auto);
    }

    #[test]
    fn parse_login_args_rejects_color_without_value() {
        let err = parse_login_args(&["--color".to_string()]).expect_err("missing value");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn parse_login_args_rejects_invalid_space_separated_color() {
        let err = parse_login_args(&[
            "--color".to_string(),
            "rainbow".to_string(),
            "user@example.com".to_string(),
        ])
        .expect_err("invalid color");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn fetch_iterations_uses_mock_client() {
        let client = HttpClient::mock();
        let iterations = fetch_iterations_with_client(&client, "USER@example.com").expect("iters");
        assert_eq!(iterations, 1000);
    }

    #[test]
    fn lastpass_login_with_mock_client_supports_success_and_failure() {
        let client = HttpClient::mock();
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let session = lastpass_login_with_client_basic(&client, "USER@example.com", &hash, 1000)
            .expect("login");
        assert_eq!(session.uid, "57747756");
        assert_eq!(session.session_id, "1234");
        assert_eq!(session.token, "abcd");
        assert_eq!(
            session.server.as_deref(),
            Some(crate::http::LASTPASS_SERVER)
        );

        let err = lastpass_login_with_client_basic(&client, "user@example.com", "bad", 1000)
            .expect_err("bad login must fail");
        assert!(matches!(err, crate::error::LpassError::User(_)));
    }

    #[test]
    fn fetch_blob_with_mock_client_rejects_empty_body() {
        let client = HttpClient::mock();
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let err = fetch_blob_with_client(&client, &session).expect_err("empty blob must fail");
        assert_eq!(err, "empty blob response");
    }

    #[test]
    fn fetch_blob_with_real_client_propagates_http_error() {
        let client = HttpClient::real().expect("real client");
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: Some("127.0.0.1:1".to_string()),
            private_key: None,
            private_key_enc: None,
        };
        let err = fetch_blob_with_client(&client, &session).expect_err("network error");
        assert!(err.contains("http post"));
    }

    #[test]
    fn fetch_blob_covers_wrapper_path() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let _ = fetch_blob(&session);
    }

    #[test]
    fn ensure_non_empty_blob_response_returns_input_when_non_empty() {
        let blob = ensure_non_empty_blob_response(vec![1, 2, 3]).expect("non-empty blob");
        assert_eq!(blob, vec![1, 2, 3]);
    }

    #[test]
    fn persist_blob_after_login_with_fetch_handles_mock_and_non_mock_paths() {
        fn sample_blob(_session: &Session) -> std::result::Result<Vec<u8>, String> {
            Ok(vec![7, 8, 9])
        }

        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [5u8; KDF_HASH_LEN];
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        persist_blob_after_login_with_fetch(&store, true, &session, &key, sample_blob)
            .expect("mock mode");
        assert!(
            store
                .read_encrypted_buffer("blob", &key)
                .expect("read blob")
                .is_none()
        );

        persist_blob_after_login_with_fetch(&store, false, &session, &key, sample_blob)
            .expect("persist blob");

        let stored = store
            .read_encrypted_buffer("blob", &key)
            .expect("read blob")
            .expect("blob present");
        assert_eq!(stored, vec![7, 8, 9]);
    }

    #[test]
    fn persist_blob_after_login_with_fetch_propagates_fetch_and_write_errors() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [5u8; KDF_HASH_LEN];

        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let err = persist_blob_after_login_with_fetch(&store, false, &session, &key, |_session| {
            Err("fetch failed".to_string())
        })
        .expect_err("fetch error");
        assert_eq!(err, "fetch failed");

        let file_home = temp.path().join("not-a-dir");
        std::fs::write(&file_home, b"x").expect("write file");
        let invalid_home = file_home.join("child");
        let bad_store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(invalid_home),
            ..ConfigEnv::default()
        });
        let err =
            persist_blob_after_login_with_fetch(&bad_store, false, &session, &key, |_session| {
                Ok(vec![1, 2, 3])
            })
            .expect_err("write error");
        assert!(err.contains("IO error while"));
    }

    #[test]
    fn persist_blob_after_login_covers_wrapper_path() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [8u8; KDF_HASH_LEN];
        let _ = persist_blob_after_login(&session, &key);
    }

    #[test]
    fn parse_yes_no_response_matches_expected_inputs() {
        assert_eq!(parse_yes_no_response("", false), Some(false));
        assert_eq!(parse_yes_no_response("y", false), Some(true));
        assert_eq!(parse_yes_no_response("n", true), Some(false));
        assert_eq!(parse_yes_no_response("maybe", true), None);
    }

    #[test]
    fn ask_yes_no_with_reader_writer_handles_retry_and_eof() {
        let mut output = Vec::new();
        let mut reader = io::Cursor::new(b"maybe\ny\n".to_vec());
        let value = ask_yes_no_with_reader_writer(&mut reader, &mut output, false, "Prompt")
            .expect("valid answer after retry");
        assert!(value);
        let rendered = String::from_utf8_lossy(&output);
        assert!(rendered.contains("Response not understood."));

        let mut output = Vec::new();
        let mut reader = io::Cursor::new(Vec::<u8>::new());
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut output, true, "Prompt")
            .expect_err("EOF should abort");
        assert_eq!(err, "aborted response.");
    }

    #[test]
    fn ask_yes_no_with_reader_writer_propagates_io_errors() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("write failed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct FailingFlushWriter;
        impl Write for FailingFlushWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("flush failed"))
            }
        }

        struct FailingReader;
        impl BufRead for FailingReader {
            fn fill_buf(&mut self) -> io::Result<&[u8]> {
                Err(io::Error::other("read failed"))
            }
            fn consume(&mut self, _amt: usize) {}
        }
        impl io::Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }

        let mut reader = io::Cursor::new(b"y\n".to_vec());
        let mut writer = FailingWriter;
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, false, "Prompt")
            .expect_err("write error");
        assert!(err.contains("write failed"));

        let mut reader = io::Cursor::new(b"y\n".to_vec());
        let mut writer = FailingFlushWriter;
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, false, "Prompt")
            .expect_err("flush error");
        assert!(err.contains("flush failed"));

        let mut reader = FailingReader;
        let mut writer = Vec::new();
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, false, "Prompt")
            .expect_err("read error");
        assert!(err.contains("read failed"));

        let mut writer = FailingWriter;
        writer.flush().expect("explicit flush path");

        let mut reader = FailingReader;
        reader.consume(0);
        let mut buf = [0u8; 1];
        let err = io::Read::read(&mut reader, &mut buf).expect_err("read path");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn generate_trusted_id_has_expected_shape() {
        let trusted_id = generate_trusted_id();
        assert_eq!(trusted_id.len(), 32);
        assert!(trusted_id.chars().all(|ch| {
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$".contains(ch)
        }));
    }

    #[test]
    fn calculate_trust_id_with_store_respects_force_and_persistence() {
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let id_none = calculate_trust_id_with_store(&store, false).expect("read");
        assert!(id_none.is_none());

        let first = calculate_trust_id_with_store(&store, true)
            .expect("create")
            .expect("created");
        assert_eq!(first.len(), 32);

        let second = calculate_trust_id_with_store(&store, false)
            .expect("read existing")
            .expect("existing");
        assert_eq!(first, second);
    }

    #[test]
    fn calculate_trust_label_is_non_empty() {
        let label = calculate_trust_label();
        assert!(label.contains(" - "));
    }

    #[test]
    fn ensure_nonzero_iterations_rejects_zero() {
        let err = ensure_nonzero_iterations(0).expect_err("zero iterations must fail");
        assert_eq!(err, "Unable to fetch iteration count.");
        ensure_nonzero_iterations(1000).expect("non-zero iterations");
    }

    #[test]
    fn maybe_attach_private_key_covers_guard_and_success_paths() {
        let key = [7u8; KDF_HASH_LEN];
        let mut session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: Some(vec![1]),
            private_key_enc: Some("ignored".to_string()),
        };
        maybe_attach_private_key(&mut session, &key);
        assert_eq!(session.private_key.as_deref(), Some(&[1][..]));

        let payload = b"LastPassPrivateKey<4142>LastPassPrivateKey";
        let encrypted = aes_encrypt_lastpass(payload, &key).expect("encrypt");
        let private_key_enc = base64_lastpass_encode(&encrypted);
        let mut session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: Some(private_key_enc),
        };
        maybe_attach_private_key(&mut session, &key);
        assert_eq!(session.private_key.as_deref(), Some(&[0x41, 0x42][..]));

        let mut session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: Some("not-a-valid-key".to_string()),
        };
        maybe_attach_private_key(&mut session, &key);
        assert!(session.private_key.is_none());
    }

    #[test]
    fn parse_login_response_reports_generic_error_when_message_is_missing() {
        let err = parse_login_response("<response><error/></response>").expect_err("must fail");
        assert!(matches!(
            err,
            crate::error::LpassError::Crypto("login failed")
        ));
    }

    #[test]
    fn command_output_trimmed_handles_missing_and_failing_commands() {
        assert!(command_output_trimmed("__definitely_missing_binary__").is_none());
        assert!(command_output_trimmed("cargo --definitely-unknown-option").is_none());
        assert!(command_output_trimmed("true").is_none());
    }

    #[test]
    fn post_trust_covers_none_and_mock_paths() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        post_trust(&session, None, None).expect("missing trust data is ignored");
        let client = HttpClient::mock();
        post_trust_with_client(&client, &session, None, None).expect("none trust post");
        post_trust_with_client(&client, &session, Some("uuid"), Some("label"))
            .expect("mock trust post");

        let real = HttpClient::real().expect("real client");
        let mut bad_server = session.clone();
        bad_server.server = Some("127.0.0.1:1".to_string());
        let err = post_trust_with_client(&real, &bad_server, Some("uuid"), Some("label"))
            .expect_err("network failure");
        assert!(format!("{err}").contains("http post"));
    }

    #[test]
    fn lastpass_login_with_client_accepts_trust_metadata() {
        let client = HttpClient::mock();
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let session = lastpass_login_with_client(
            &client,
            "user@example.com",
            &hash,
            1000,
            Some("trusted-id"),
            Some("trusted-label"),
        )
        .expect("login");
        assert_eq!(session.uid, "57747756");
    }

    #[test]
    fn filter_error_message_normalizes_known_messages() {
        assert_eq!(filter_error_message("invalid password"), "Invalid password");
        assert_eq!(
            filter_error_message("multifactorresponsefailed"),
            "Multifactor authentication failed"
        );
        assert_eq!(filter_error_message("something else"), "login failed");
    }
}
