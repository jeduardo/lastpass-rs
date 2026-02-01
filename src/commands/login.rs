#![forbid(unsafe_code)]

use std::env;

use crate::config::{config_write_buffer, config_write_encrypted_buffer, config_write_string};
use crate::crypto::decrypt_private_key;
use crate::error::Result;
use crate::http::HttpClient;
use crate::kdf::{kdf_decryption_key, kdf_login_key};
use crate::password::prompt_password;
use crate::session::{session_save, Session};
use crate::xml::{parse_error_cause, parse_ok_session};
use super::data::ensure_mock_blob;
use crate::agent::agent_save;
use crate::config::config_unlink;
use crate::terminal::{self, BOLD, FG_GREEN, RESET, UNDERLINE};

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
    let mut trust = false;
    let mut plaintext_key = false;
    let mut force = false;
    let mut username: Option<String> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--trust" || arg == "-t" {
            trust = true;
            continue;
        }
        if arg == "--plaintext-key" || arg == "-P" {
            plaintext_key = true;
            continue;
        }
        if arg == "--force" || arg == "-f" {
            force = true;
            continue;
        }
        if arg == "--color" || arg == "-C" {
            let value = iter.next().ok_or_else(|| {
                "... --color=auto|never|always".to_string()
            })?;
            let mode = terminal::parse_color_mode(value)
                .ok_or_else(|| "... --color=auto|never|always".to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value)
                .ok_or_else(|| "... --color=auto|never|always".to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if arg.starts_with('-') {
            return Err("usage: login [--trust] [--plaintext-key [--force, -f]] USERNAME".to_string());
        }
        if username.is_none() {
            username = Some(arg.clone());
        } else {
            return Err("usage: login [--trust] [--plaintext-key [--force, -f]] USERNAME".to_string());
        }
    }

    let username = username.ok_or_else(|| "usage: login [--trust] [--plaintext-key [--force, -f]] USERNAME".to_string())?;

    if plaintext_key && !force {
        // keep behavior simple: allow but warn
        eprintln!("warning: --plaintext-key reduces security; use --force to suppress this warning");
    }

    let iterations = fetch_iterations(&username).map_err(|err| format!("{err}"))?;
    if iterations == 0 {
        return Err("Unable to fetch iteration count.".to_string());
    }

    let password = prompt_password(&username).map_err(|err| format!("{err}"))?;
    let login_hash = kdf_login_key(&username, &password, iterations)
        .map_err(|err| format!("{err}"))?;
    let key = kdf_decryption_key(&username, &password, iterations)
        .map_err(|err| format!("{err}"))?;

    let mut session = lastpass_login(&username, &login_hash, iterations)
        .map_err(|err| format!("{err}"))?;
    if session.private_key.is_none() {
        if let Some(private_key_enc) = session.private_key_enc.clone() {
            if let Ok(private_key) = decrypt_private_key(&private_key_enc, &key) {
                session.private_key = Some(private_key);
            }
        }
    }
    session_save(&session, &key).map_err(|err| format!("{err}"))?;

    config_write_string("username", &username).map_err(|err| format!("{err}"))?;
    config_write_string("iterations", &iterations.to_string()).map_err(|err| format!("{err}"))?;

    let _ = config_unlink("plaintext_key");
    if plaintext_key {
        config_write_buffer("plaintext_key", &key).map_err(|err| format!("{err}"))?;
    }

    agent_save(&username, iterations, &key).map_err(|err| format!("{err}"))?;

    if env::var("LPASS_HTTP_MOCK").as_deref() != Ok("1") {
        let blob = fetch_blob(&session)?;
        if !blob.is_empty() {
            config_write_encrypted_buffer("blob", &blob, &key).map_err(|err| format!("{err}"))?;
            let _ = crate::config::config_unlink("blob.json");
        }
    } else {
        ensure_mock_blob().map_err(|err| format!("{err}"))?;
    }

    if trust {
        // placeholder: trust is not implemented yet
    }

    let message =
        format!("{FG_GREEN}{BOLD}Success{RESET}: Logged in as {UNDERLINE}{username}{RESET}.");
    println!("{}", terminal::render_stdout(&message));
    Ok(0)
}

fn fetch_iterations(username: &str) -> Result<u32> {
    let client = HttpClient::from_env()?;
    let user_lower = username.to_ascii_lowercase();
    let response = client.post_lastpass(None, "iterations.php", None, &[("email", &user_lower)])?;
    response
        .body
        .trim()
        .parse::<u32>()
        .map_err(|_| crate::error::LpassError::Crypto("invalid iterations"))
}

fn lastpass_login(username: &str, hash: &str, iterations: u32) -> Result<Session> {
    let client = HttpClient::from_env()?;
    let user_lower = username.to_ascii_lowercase();
    let iterations_str = iterations.to_string();

    let params = [
        ("xml", "2"),
        ("username", user_lower.as_str()),
        ("hash", hash),
        ("iterations", iterations_str.as_str()),
        ("includeprivatekeyenc", "1"),
        ("method", "cli"),
        ("outofbandsupported", "1"),
    ];

    let response = client.post_lastpass(None, "login.php", None, &params)?;
    if let Some(mut session) = parse_ok_session(&response.body) {
        session.server = Some(crate::http::LASTPASS_SERVER.to_string());
        return Ok(session);
    }

    if let Some(_message) = parse_error_cause(&response.body, "message") {
        return Err(crate::error::LpassError::Crypto("login failed"));
    }

    Err(crate::error::LpassError::Crypto("login failed"))
}

fn fetch_blob(session: &Session) -> std::result::Result<Vec<u8>, String> {
    let client = HttpClient::from_env().map_err(|err| format!("{err}"))?;
    let params = [
        ("mobile", "1"),
        ("requestsrc", "cli"),
        ("hasplugin", env!("CARGO_PKG_VERSION")),
    ];
    let response = client
        .post_lastpass_bytes(None, "getaccts.php", Some(session), &params)
        .map_err(|err| format!("{err}"))?;
    if response.body.is_empty() {
        return Err("empty blob response".to_string());
    }
    Ok(response.body)
}
