#![forbid(unsafe_code)]

use std::io::{self, Write};

use super::data::SyncMode;
use crate::agent::agent_get_decryption_key;
use crate::commands::data::load_blob;
use crate::config::config_read_string;
use crate::crypto::{
    aes_decrypt_base64_lastpass, aes_encrypt_lastpass, base64_lastpass_encode, decrypt_private_key,
    encrypt_private_key, rsa_encrypt_oaep, sha256_hex,
};
use crate::http::HttpClient;
use crate::kdf::{KDF_HASH_LEN, kdf_decryption_key, kdf_login_key};
use crate::password::prompt_password_with_description;
use crate::session::{Session, session_kill, session_load};
use crate::terminal::{self, BOLD, FG_BLUE, FG_CYAN, FG_GREEN, RESET};
use crate::xml::{PwChangeInfo, PwChangeParseError, parse_pwchange};
use zeroize::Zeroize;

#[derive(Debug, Clone)]
struct CommandState {
    username: String,
    current_key: [u8; KDF_HASH_LEN],
    session: Session,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum PwChangeStartError {
    IncorrectPassword,
    Code(i32),
}

pub fn run(args: &[String]) -> i32 {
    finish_run_result(run_inner(args), &mut io::stderr().lock())
}

fn run_inner(args: &[String]) -> Result<i32, String> {
    let client = HttpClient::from_env().map_err(display_to_string)?;
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    run_inner_with(
        args,
        &client,
        load_command_state,
        prompt_for_password,
        fetch_iterations_with_client,
        pwchange_start_with_client,
        pwchange_complete_with_client,
        kill_session_for_passwd,
        &mut stdout,
        &mut stderr,
    )
}

fn run_inner_with<W: Write, E: Write, L, P, F, S, C, K>(
    _args: &[String],
    client: &HttpClient,
    load_state: L,
    mut prompt: P,
    mut fetch_iterations: F,
    mut start: S,
    mut complete: C,
    mut kill: K,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<i32, String>
where
    L: Fn() -> Result<CommandState, String>,
    P: FnMut(&str, Option<&str>, &str) -> Result<String, String>,
    F: FnMut(&HttpClient, &str) -> Result<u32, String>,
    S: FnMut(&HttpClient, &Session, &str, &str) -> Result<PwChangeInfo, PwChangeStartError>,
    C: FnMut(
        &HttpClient,
        &Session,
        &str,
        &str,
        &str,
        &str,
        u32,
        &PwChangeInfo,
    ) -> Result<(), String>,
    K: FnMut() -> Result<(), String>,
{
    let state = load_state()?;
    let iterations = fetch_iterations(client, &state.username)?;
    if iterations == 0 {
        return Err(
            "Unable to fetch iteration count. Check your internet connection and be sure your username is valid.".to_string(),
        );
    }

    let mut current_password = prompt(
        "Current Master Password",
        None,
        &format!(
            "Please enter the current LastPass master password for <{}>.",
            state.username
        ),
    )?;
    let current_hash =
        kdf_login_key(&state.username, &current_password, iterations).map_err(display_to_string)?;
    current_password.zeroize();

    let mut new_password = prompt(
        "New Master Password",
        None,
        &format!(
            "Please enter the new LastPass master password for <{}>.",
            state.username
        ),
    )?;
    let mut confirmation = prompt(
        "Confirm New Master Password",
        None,
        &format!(
            "Please retype the new LastPass master password for <{}>.",
            state.username
        ),
    )?;

    if new_password != confirmation {
        confirmation.zeroize();
        new_password.zeroize();
        return Err("Bad password: passwords don't match.".to_string());
    }
    confirmation.zeroize();

    if new_password.len() < 8 {
        new_password.zeroize();
        return Err("Bad password: too short.".to_string());
    }

    let new_key = kdf_decryption_key(&state.username, &new_password, iterations)
        .map_err(display_to_string)?;
    let new_hash =
        kdf_login_key(&state.username, &new_password, iterations).map_err(display_to_string)?;
    new_password.zeroize();

    write_stdout_line(stdout, &format!("{FG_CYAN}Fetching data...{RESET}"))?;
    let mut info = match start(client, &state.session, &state.username, &current_hash) {
        Ok(info) => info,
        Err(PwChangeStartError::IncorrectPassword) => {
            return Err("Incorrect password.  Password not changed.".to_string());
        }
        Err(PwChangeStartError::Code(code)) => {
            return Err(format!("Error changing password (error={code})"));
        }
    };

    reencrypt_with_writer(
        &state.session,
        &mut info,
        &state.current_key,
        &new_key,
        stderr,
    )?;

    write_stdout_line(stdout, &format!("{FG_CYAN}Uploading...{RESET}"))?;
    let encrypted_username = encrypt_and_base64(state.username.as_bytes(), &new_key)?;
    complete(
        client,
        &state.session,
        &state.username,
        &encrypted_username,
        &current_hash,
        &new_hash,
        iterations,
        &info,
    )?;

    kill()?;
    write_stdout_line(
        stdout,
        &format!("{FG_GREEN}{BOLD}Success{RESET}: Password changed and logged out."),
    )?;
    Ok(0)
}

fn load_command_state() -> Result<CommandState, String> {
    let _ = load_blob(SyncMode::Now).map_err(display_to_string)?;

    let key = agent_get_decryption_key()
        .map_err(map_decryption_key_error)
        .map_err(display_to_string)?;
    let mut session = session_load(&key)
        .map_err(display_to_string)?
        .ok_or_else(|| {
            "Could not find session. Perhaps you need to login with `lpass login`.".to_string()
        })?;

    if session.private_key.is_none()
        && let Some(private_key_enc) = session.private_key_enc.as_deref()
    {
        session.private_key =
            Some(decrypt_private_key(private_key_enc, &key).map_err(display_to_string)?);
    }

    let username = config_read_string("username")
        .map_err(display_to_string)?
        .ok_or_else(|| {
            "Could not find session. Perhaps you need to login with `lpass login`.".to_string()
        })?;

    Ok(CommandState {
        username,
        current_key: key,
        session,
    })
}

fn fetch_iterations_with_client(client: &HttpClient, username: &str) -> Result<u32, String> {
    let user_lower = username.to_ascii_lowercase();
    let response = client
        .post_lastpass(None, "iterations.php", None, &[("email", &user_lower)])
        .map_err(display_to_string)?;
    response
        .body
        .trim()
        .parse::<u32>()
        .map_err(|_| "Unable to fetch iteration count. Check your internet connection and be sure your username is valid.".to_string())
}

fn prompt_for_password(
    prompt: &str,
    error: Option<&str>,
    description: &str,
) -> Result<String, String> {
    prompt_password_with_description(prompt, error, description).map_err(display_to_string)
}

fn pwchange_start_with_client(
    client: &HttpClient,
    session: &Session,
    username: &str,
    current_hash: &str,
) -> Result<PwChangeInfo, PwChangeStartError> {
    let response = client
        .post_lastpass(
            None,
            "lastpass/api.php",
            Some(session),
            &[
                ("cmd", "getacctschangepw"),
                ("username", username),
                ("hash", current_hash),
                ("changepw", "1"),
                ("changepw2", "1"),
                ("includersaprivatekeyenc", "1"),
                ("changeun", ""),
                ("resetrsakeys", "0"),
                ("includeendmarker", "1"),
            ],
        )
        .map_err(|_| PwChangeStartError::Code(-2))?;
    match parse_pwchange(&response.body) {
        Ok(info) => Ok(info),
        Err(PwChangeParseError::IncorrectPassword) => Err(PwChangeStartError::IncorrectPassword),
        Err(PwChangeParseError::Invalid) => Err(PwChangeStartError::Code(-22)),
    }
}

fn pwchange_complete_with_client(
    client: &HttpClient,
    session: &Session,
    username: &str,
    encrypted_username: &str,
    current_hash: &str,
    new_hash: &str,
    iterations: u32,
    info: &PwChangeInfo,
) -> Result<(), String> {
    let params = build_pwchange_complete_params(
        username,
        encrypted_username,
        current_hash,
        new_hash,
        iterations,
        info,
    );
    let borrowed = borrow_params(&params);
    let response = client
        .post_lastpass(None, "lastpass/api.php", Some(session), &borrowed)
        .map_err(display_to_string)?;
    if response.body.contains("pwchangeok") {
        Ok(())
    } else {
        Err("Password change failed.".to_string())
    }
}

fn build_pwchange_complete_params(
    username: &str,
    encrypted_username: &str,
    current_hash: &str,
    new_hash: &str,
    iterations: u32,
    info: &PwChangeInfo,
) -> Vec<(String, String)> {
    let mut reencrypt = String::new();
    reencrypt.push_str(&info.reencrypt_id);
    reencrypt.push('\n');
    for field in &info.fields {
        reencrypt.push_str(&field.old_ctext);
        reencrypt.push(':');
        reencrypt.push_str(&field.new_ctext);
        reencrypt.push('\n');
    }

    let mut params = vec![
        ("cmd".to_string(), "updatepassword".to_string()),
        ("pwupdate".to_string(), "1".to_string()),
        ("email".to_string(), username.to_string()),
        ("token".to_string(), info.token.clone()),
        ("reencrypt".to_string(), reencrypt),
        (
            "newprivatekeyenc".to_string(),
            info.new_privkey_encrypted.clone(),
        ),
        ("newuserkeyhexhash".to_string(), info.new_key_hash.clone()),
        (
            "newprivatekeyenchexhash".to_string(),
            info.new_privkey_hash.clone(),
        ),
        ("newpasswordhash".to_string(), new_hash.to_string()),
        ("key_iterations".to_string(), iterations.to_string()),
        (
            "encrypted_username".to_string(),
            encrypted_username.to_string(),
        ),
        ("origusername".to_string(), username.to_string()),
        ("wxhash".to_string(), current_hash.to_string()),
    ];

    for (idx, su_key) in info.su_keys.iter().enumerate() {
        params.push((format!("suuid{idx}"), su_key.uid.clone()));
        params.push((format!("sukey{idx}"), su_key.new_enc_key.clone()));
    }
    params.push(("sukeycnt".to_string(), info.su_keys.len().to_string()));

    params
}

fn borrow_params(params: &[(String, String)]) -> Vec<(&str, &str)> {
    params
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
}

fn reencrypt_with_writer<W: Write>(
    session: &Session,
    info: &mut PwChangeInfo,
    current_key: &[u8; KDF_HASH_LEN],
    new_key: &[u8; KDF_HASH_LEN],
    writer: &mut W,
) -> Result<(), String> {
    let session_private_key = session.private_key.as_deref().ok_or_else(|| {
        "Server and session private key don't match! Try lpass sync first.".to_string()
    })?;
    let server_private_key =
        decrypt_private_key(&info.privkey_encrypted, current_key).map_err(|_| {
            "Server and session private key don't match! Try lpass sync first.".to_string()
        })?;
    if server_private_key != session_private_key {
        return Err(
            "Server and session private key don't match! Try lpass sync first.".to_string(),
        );
    }

    let total = info.fields.len() + info.su_keys.len() + 1;
    let mut index = 0usize;
    show_status_bar(writer, "Re-encrypting", index, total)?;
    index += 1;

    info.new_privkey_encrypted =
        encrypt_private_key(&server_private_key, new_key).map_err(display_to_string)?;

    let mut required = 0usize;
    let mut errors = 0usize;
    for field in &mut info.fields {
        show_status_bar(writer, "Re-encrypting", index, total)?;
        index += 1;
        if !field.optional {
            required += 1;
        }

        let plaintext = match aes_decrypt_base64_lastpass(&field.old_ctext, current_key) {
            Ok(bytes) => bytes,
            Err(_) => {
                if !field.optional {
                    errors += 1;
                }
                b" ".to_vec()
            }
        };
        field.new_ctext = encrypt_and_base64(&plaintext, new_key)?;
    }

    if errors > required / 10 {
        return Err("Too many decryption failures.".to_string());
    }

    for su_key in &mut info.su_keys {
        show_status_bar(writer, "Re-encrypting", index, total)?;
        index += 1;
        let encrypted =
            rsa_encrypt_oaep(&su_key.sharing_key, new_key).map_err(display_to_string)?;
        su_key.new_enc_key = hex::encode(encrypted);
    }

    show_status_bar(writer, "Re-encrypting", total, total)?;
    writer.write_all(b"\n").map_err(display_to_string)?;
    writer.flush().map_err(display_to_string)?;

    info.new_privkey_hash = sha256_hex(info.new_privkey_encrypted.as_bytes());
    info.new_key_hash = sha256_hex(new_key);
    Ok(())
}

fn show_status_bar<W: Write>(
    writer: &mut W,
    operation: &str,
    current: usize,
    max: usize,
) -> Result<(), String> {
    let max = max.max(1);
    let current = current.min(max);
    let filled = current * 40 / max;
    let progress = format!("{:<40}", "=".repeat(filled));
    let line = format!(
        "{FG_CYAN}{operation} {RESET}{FG_BLUE}[{progress}] {RESET}{FG_CYAN}{current}/{max}     \r{RESET}"
    );
    writer
        .write_all(terminal::render_stderr(&line).as_bytes())
        .map_err(display_to_string)?;
    writer.flush().map_err(display_to_string)
}

fn encrypt_and_base64(bytes: &[u8], key: &[u8; KDF_HASH_LEN]) -> Result<String, String> {
    let encrypted = aes_encrypt_lastpass(bytes, key).map_err(display_to_string)?;
    Ok(base64_lastpass_encode(&encrypted))
}

fn kill_session_for_passwd() -> Result<(), String> {
    session_kill().map_err(display_to_string)
}

fn map_decryption_key_error(err: crate::error::LpassError) -> crate::error::LpassError {
    match err {
        crate::error::LpassError::Crypto("missing iterations")
        | crate::error::LpassError::Crypto("missing username")
        | crate::error::LpassError::Crypto("missing verify") => crate::error::LpassError::User(
            "Could not find decryption key. Perhaps you need to login with `lpass login`.",
        ),
        other => other,
    }
}

fn display_to_string<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

fn write_stdout_line<W: Write>(writer: &mut W, line: &str) -> Result<(), String> {
    writer
        .write_all(terminal::render_stdout(line).as_bytes())
        .map_err(display_to_string)?;
    writer.write_all(b"\n").map_err(display_to_string)?;
    writer.flush().map_err(display_to_string)
}

fn finish_run_result<E: Write>(result: Result<i32, String>, stderr: &mut E) -> i32 {
    match result {
        Ok(code) => code,
        Err(err) => {
            let _ = writeln!(stderr, "error: {err}");
            1
        }
    }
}

#[cfg(test)]
#[path = "passwd_tests.rs"]
mod tests;
