#![forbid(unsafe_code)]

use std::io::{self, Write};

use super::data::SyncMode;
use crate::agent::agent_get_decryption_key;
use crate::commands::data::load_blob;
use crate::config::config_read_string;
use crate::crypto::{
    aes_decrypt_base64_lastpass, aes_encrypt_lastpass, base64_lastpass_encode,
    decrypt_private_key, encrypt_private_key, rsa_encrypt_oaep, sha256_hex,
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
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
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
    let current_hash = kdf_login_key(&state.username, &current_password, iterations)
        .map_err(display_to_string)?;
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

    let new_key =
        kdf_decryption_key(&state.username, &new_password, iterations).map_err(display_to_string)?;
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
        &format!(
            "{FG_GREEN}{BOLD}Success{RESET}: Password changed and logged out."
        ),
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
        .ok_or_else(|| "Could not find session. Perhaps you need to login with `lpass login`.".to_string())?;

    if session.private_key.is_none()
        && let Some(private_key_enc) = session.private_key_enc.as_deref()
    {
        session.private_key = Some(decrypt_private_key(private_key_enc, &key).map_err(display_to_string)?);
    }

    let username = config_read_string("username")
        .map_err(display_to_string)?
        .ok_or_else(|| "Could not find session. Perhaps you need to login with `lpass login`.".to_string())?;

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
        (
            "newuserkeyhexhash".to_string(),
            info.new_key_hash.clone(),
        ),
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
    let session_private_key = session
        .private_key
        .as_deref()
        .ok_or_else(|| "Server and session private key don't match! Try lpass sync first.".to_string())?;
    let server_private_key = decrypt_private_key(&info.privkey_encrypted, current_key)
        .map_err(|_| "Server and session private key don't match! Try lpass sync first.".to_string())?;
    if server_private_key != session_private_key {
        return Err("Server and session private key don't match! Try lpass sync first.".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_private_key;
    use crate::http::HttpClient;

    fn sample_session(private_key: &[u8]) -> Session {
        Session {
            uid: "u1".to_string(),
            session_id: "s1".to_string(),
            token: "t1".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: Some(private_key.to_vec()),
            private_key_enc: None,
        }
    }

    fn sample_info(
        current_key: &[u8; KDF_HASH_LEN],
        private_key: &[u8],
        fields: &[(&str, bool)],
    ) -> PwChangeInfo {
        let mut info = PwChangeInfo {
            reencrypt_id: "rid".to_string(),
            token: "tok".to_string(),
            privkey_encrypted: encrypt_private_key(private_key, current_key).expect("private key"),
            new_privkey_encrypted: String::new(),
            new_privkey_hash: String::new(),
            new_key_hash: String::new(),
            fields: Vec::new(),
            su_keys: Vec::new(),
        };
        for (value, optional) in fields {
            info.fields.push(crate::xml::PwChangeField {
                old_ctext: encrypt_and_base64(value.as_bytes(), current_key).expect("field"),
                new_ctext: String::new(),
                optional: *optional,
            });
        }
        info
    }

    #[test]
    fn fetch_iterations_uses_mock_transport() {
        let client = HttpClient::mock();
        let iterations =
            fetch_iterations_with_client(&client, "user@example.com").expect("iterations");
        assert_eq!(iterations, 1000);
    }

    #[test]
    fn fetch_iterations_rejects_invalid_response() {
        let client = HttpClient::mock_with_overrides(&[("iterations.php", 200, "invalid")]);
        let err =
            fetch_iterations_with_client(&client, "user@example.com").expect_err("must fail");
        assert!(err.contains("Unable to fetch iteration count"));
    }

    #[test]
    fn pwchange_start_uses_mock_transport() {
        let client = HttpClient::mock();
        let session = Session {
            uid: "u1".to_string(),
            session_id: "s1".to_string(),
            token: "t1".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let info =
            pwchange_start_with_client(&client, &session, "user@example.com", &hash).expect("ok");
        assert_eq!(info.reencrypt_id, "mock-reencrypt-id");
        assert_eq!(info.token, "mock-pwchange-token");
        assert_eq!(info.fields.len(), 2);
    }

    #[test]
    fn pwchange_start_reports_incorrect_password() {
        let client = HttpClient::mock();
        let session = Session::default();
        let err =
            pwchange_start_with_client(&client, &session, "user@example.com", "bad").expect_err("bad");
        assert_eq!(err, PwChangeStartError::IncorrectPassword);
    }

    #[test]
    fn pwchange_start_maps_invalid_xml_to_einval() {
        let client = HttpClient::mock_with_overrides(&[("lastpass/api.php", 200, "<lastpass rc=\"OK\"/>")]);
        let err = pwchange_start_with_client(&client, &Session::default(), "user@example.com", "bad")
            .expect_err("invalid");
        assert_eq!(err, PwChangeStartError::Code(-22));
    }

    #[test]
    fn pwchange_complete_uses_mock_transport() {
        let client = HttpClient::mock();
        let mut info = PwChangeInfo {
            reencrypt_id: "mock-reencrypt-id".to_string(),
            token: "mock-pwchange-token".to_string(),
            privkey_encrypted: "old".to_string(),
            new_privkey_encrypted: "new".to_string(),
            new_privkey_hash: "hash1".to_string(),
            new_key_hash: "hash2".to_string(),
            fields: vec![crate::xml::PwChangeField {
                old_ctext: "old-ctext".to_string(),
                new_ctext: "new-ctext".to_string(),
                optional: false,
            }],
            su_keys: Vec::new(),
        };
        let result = pwchange_complete_with_client(
            &client,
            &Session::default(),
            "user@example.com",
            "enc-user",
            "old-hash",
            "new-hash",
            1000,
            &info,
        );
        assert!(result.is_ok());

        info.token.clear();
        let err = pwchange_complete_with_client(
            &client,
            &Session::default(),
            "user@example.com",
            "enc-user",
            "old-hash",
            "new-hash",
            1000,
            &info,
        )
        .expect_err("missing token");
        assert_eq!(err, "Password change failed.");
    }

    #[test]
    fn build_pwchange_complete_params_includes_su_keys() {
        let info = PwChangeInfo {
            reencrypt_id: "rid".to_string(),
            token: "tok".to_string(),
            privkey_encrypted: String::new(),
            new_privkey_encrypted: "priv".to_string(),
            new_privkey_hash: "ph".to_string(),
            new_key_hash: "kh".to_string(),
            fields: vec![crate::xml::PwChangeField {
                old_ctext: "old".to_string(),
                new_ctext: "new".to_string(),
                optional: false,
            }],
            su_keys: vec![crate::xml::PwChangeSuKey {
                uid: "7".to_string(),
                sharing_key: vec![1, 2],
                new_enc_key: "enc".to_string(),
            }],
        };
        let params =
            build_pwchange_complete_params("user", "enc-user", "old-hash", "new-hash", 2, &info);
        let map: std::collections::HashMap<_, _> = params.into_iter().collect();
        assert_eq!(map.get("cmd").map(String::as_str), Some("updatepassword"));
        assert_eq!(map.get("reencrypt").map(String::as_str), Some("rid\nold:new\n"));
        assert_eq!(map.get("suuid0").map(String::as_str), Some("7"));
        assert_eq!(map.get("sukey0").map(String::as_str), Some("enc"));
        assert_eq!(map.get("sukeycnt").map(String::as_str), Some("1"));
    }

    #[test]
    fn reencrypt_updates_fields_hashes_and_progress_output() {
        let current_key = [3u8; KDF_HASH_LEN];
        let new_key = [4u8; KDF_HASH_LEN];
        let private_key = b"server-private-key";
        let session = sample_session(private_key);
        let mut info = sample_info(&current_key, private_key, &[("alpha", false), ("beta", true)]);
        let mut stderr = Vec::new();

        reencrypt_with_writer(&session, &mut info, &current_key, &new_key, &mut stderr)
            .expect("reencrypt");

        assert!(!info.new_privkey_encrypted.is_empty());
        assert_eq!(info.new_privkey_hash, sha256_hex(info.new_privkey_encrypted.as_bytes()));
        assert_eq!(info.new_key_hash, sha256_hex(&new_key));
        assert_eq!(stderr.iter().filter(|byte| **byte == b'\r').count(), 4);

        let first =
            String::from_utf8(aes_decrypt_base64_lastpass(&info.fields[0].new_ctext, &new_key).expect("field"))
                .expect("utf8");
        assert_eq!(first, "alpha");
    }

    #[test]
    fn reencrypt_rejects_private_key_mismatch() {
        let current_key = [5u8; KDF_HASH_LEN];
        let new_key = [6u8; KDF_HASH_LEN];
        let session = sample_session(b"local-private-key");
        let mut info = sample_info(&current_key, b"server-private-key", &[("alpha", false)]);
        let err = reencrypt_with_writer(&session, &mut info, &current_key, &new_key, &mut Vec::new())
            .expect_err("mismatch");
        assert_eq!(err, "Server and session private key don't match! Try lpass sync first.");
    }

    #[test]
    fn reencrypt_rejects_too_many_required_failures() {
        let current_key = [7u8; KDF_HASH_LEN];
        let new_key = [8u8; KDF_HASH_LEN];
        let private_key = b"server-private-key";
        let session = sample_session(private_key);
        let mut info = sample_info(&current_key, private_key, &[]);
        info.fields = vec![crate::xml::PwChangeField {
            old_ctext: "bad".to_string(),
            new_ctext: String::new(),
            optional: false,
        }];
        let err = reencrypt_with_writer(&session, &mut info, &current_key, &new_key, &mut Vec::new())
            .expect_err("must fail");
        assert_eq!(err, "Too many decryption failures.");
    }

    #[test]
    fn reencrypt_allows_optional_decryption_failures() {
        let current_key = [9u8; KDF_HASH_LEN];
        let new_key = [10u8; KDF_HASH_LEN];
        let private_key = b"server-private-key";
        let session = sample_session(private_key);
        let mut info = sample_info(&current_key, private_key, &[]);
        info.fields = vec![crate::xml::PwChangeField {
            old_ctext: "bad".to_string(),
            new_ctext: String::new(),
            optional: true,
        }];
        reencrypt_with_writer(&session, &mut info, &current_key, &new_key, &mut Vec::new())
            .expect("optional failure");
        let value =
            String::from_utf8(aes_decrypt_base64_lastpass(&info.fields[0].new_ctext, &new_key).expect("field"))
                .expect("utf8");
        assert_eq!(value, " ");
    }

    #[test]
    fn show_status_bar_bounds_current_and_max() {
        let mut stderr = Vec::new();
        show_status_bar(&mut stderr, "Re-encrypting", 9, 0).expect("status");
        let text = String::from_utf8(stderr).expect("utf8");
        assert!(text.contains("1/1"));
    }

    #[test]
    fn run_inner_with_reports_mismatched_passwords() {
        let client = HttpClient::mock();
        let state = CommandState {
            username: "user@example.com".to_string(),
            current_key: [1u8; KDF_HASH_LEN],
            session: sample_session(b"private"),
        };
        let mut prompts = ["123456".to_string(), "abcdefgh".to_string(), "abcdefgi".to_string()]
            .into_iter();
        let err = run_inner_with(
            &[],
            &client,
            || Ok(state.clone()),
            |_, _, _| Ok(prompts.next().expect("prompt")),
            |_, _| Ok(1000),
            |_, _, _, _| unreachable!(),
            |_, _, _, _, _, _, _, _| unreachable!(),
            || Ok(()),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("must fail");
        assert_eq!(err, "Bad password: passwords don't match.");
    }

    #[test]
    fn run_inner_with_reports_short_passwords() {
        let client = HttpClient::mock();
        let state = CommandState {
            username: "user@example.com".to_string(),
            current_key: [1u8; KDF_HASH_LEN],
            session: sample_session(b"private"),
        };
        let mut prompts = ["123456".to_string(), "short".to_string(), "short".to_string()]
            .into_iter();
        let err = run_inner_with(
            &[],
            &client,
            || Ok(state.clone()),
            |_, _, _| Ok(prompts.next().expect("prompt")),
            |_, _| Ok(1000),
            |_, _, _, _| unreachable!(),
            |_, _, _, _, _, _, _, _| unreachable!(),
            || Ok(()),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("must fail");
        assert_eq!(err, "Bad password: too short.");
    }

    #[test]
    fn run_inner_with_reports_incorrect_current_password() {
        let client = HttpClient::mock();
        let state = CommandState {
            username: "user@example.com".to_string(),
            current_key: [1u8; KDF_HASH_LEN],
            session: sample_session(b"private"),
        };
        let mut prompts = ["123456".to_string(), "abcdefgh".to_string(), "abcdefgh".to_string()]
            .into_iter();
        let err = run_inner_with(
            &[],
            &client,
            || Ok(state.clone()),
            |_, _, _| Ok(prompts.next().expect("prompt")),
            |_, _| Ok(1000),
            |_, _, _, _| Err(PwChangeStartError::IncorrectPassword),
            |_, _, _, _, _, _, _, _| unreachable!(),
            || Ok(()),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("must fail");
        assert_eq!(err, "Incorrect password.  Password not changed.");
    }

    #[test]
    fn run_inner_with_reports_start_codes() {
        let client = HttpClient::mock();
        let state = CommandState {
            username: "user@example.com".to_string(),
            current_key: [1u8; KDF_HASH_LEN],
            session: sample_session(b"private"),
        };
        let mut prompts = ["123456".to_string(), "abcdefgh".to_string(), "abcdefgh".to_string()]
            .into_iter();
        let err = run_inner_with(
            &[],
            &client,
            || Ok(state.clone()),
            |_, _, _| Ok(prompts.next().expect("prompt")),
            |_, _| Ok(1000),
            |_, _, _, _| Err(PwChangeStartError::Code(-22)),
            |_, _, _, _, _, _, _, _| unreachable!(),
            || Ok(()),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("must fail");
        assert_eq!(err, "Error changing password (error=-22)");
    }

    #[test]
    fn run_inner_with_success_path_writes_messages_and_kills_session() {
        let client = HttpClient::mock();
        let current_key = [11u8; KDF_HASH_LEN];
        let new_key = kdf_decryption_key("user@example.com", "abcdefgh", 1000).expect("new key");
        let private_key = b"private";
        let state = CommandState {
            username: "user@example.com".to_string(),
            current_key,
            session: sample_session(private_key),
        };
        let mut prompts = ["123456".to_string(), "abcdefgh".to_string(), "abcdefgh".to_string()]
            .into_iter();
        let mut killed = false;
        let mut info = sample_info(&current_key, private_key, &[("alpha", false)]);
        reencrypt_with_writer(&state.session, &mut info, &current_key, &new_key, &mut Vec::new())
            .expect("reencrypt");

        let mut stdout = Vec::new();
        let code = run_inner_with(
            &[],
            &client,
            || Ok(state.clone()),
            |_, _, _| Ok(prompts.next().expect("prompt")),
            |_, _| Ok(1000),
            move |_, _, _, _| Ok(info.clone()),
            |_, _, _, _, _, _, _, _| Ok(()),
            || {
                killed = true;
                Ok(())
            },
            &mut stdout,
            &mut Vec::new(),
        )
        .expect("success");

        assert_eq!(code, 0);
        assert!(killed);
        let output = String::from_utf8(stdout).expect("utf8");
        assert!(output.contains("Fetching data..."));
        assert!(output.contains("Uploading..."));
        assert!(output.contains("Password changed and logged out."));
    }

    #[test]
    fn run_inner_with_propagates_complete_failure() {
        let client = HttpClient::mock();
        let state = CommandState {
            username: "user@example.com".to_string(),
            current_key: [1u8; KDF_HASH_LEN],
            session: sample_session(b"private"),
        };
        let mut prompts = ["123456".to_string(), "abcdefgh".to_string(), "abcdefgh".to_string()]
            .into_iter();
        let info = sample_info(&state.current_key, b"private", &[("alpha", false)]);
        let err = run_inner_with(
            &[],
            &client,
            || Ok(state.clone()),
            |_, _, _| Ok(prompts.next().expect("prompt")),
            |_, _| Ok(1000),
            move |_, _, _, _| Ok(info.clone()),
            |_, _, _, _, _, _, _, _| Err("Password change failed.".to_string()),
            || Ok(()),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect_err("must fail");
        assert_eq!(err, "Password change failed.");
    }
}
