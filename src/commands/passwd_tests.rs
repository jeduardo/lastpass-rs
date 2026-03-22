use super::*;
use crate::config::{
    ConfigEnv, config_write_buffer, config_write_encrypted_string, config_write_string,
    set_test_env,
};
use crate::crypto::encrypt_private_key;
use crate::http::HttpClient;
use crate::session::session_save;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePublicKey;
use tempfile::TempDir;

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

fn ok_command_state() -> CommandState {
    CommandState {
        username: "user@example.com".to_string(),
        current_key: [1u8; KDF_HASH_LEN],
        session: sample_session(b"private"),
    }
}

#[test]
fn finish_run_result_writes_error_and_returns_one() {
    let mut stderr = Vec::new();
    let code = finish_run_result(Err("boom".to_string()), &mut stderr);
    assert_eq!(code, 1);
    let text = String::from_utf8(stderr).expect("utf8");
    assert!(text.contains("Error"), "stderr: {text:?}");
    assert!(text.contains("boom"), "stderr: {text:?}");
}

#[test]
fn fetch_iterations_uses_mock_transport() {
    let client = HttpClient::mock();
    let iterations = fetch_iterations_with_client(&client, "user@example.com").expect("iterations");
    assert_eq!(iterations, 1000);
}

#[test]
fn fetch_iterations_rejects_invalid_response() {
    let client = HttpClient::mock_with_overrides(&[("iterations.php", 200, "invalid")]);
    let err = fetch_iterations_with_client(&client, "user@example.com").expect_err("must fail");
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
    let client =
        HttpClient::mock_with_overrides(&[("lastpass/api.php", 200, "<lastpass rc=\"OK\"/>")]);
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
    assert_eq!(
        map.get("reencrypt").map(String::as_str),
        Some("rid\nold:new\n")
    );
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
    let mut info = sample_info(
        &current_key,
        private_key,
        &[("alpha", false), ("beta", true)],
    );
    let mut stderr = Vec::new();

    reencrypt_with_writer(&session, &mut info, &current_key, &new_key, &mut stderr)
        .expect("reencrypt");

    assert!(!info.new_privkey_encrypted.is_empty());
    assert_eq!(
        info.new_privkey_hash,
        sha256_hex(info.new_privkey_encrypted.as_bytes())
    );
    assert_eq!(info.new_key_hash, sha256_hex(&new_key));
    assert_eq!(stderr.iter().filter(|byte| **byte == b'\r').count(), 4);

    let first = String::from_utf8(
        aes_decrypt_base64_lastpass(&info.fields[0].new_ctext, &new_key).expect("field"),
    )
    .expect("utf8");
    assert_eq!(first, "alpha");
}

#[test]
fn reencrypt_updates_shared_user_keys() {
    let current_key = [21u8; KDF_HASH_LEN];
    let new_key = [22u8; KDF_HASH_LEN];
    let private_key = b"server-private-key";
    let session = sample_session(private_key);
    let mut info = sample_info(&current_key, private_key, &[("alpha", false)]);
    let rsa_private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa private key");
    let sharing_key = rsa_private_key
        .to_public_key()
        .to_public_key_der()
        .expect("public der");
    info.su_keys.push(crate::xml::PwChangeSuKey {
        uid: "42".to_string(),
        sharing_key: sharing_key.as_ref().to_vec(),
        new_enc_key: String::new(),
    });

    reencrypt_with_writer(&session, &mut info, &current_key, &new_key, &mut Vec::new())
        .expect("reencrypt");

    assert!(!info.su_keys[0].new_enc_key.is_empty());
}

#[test]
fn reencrypt_rejects_private_key_mismatch() {
    let current_key = [5u8; KDF_HASH_LEN];
    let new_key = [6u8; KDF_HASH_LEN];
    let session = sample_session(b"local-private-key");
    let mut info = sample_info(&current_key, b"server-private-key", &[("alpha", false)]);
    let err = reencrypt_with_writer(&session, &mut info, &current_key, &new_key, &mut Vec::new())
        .expect_err("mismatch");
    assert_eq!(
        err,
        "Server and session private key don't match! Try lpass sync first."
    );
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
    let value = String::from_utf8(
        aes_decrypt_base64_lastpass(&info.fields[0].new_ctext, &new_key).expect("field"),
    )
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
fn map_decryption_key_error_converts_missing_fields_to_user_error() {
    for message in ["missing iterations", "missing username", "missing verify"] {
        let mapped = map_decryption_key_error(crate::error::LpassError::Crypto(message));
        assert!(matches!(mapped, crate::error::LpassError::User(_)));
    }

    let other = map_decryption_key_error(crate::error::LpassError::Crypto("other"));
    assert!(matches!(other, crate::error::LpassError::Crypto("other")));
}

#[test]
fn display_to_string_uses_display_impl() {
    assert_eq!(display_to_string(std::io::Error::other("boom")), "boom");
}

#[test]
fn load_command_state_decrypts_private_key_from_session() {
    let _override_guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
    let temp = TempDir::new().expect("tempdir");
    let _config_guard = set_test_env(ConfigEnv {
        lpass_home: Some(temp.path().to_path_buf()),
        ..ConfigEnv::default()
    });

    let key = [31u8; KDF_HASH_LEN];
    let private_key = vec![0x30, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef];
    config_write_buffer("plaintext_key", &key).expect("write plaintext key");
    config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
        .expect("write verify");
    config_write_string("username", "user@example.com").expect("write username");

    let session = Session {
        uid: "u1".to_string(),
        session_id: "s1".to_string(),
        token: "t1".to_string(),
        url_encryption_enabled: false,
        url_logging_enabled: false,
        server: None,
        private_key: None,
        private_key_enc: Some(
            encrypt_private_key(&private_key, &key).expect("encrypt private key"),
        ),
    };
    session_save(&session, &key).expect("save session");

    let state = load_command_state().expect("load state");
    assert_eq!(state.username, "user@example.com");
    assert_eq!(state.current_key, key);
    assert_eq!(
        state.session.private_key.as_deref(),
        Some(private_key.as_slice())
    );
}

#[test]
fn run_inner_with_reports_zero_iterations() {
    let client = HttpClient::mock();
    let err = run_inner_with(
        &[],
        &client,
        || Ok(ok_command_state()),
        |_, _, _| Ok("unused".to_string()),
        |_, _| Ok(0),
        |_, _, _, _| Ok(PwChangeInfo::default()),
        |_, _, _, _, _, _, _, _| Ok(()),
        || Ok(()),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .expect_err("must fail");
    assert!(err.contains("Unable to fetch iteration count"));
}

#[test]
fn run_inner_with_reports_mismatched_passwords() {
    let client = HttpClient::mock();
    let state = ok_command_state();
    let mut prompts = [
        "123456".to_string(),
        "abcdefgh".to_string(),
        "abcdefgi".to_string(),
    ]
    .into_iter();
    let err = run_inner_with(
        &[],
        &client,
        || Ok(state.clone()),
        |_, _, _| Ok(prompts.next().expect("prompt")),
        |_, _| Ok(1000),
        |_, _, _, _| Ok(PwChangeInfo::default()),
        |_, _, _, _, _, _, _, _| Ok(()),
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
    let state = ok_command_state();
    let mut prompts = [
        "123456".to_string(),
        "short".to_string(),
        "short".to_string(),
    ]
    .into_iter();
    let err = run_inner_with(
        &[],
        &client,
        || Ok(state.clone()),
        |_, _, _| Ok(prompts.next().expect("prompt")),
        |_, _| Ok(1000),
        |_, _, _, _| Ok(PwChangeInfo::default()),
        |_, _, _, _, _, _, _, _| Ok(()),
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
    let state = ok_command_state();
    let mut prompts = [
        "123456".to_string(),
        "abcdefgh".to_string(),
        "abcdefgh".to_string(),
    ]
    .into_iter();
    let err = run_inner_with(
        &[],
        &client,
        || Ok(state.clone()),
        |_, _, _| Ok(prompts.next().expect("prompt")),
        |_, _| Ok(1000),
        |_, _, _, _| Err(PwChangeStartError::IncorrectPassword),
        |_, _, _, _, _, _, _, _| Ok(()),
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
    let state = ok_command_state();
    let mut prompts = [
        "123456".to_string(),
        "abcdefgh".to_string(),
        "abcdefgh".to_string(),
    ]
    .into_iter();
    let err = run_inner_with(
        &[],
        &client,
        || Ok(state.clone()),
        |_, _, _| Ok(prompts.next().expect("prompt")),
        |_, _| Ok(1000),
        |_, _, _, _| Err(PwChangeStartError::Code(-22)),
        |_, _, _, _, _, _, _, _| Ok(()),
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
    let mut prompts = [
        "123456".to_string(),
        "abcdefgh".to_string(),
        "abcdefgh".to_string(),
    ]
    .into_iter();
    let mut killed = false;
    let mut info = sample_info(&current_key, private_key, &[("alpha", false)]);
    reencrypt_with_writer(
        &state.session,
        &mut info,
        &current_key,
        &new_key,
        &mut Vec::new(),
    )
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
    let state = ok_command_state();
    let mut prompts = [
        "123456".to_string(),
        "abcdefgh".to_string(),
        "abcdefgh".to_string(),
    ]
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
