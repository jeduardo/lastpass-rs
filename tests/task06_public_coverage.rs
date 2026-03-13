#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use aes::Aes256;
use cbc::Encryptor as Aes256CbcEncryptor;
use cipher::block_padding::Pkcs7;
use cipher::{BlockEncryptMut, KeyInit, KeyIvInit};
use ecb::Encryptor as Aes256EcbEncryptor;
use lpass_core::crypto::{
    aes_decrypt_lastpass, decrypt_private_key, rsa_decrypt_oaep, rsa_encrypt_oaep,
};
use lpass_core::xml::{parse_lastpass_api_ok, parse_ok_session};
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePublicKey;
use tempfile::TempDir;

const LP_PKEY_PREFIX: &str = "LastPassPrivateKey<";
const LP_PKEY_SUFFIX: &str = ">LastPassPrivateKey";

fn run_lpass(home: &Path, askpass: &Path, args: &[&str]) -> Output {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut command = Command::new(exe);
    command.env("LPASS_HOME", home);
    command.env("LPASS_HTTP_MOCK", "1");
    command.env("LPASS_ASKPASS", askpass);
    command.args(args);
    command.output().expect("run lpass")
}

#[cfg(unix)]
fn write_askpass_script(home: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let askpass = home.join(name);
    fs::write(&askpass, body).expect("write askpass");
    fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).expect("chmod askpass");
    askpass
}

fn encrypt_legacy_private_key_payload(payload: &str, key: &[u8; 32]) -> String {
    let mut buffer = payload.as_bytes().to_vec();
    let msg_len = buffer.len();
    buffer.resize(msg_len + 16, 0);
    let ciphertext = Aes256CbcEncryptor::<Aes256>::new(key.into(), (&key[..16]).into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, msg_len)
        .expect("encrypt legacy private key")
        .to_vec();
    hex::encode(ciphertext)
}

#[test]
fn crypto_public_api_covers_task06_paths() {
    let key = [19u8; 32];
    let plaintext = b"legacy ecb payload";
    let mut buffer = plaintext.to_vec();
    let msg_len = buffer.len();
    buffer.resize(msg_len + 16, 0);
    let ciphertext = Aes256EcbEncryptor::<Aes256>::new((&key).into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, msg_len)
        .expect("encrypt legacy ecb")
        .to_vec();
    let decrypted = aes_decrypt_lastpass(&ciphertext, &key).expect("decrypt legacy ecb");
    assert_eq!(decrypted, plaintext);

    let payload = format!(
        "{LP_PKEY_PREFIX}{}{LP_PKEY_SUFFIX}",
        hex::encode([0x30u8, 0x82, 0x01])
    );
    let decrypted = decrypt_private_key(&encrypt_legacy_private_key_payload(&payload, &key), &key)
        .expect("decrypt legacy private key");
    assert_eq!(decrypted, vec![0x30, 0x82, 0x01]);

    let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("private key");
    let public_der = private_key
        .to_public_key()
        .to_public_key_der()
        .expect("public der");
    let ciphertext = rsa_encrypt_oaep(public_der.as_ref(), b"shared-folder-key").expect("encrypt");
    let private_der = private_key.to_pkcs1_der().expect("private der");
    let decrypted = rsa_decrypt_oaep(private_der.as_bytes(), &ciphertext).expect("decrypt");
    assert_eq!(decrypted, b"shared-folder-key");
}

#[test]
fn xml_public_api_covers_task06_paths() {
    let session = parse_ok_session(
        "<response><ok uid=\"1\" sessionid=\"2\" token=\"3\" url_encryption=\"1\" url_logging=\"0\" privatekeyenc=\"enc\"/></response>",
    )
    .expect("session");
    assert_eq!(session.uid, "1");
    assert_eq!(session.private_key_enc.as_deref(), Some("enc"));

    assert!(parse_ok_session("<response><error/></response>").is_none());
    assert_eq!(parse_lastpass_api_ok("<lastpass rc=\"OK\"/>"), Some(true));
    assert_eq!(
        parse_lastpass_api_ok("<lastpass rc=\"FAIL\"/>"),
        Some(false)
    );
    assert_eq!(parse_lastpass_api_ok("<broken"), None);
}

#[test]
#[cfg(unix)]
fn askpass_login_paths_cover_password_prompt_behavior() {
    let home = TempDir::new().expect("tempdir");
    let ok_askpass = write_askpass_script(home.path(), "askpass-ok.sh", "#!/bin/sh\necho 123456\n");
    let ok = run_lpass(home.path(), &ok_askpass, &["login", "user@example.com"]);
    assert_eq!(
        ok.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    let fail_askpass = write_askpass_script(home.path(), "askpass-fail.sh", "#!/bin/sh\nexit 1\n");
    let fail = run_lpass(home.path(), &fail_askpass, &["login", "user@example.com"]);
    assert_eq!(fail.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&fail.stderr).contains("askpass failed"),
        "stderr: {}",
        String::from_utf8_lossy(&fail.stderr)
    );
}

#[test]
#[cfg(unix)]
fn passwd_cli_flow_runs_from_act_coverage_binary() {
    let home = TempDir::new().expect("tempdir");
    let login_askpass =
        write_askpass_script(home.path(), "askpass-login.sh", "#!/bin/sh\necho 123456\n");
    let login = run_lpass(home.path(), &login_askpass, &["login", "user@example.com"]);
    assert_eq!(
        login.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&login.stderr)
    );

    let passwd_askpass = write_askpass_script(
        home.path(),
        "askpass-passwd.sh",
        "#!/bin/sh\ncount_file=\"$(dirname \"$0\")/.askpass-passwd-count\"\ncount=0\nif [ -f \"$count_file\" ]; then\n  count=$(cat \"$count_file\")\nfi\ncount=$((count + 1))\necho \"$count\" > \"$count_file\"\nif [ \"$count\" -eq 1 ]; then\n  echo 123456\nelse\n  echo abcdefgh\nfi\n",
    );
    let passwd = run_lpass(home.path(), &passwd_askpass, &["passwd"]);
    assert_eq!(
        passwd.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&passwd.stderr)
    );

    let status = run_lpass(home.path(), &login_askpass, &["status", "--color=never"]);
    assert_eq!(status.status.code().unwrap_or(-1), 1);
    assert_eq!(
        String::from_utf8_lossy(&status.stdout).trim(),
        "Not logged in."
    );
}
