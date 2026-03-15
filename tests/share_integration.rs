use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use lpass_core::blob::{Account, Blob, Share};
use lpass_core::config::{ConfigEnv, ConfigStore};
use lpass_core::kdf::KDF_HASH_LEN;
use lpass_core::session::{Session, session_save_with_store};
use tempfile::TempDir;

fn unique_test_home() -> (TempDir, PathBuf) {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().to_path_buf();
    (temp, path)
}

fn store_for(home: &Path) -> ConfigStore {
    ConfigStore::with_env(ConfigEnv {
        lpass_home: Some(home.to_path_buf()),
        ..ConfigEnv::default()
    })
}

fn write_mock_blob(home: &Path, blob: &Blob) {
    let store = store_for(home);
    let json = serde_json::to_vec(blob).expect("blob json");
    store.write_buffer("blob", &json).expect("blob write");
}

fn write_key_and_session(home: &Path, key: &[u8; KDF_HASH_LEN]) {
    let store = store_for(home);
    store
        .write_buffer("plaintext_key", key)
        .expect("plaintext key");
    store
        .write_encrypted_string("verify", "`lpass` was written by LastPass.\n", key)
        .expect("verify");
    session_save_with_store(
        &store,
        &Session {
            uid: "57747756".to_string(),
            session_id: "sess".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        },
        key,
    )
    .expect("session save");
}

fn shared_account(
    id: &str,
    name: &str,
    fullname: &str,
    share_name: &str,
    share_id: &str,
) -> Account {
    Account {
        id: id.to_string(),
        share_name: Some(share_name.to_string()),
        share_id: Some(share_id.to_string()),
        share_readonly: false,
        name: name.to_string(),
        name_encrypted: None,
        group: "apps".to_string(),
        group_encrypted: None,
        fullname: fullname.to_string(),
        url: String::new(),
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
    }
}

fn share_blob() -> Blob {
    Blob {
        version: 1,
        local_version: false,
        shares: vec![Share {
            id: "77".to_string(),
            name: "Team".to_string(),
            readonly: false,
            key: Some([7u8; KDF_HASH_LEN]),
        }],
        accounts: vec![
            shared_account("100", "alpha", "Team/alpha", "Team", "77"),
            shared_account("200", "beta", "Team/beta", "Team", "77"),
        ],
        attachments: Vec::new(),
    }
}

fn run_lpass(home: &Path, args: &[&str], stdin: Option<&str>) -> std::process::Output {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut command = Command::new(exe);
    command
        .env("LPASS_HOME", home)
        .env("LPASS_HTTP_MOCK", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args(args);

    if let Some(stdin_value) = stdin {
        command.stdin(Stdio::piped());
        let mut child = command.spawn().expect("spawn lpass");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(stdin_value.as_bytes())
            .expect("stdin write");
        child.wait_with_output().expect("wait output")
    } else {
        command.output().expect("run lpass")
    }
}

#[test]
fn share_without_subcommand_prints_help() {
    let (_temp, home) = unique_test_home();
    let output = run_lpass(&home, &["share"], None);
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"));
    assert!(stderr.contains("share userls SHARE"));
}

#[test]
fn share_library_dispatch_covers_help_path() {
    let code = lpass_core::commands::run("share", &[]);
    assert_eq!(code, 1);
}

#[test]
fn share_library_dispatch_covers_subcommand_usage_path() {
    let code = lpass_core::commands::run("share", &[String::from("userls")]);
    assert_eq!(code, 1);
}

#[test]
fn share_userls_renders_users_and_groups() {
    let (_temp, home) = unique_test_home();
    write_key_and_session(&home, &[7u8; KDF_HASH_LEN]);
    write_mock_blob(&home, &share_blob());

    let output = run_lpass(&home, &["share", "userls", "Team"], None);
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("User"));
    assert!(stdout.contains("Test User <user@example.com>"));
    assert!(stdout.contains("Group"));
    assert!(stdout.contains("group-team"));
}

#[test]
fn share_create_and_useradd_succeed_in_mock_mode() {
    let (_temp, home) = unique_test_home();
    write_key_and_session(&home, &[7u8; KDF_HASH_LEN]);
    write_mock_blob(&home, &share_blob());

    let create = run_lpass(&home, &["share", "create", "Shared-Team"], None);
    assert_eq!(create.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&create.stdout);
    assert!(stdout.contains("Folder Shared-Team created."));

    let useradd = run_lpass(
        &home,
        &[
            "share",
            "useradd",
            "--read-only=false",
            "Team",
            "group-team",
        ],
        None,
    );
    assert_eq!(useradd.status.code().unwrap_or(-1), 0);
}

#[test]
fn share_limit_supports_display_and_confirmation_flow() {
    let (_temp, home) = unique_test_home();
    write_key_and_session(&home, &[7u8; KDF_HASH_LEN]);
    write_mock_blob(&home, &share_blob());

    let show = run_lpass(&home, &["share", "limit", "Team", "user@example.com"], None);
    assert_eq!(show.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&show.stdout);
    assert!(stdout.contains("Site"));
    assert!(stdout.contains("alpha [id: 100]"));

    let update = run_lpass(
        &home,
        &[
            "share",
            "limit",
            "--allow",
            "--add",
            "Team",
            "user@example.com",
            "Team/beta",
        ],
        Some("y\n"),
    );
    assert_eq!(update.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&update.stdout);
    assert!(stdout.contains("beta [id: 200]"));
}

#[test]
fn share_reports_missing_user_and_share_errors() {
    let (_temp, home) = unique_test_home();
    write_key_and_session(&home, &[7u8; KDF_HASH_LEN]);
    write_mock_blob(&home, &share_blob());

    let missing_user = run_lpass(
        &home,
        &["share", "userdel", "Team", "missing@example.com"],
        None,
    );
    assert_eq!(missing_user.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&missing_user.stderr);
    assert!(stderr.contains("Unable to find user"));

    let missing_share = run_lpass(&home, &["share", "rm", "Missing"], None);
    assert_eq!(missing_share.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&missing_share.stderr);
    assert!(stderr.contains("Share Missing not found."));
}
