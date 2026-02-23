use std::path::{Path, PathBuf};
use std::process::Command;

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

fn account(id: &str, name: &str, group: &str) -> Account {
    let fullname = if group.is_empty() {
        name.to_string()
    } else {
        format!("{group}/{name}")
    };
    Account {
        id: id.to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name: name.to_string(),
        name_encrypted: None,
        group: group.to_string(),
        group_encrypted: None,
        fullname,
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

fn write_mock_blob(home: &Path, blob: &Blob) {
    let store = store_for(home);
    let json = serde_json::to_vec(blob).expect("blob json");
    store.write_buffer("blob", &json).expect("mock blob write");
}

fn write_key_and_verify(home: &Path, key: &[u8; KDF_HASH_LEN]) {
    let store = store_for(home);
    store
        .write_buffer("plaintext_key", key)
        .expect("plaintext key");
    store
        .write_encrypted_string("verify", "`lpass` was written by LastPass.\n", key)
        .expect("verify");
}

fn write_session_and_blob(home: &Path, key: &[u8; KDF_HASH_LEN]) {
    let store = store_for(home);
    write_key_and_verify(home, key);
    store.write_string("username", "tester").expect("username");

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
    session_save_with_store(&store, &session, key).expect("session save");

    let account = Account {
        id: "100".to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name: "entry".to_string(),
        name_encrypted: None,
        group: "team".to_string(),
        group_encrypted: None,
        fullname: "team/entry".to_string(),
        url: "https://example.com".to_string(),
        url_encrypted: None,
        username: "user".to_string(),
        username_encrypted: None,
        password: "secret".to_string(),
        password_encrypted: None,
        note: "note".to_string(),
        note_encrypted: None,
        last_touch: "now".to_string(),
        last_modified_gmt: "now".to_string(),
        fav: false,
        pwprotect: false,
        attachkey: String::new(),
        attachkey_encrypted: None,
        attachpresent: false,
        fields: Vec::new(),
    };

    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![account],
    };
    let json = serde_json::to_vec(&blob).expect("blob json");
    store
        .write_encrypted_buffer("blob.json", &json, key)
        .expect("blob write");
}

#[test]
fn status_with_plaintext_key_reports_logged_in() {
    let (temp, home) = unique_test_home();
    let key = [1u8; KDF_HASH_LEN];
    write_session_and_blob(&home, &key);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .args(["status", "--quiet"])
        .output()
        .expect("run status");
    assert_eq!(output.status.code().unwrap_or(-1), 0);

    let _ = temp;
}

#[test]
fn ls_reads_encrypted_blob_json() {
    let (temp, home) = unique_test_home();
    let key = [2u8; KDF_HASH_LEN];
    write_session_and_blob(&home, &key);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .args(["ls", "--color=never"])
        .output()
        .expect("run ls");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("team/entry"));

    let _ = temp;
}

#[test]
fn ls_uses_saved_env_file_for_mock_mode() {
    let (temp, home) = unique_test_home();
    let store = store_for(&home);
    store
        .write_string("env", "LPASS_HTTP_MOCK=1\n")
        .expect("write env");
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![account("0001", "alpha", "team")],
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env_remove("LPASS_HTTP_MOCK")
        .args(["ls", "--color=never"])
        .output()
        .expect("run ls");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("team/alpha"));

    let _ = temp;
}

#[test]
fn alias_expands_before_dispatch_in_cli_flow() {
    let (temp, home) = unique_test_home();
    let key = [4u8; KDF_HASH_LEN];
    write_session_and_blob(&home, &key);
    let store = store_for(&home);
    store
        .write_string("alias.passclip", "show --password -c")
        .expect("alias write");

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .args(["passclip", "team/entry"])
        .output()
        .expect("run alias command");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("secret"));

    let _ = temp;
}

#[test]
fn rm_removes_account_with_mock_env() {
    let (temp, home) = unique_test_home();
    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args([
            "rm",
            "--sync=no",
            "--color=never",
            "test-group/test-account",
        ])
        .output()
        .expect("run rm");
    assert_eq!(output.status.code().unwrap_or(-1), 0);

    let _ = temp;
}

#[test]
fn duplicate_accepts_sync_and_color_flags() {
    let (temp, home) = unique_test_home();
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![account("0001", "alpha", "team")],
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["duplicate", "--sync=now", "--color=never", "team/alpha"])
        .output()
        .expect("run duplicate");
    assert_eq!(output.status.code().unwrap_or(-1), 0);

    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args([
            "duplicate",
            "--sync",
            "auto",
            "--color",
            "never",
            "team/alpha",
        ])
        .output()
        .expect("run duplicate");
    assert_eq!(output.status.code().unwrap_or(-1), 0);

    let store = store_for(&home);
    let data = store.read_buffer("blob").expect("read blob").expect("blob");
    let updated: Blob = serde_json::from_slice(&data).expect("parse blob");
    assert_eq!(updated.accounts.len(), 3);

    let _ = temp;
}

#[test]
fn rm_accepts_space_separated_sync_and_color_flags() {
    let (temp, home) = unique_test_home();
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![account("0001", "alpha", "team")],
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["rm", "--sync", "now", "--color", "never", "team/alpha"])
        .output()
        .expect("run rm");
    assert_eq!(output.status.code().unwrap_or(-1), 0);

    let _ = temp;
}

#[test]
fn rm_reports_ambiguous_match() {
    let (temp, home) = unique_test_home();
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![
            account("0001", "dup", "team"),
            account("0002", "dup", "other"),
        ],
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["rm", "--sync=no", "dup"])
        .output()
        .expect("run rm");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Multiple matches"));

    let _ = temp;
}

#[test]
fn status_reports_not_logged_in_with_color() {
    let (temp, home) = unique_test_home();
    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .args(["status", "--color", "never"])
        .output()
        .expect("run status");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Not logged in"));

    let _ = temp;
}

#[test]
fn status_reports_logged_in_with_color_equals() {
    let (temp, home) = unique_test_home();
    let key = [3u8; KDF_HASH_LEN];
    write_session_and_blob(&home, &key);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .args(["status", "--color=never"])
        .output()
        .expect("run status");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Logged in"));

    let _ = temp;
}

#[test]
fn sync_reports_missing_session() {
    let (temp, home) = unique_test_home();
    let key = [5u8; KDF_HASH_LEN];
    write_key_and_verify(&home, &key);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .args(["sync"])
        .output()
        .expect("run sync");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Could not find session"));

    let _ = temp;
}

#[test]
fn ls_sync_mode_now_requires_remote_while_no_uses_local() {
    let (temp, home) = unique_test_home();
    let key = [6u8; KDF_HASH_LEN];
    write_session_and_blob(&home, &key);
    let store = store_for(&home);
    store
        .write_string("session_server", "127.0.0.1:1")
        .expect("write session server");

    let exe = env!("CARGO_BIN_EXE_lpass");
    let local_ok = Command::new(exe)
        .env("LPASS_HOME", &home)
        .args(["ls", "--sync=no", "--color=never"])
        .output()
        .expect("run ls sync=no");
    assert_eq!(local_ok.status.code().unwrap_or(-1), 0);

    let now_fail = Command::new(exe)
        .env("LPASS_HOME", &home)
        .args(["ls", "--sync=now", "--color=never"])
        .output()
        .expect("run ls sync=now");
    assert_eq!(now_fail.status.code().unwrap_or(-1), 1);

    let _ = temp;
}

#[test]
fn ls_includes_empty_shared_folders_from_blob_metadata() {
    let (temp, home) = unique_test_home();
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: vec![Share {
            id: "9001".to_string(),
            name: "Team Shared".to_string(),
            readonly: false,
        }],
        accounts: Vec::new(),
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["ls", "--color=never"])
        .output()
        .expect("run ls");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Team Shared"));

    let _ = temp;
}

#[test]
fn rm_rejects_readonly_shared_entries() {
    let (temp, home) = unique_test_home();
    let mut shared = account("0001", "entry", "Team");
    shared.share_name = Some("Team".to_string());
    shared.share_id = Some("77".to_string());
    shared.share_readonly = true;

    let blob = Blob {
        version: 1,
        local_version: false,
        shares: vec![Share {
            id: "77".to_string(),
            name: "Team".to_string(),
            readonly: true,
        }],
        accounts: vec![shared],
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["rm", "Team/entry"])
        .output()
        .expect("run rm");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("readonly shared entry"), "stderr: {stderr}");

    let _ = temp;
}
