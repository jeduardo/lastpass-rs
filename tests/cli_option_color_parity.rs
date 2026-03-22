use std::path::Path;
use std::process::Command;

use lpass_core::blob::{Account, Blob};
use lpass_core::config::{ConfigEnv, ConfigStore};
use lpass_core::kdf::KDF_HASH_LEN;
use lpass_core::session::{Session, session_save_with_store};
use tempfile::TempDir;

fn run(args: &[&str]) -> (i32, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .args(args)
        .output()
        .expect("failed to run lpass");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

const TEST_KEY: [u8; KDF_HASH_LEN] = [7u8; KDF_HASH_LEN];

fn store_for(home: &Path) -> ConfigStore {
    ConfigStore::with_env(ConfigEnv {
        lpass_home: Some(home.to_path_buf()),
        ..ConfigEnv::default()
    })
}

fn seed_logged_in_blob(home: &Path) {
    let store = store_for(home);
    store
        .write_buffer("plaintext_key", &TEST_KEY)
        .expect("plaintext key");
    store
        .write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &TEST_KEY)
        .expect("verify");
    store.write_string("username", "tester").expect("username");
    session_save_with_store(
        &store,
        &Session {
            uid: "u1".to_string(),
            session_id: "s1".to_string(),
            token: "t1".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        },
        &TEST_KEY,
    )
    .expect("session save");
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![Account {
            id: "100".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: "present-entry".to_string(),
            name_encrypted: None,
            group: "group".to_string(),
            group_encrypted: None,
            fullname: "group/present-entry".to_string(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: "user".to_string(),
            username_encrypted: None,
            password: "secret".to_string(),
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
        }],
        attachments: Vec::new(),
    };
    let encoded = serde_json::to_vec(&blob).expect("blob json");
    store
        .write_encrypted_buffer("blob.json", &encoded, &TEST_KEY)
        .expect("blob write");
}

#[test]
fn help_lists_mv_and_import_usage_like_c_client() {
    let (status, stdout, stderr) = run(&["--help"]);
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(stdout.contains("  lpass mv [--color=auto|never|always] {UNIQUENAME|UNIQUEID} GROUP"));
    assert!(!stdout.contains("  lpass mv [--sync=auto|now|no]"));
    assert!(stdout.contains("  lpass import [--keep-dupes] [CSV_FILENAME]"));
    assert!(!stdout.contains("  lpass import [--sync=auto|now|no]"));
}

#[test]
fn mv_and_import_invalid_sync_show_c_usage_text() {
    let home = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let mv = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["mv", "--sync=bad", "entry", "group"])
        .output()
        .expect("run mv");
    assert_eq!(mv.status.code().unwrap_or(-1), 1);
    let mv_stderr = String::from_utf8_lossy(&mv.stderr);
    assert!(mv_stderr.contains("Usage:"), "stderr: {mv_stderr}");
    assert!(mv_stderr.contains(" mv "), "stderr: {mv_stderr}");
    assert!(!mv_stderr.contains("--sync=auto|now|no"), "stderr: {mv_stderr}");

    let import = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["import", "--sync=bad"])
        .output()
        .expect("run import");
    assert_eq!(import.status.code().unwrap_or(-1), 1);
    let import_stderr = String::from_utf8_lossy(&import.stderr);
    assert!(import_stderr.contains("Usage:"), "stderr: {import_stderr}");
    assert!(import_stderr.contains(" import "), "stderr: {import_stderr}");
    assert!(
        !import_stderr.contains("--sync=auto|now|no"),
        "stderr: {import_stderr}"
    );
}

#[test]
fn status_color_always_preserves_ansi_on_stdout() {
    let home = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let output = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .arg("status")
        .arg("--color=always")
        .output()
        .expect("run status");

    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\x1b["), "stdout: {stdout}");
    assert!(stdout.contains("Not logged in"), "stdout: {stdout}");
}

#[test]
fn stderr_color_auto_strips_and_always_preserves_ansi() {
    let home = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");
    seed_logged_in_blob(home.path());

    let auto = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["show", "--sync=no", "missing-entry"])
        .output()
        .expect("run show auto");
    assert_eq!(auto.status.code().unwrap_or(-1), 1);
    let auto_stderr = String::from_utf8_lossy(&auto.stderr);
    assert!(!auto_stderr.contains("\x1b["), "stderr: {auto_stderr}");
    assert!(
        auto_stderr.contains("Could not find specified account(s)."),
        "stderr: {auto_stderr}"
    );

    let always = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["show", "--sync=no", "--color=always", "missing-entry"])
        .output()
        .expect("run show always");
    assert_eq!(always.status.code().unwrap_or(-1), 1);
    let always_stderr = String::from_utf8_lossy(&always.stderr);
    assert!(always_stderr.contains("\x1b["), "stderr: {always_stderr}");
    assert!(
        always_stderr.contains("Could not find specified account(s)."),
        "stderr: {always_stderr}"
    );
}

#[test]
fn saved_environment_read_errors_render_warning_prefix() {
    let home = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(home.path().join("env")).expect("make env dir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let output = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .arg("--version")
        .output()
        .expect("run version");

    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Warning: failed to load saved environment:"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("\x1b["), "stderr: {stderr}");
}

#[test]
fn saved_environment_warning_honors_color_flag() {
    let home = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(home.path().join("env")).expect("make env dir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let never = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .args(["status", "--color=never"])
        .output()
        .expect("run status --color=never");
    assert_eq!(never.status.code().unwrap_or(-1), 1);
    let never_stderr = String::from_utf8_lossy(&never.stderr);
    assert!(
        never_stderr.contains("Warning: failed to load saved environment:"),
        "stderr: {never_stderr}"
    );
    assert!(!never_stderr.contains("\x1b["), "stderr: {never_stderr}");

    let always = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .args(["status", "--color=always"])
        .output()
        .expect("run status --color=always");
    assert_eq!(always.status.code().unwrap_or(-1), 1);
    let always_stderr = String::from_utf8_lossy(&always.stderr);
    assert!(
        always_stderr.contains("failed to load saved environment:"),
        "stderr: {always_stderr}"
    );
    assert!(always_stderr.contains("\x1b["), "stderr: {always_stderr}");
}
