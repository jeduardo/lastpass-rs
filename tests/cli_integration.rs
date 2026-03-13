use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

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
        attachments: Vec::new(),
    };
    let json = serde_json::to_vec(&blob).expect("blob json");
    store
        .write_encrypted_buffer("blob.json", &json, key)
        .expect("blob write");
}

fn write_session(home: &Path, key: &[u8; KDF_HASH_LEN], session: &Session) {
    let store = store_for(home);
    write_key_and_verify(home, key);
    store.write_string("username", "tester").expect("username");
    session_save_with_store(&store, session, key).expect("session save");
}

fn write_queue_request(home: &Path, key: &[u8; KDF_HASH_LEN], name: &str, page: &str) {
    let store = store_for(home);
    let payload = serde_json::to_vec(&serde_json::json!({
        "page": page,
        "params": [["id", "100"], ["method", "cli"]],
    }))
    .expect("queue json");
    store
        .write_encrypted_buffer(&format!("upload-queue/{name}"), &payload, key)
        .expect("queue write");
}

fn queued_entry_count(home: &Path) -> usize {
    let dir = home.join("upload-queue");
    match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
            })
            .count(),
        Err(_) => 0,
    }
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
fn hidden_uploader_requires_key_stdin() {
    let (_temp, home) = unique_test_home();
    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .arg("__upload-queue")
        .output()
        .expect("run hidden uploader");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("read uploader key"));
}

#[test]
fn hidden_uploader_processes_queue_entries() {
    let (_temp, home) = unique_test_home();
    let key = [9u8; KDF_HASH_LEN];
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
    write_session(&home, &key, &session);
    write_queue_request(&home, &key, "1000", "loglogin.php");

    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut child = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .arg("__upload-queue")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn hidden uploader");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(&key)
        .expect("write key");
    let output = child.wait_with_output().expect("wait uploader");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    assert_eq!(queued_entry_count(&home), 0);
}

#[test]
fn sync_background_starts_uploader_and_drains_queue() {
    let (_temp, home) = unique_test_home();
    let key = [8u8; KDF_HASH_LEN];
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
    write_session(&home, &key, &session);
    write_queue_request(&home, &key, "1001", "loglogin.php");

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["sync", "--background"])
        .output()
        .expect("run sync background");
    assert_eq!(output.status.code().unwrap_or(-1), 0);

    for _ in 0..40 {
        if queued_entry_count(&home) == 0 && !home.join("uploader.pid").exists() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }

    panic!(
        "background uploader did not drain queue: remaining={}, pid={}",
        queued_entry_count(&home),
        home.join("uploader.pid").display()
    );
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
        attachments: Vec::new(),
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
    let clip_file = home.join("alias-clip.out");
    let clip_command = format!("cat > {}", clip_file.display());
    store
        .write_string("alias.passclip", "show --password -c")
        .expect("alias write");

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_CLIPBOARD_COMMAND", clip_command)
        .args(["passclip", "team/entry"])
        .output()
        .expect("run alias command");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    assert!(
        output.stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let copied = fs::read_to_string(&clip_file).expect("read copied value");
    assert_eq!(copied, "secret");

    let _ = temp;
}

#[test]
fn generate_clip_uses_clipboard_and_suppresses_stdout() {
    let (temp, home) = unique_test_home();
    let clip_file = home.join("generate-clip.out");
    let clip_command = format!("cat > {}", clip_file.display());
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![account("0001", "entry", "team")],
        attachments: Vec::new(),
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_CLIPBOARD_COMMAND", clip_command)
        .args(["generate", "--sync=no", "--clip", "team/entry", "18"])
        .output()
        .expect("run generate");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    assert!(
        output.stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let copied = fs::read_to_string(&clip_file).expect("read copied password");
    assert!(copied.ends_with('\n'));
    assert_eq!(copied.trim().len(), 18);

    let show = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["show", "--sync=no", "--password", "team/entry"])
        .output()
        .expect("run show");
    assert_eq!(show.status.code().unwrap_or(-1), 0);
    assert_eq!(String::from_utf8_lossy(&show.stdout).trim(), copied.trim());

    let _ = temp;
}

#[test]
fn generate_no_symbols_outputs_only_alnum_characters() {
    let (temp, home) = unique_test_home();
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![account("0001", "entry", "team")],
        attachments: Vec::new(),
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["generate", "--sync=no", "--no-symbols", "team/entry", "64"])
        .output()
        .expect("run generate");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(password.len(), 64);
    assert!(password.chars().all(|ch| ch.is_ascii_alphanumeric()));

    let _ = temp;
}

#[test]
fn generate_updates_secure_note_fields() {
    let (temp, home) = unique_test_home();
    let mut secure_note = account("0001", "server-note", "team");
    secure_note.url = "http://sn".to_string();
    secure_note.note =
        "NoteType: Server\nHostname:server.example.com\nUsername:old-user\nPassword:old-pass"
            .to_string();
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![secure_note],
        attachments: Vec::new(),
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let generate = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args([
            "generate",
            "--sync=no",
            "--username=new-user",
            "--url=https://example.com",
            "team/server-note",
            "24",
        ])
        .output()
        .expect("run generate");
    assert_eq!(generate.status.code().unwrap_or(-1), 0);
    let password = String::from_utf8_lossy(&generate.stdout).trim().to_string();
    assert_eq!(password.len(), 24);

    let show_user = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["show", "--sync=no", "--username", "team/server-note"])
        .output()
        .expect("run show user");
    assert_eq!(show_user.status.code().unwrap_or(-1), 0);
    assert_eq!(
        String::from_utf8_lossy(&show_user.stdout).trim(),
        "new-user"
    );

    let show_url = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["show", "--sync=no", "--url", "team/server-note"])
        .output()
        .expect("run show url");
    assert_eq!(show_url.status.code().unwrap_or(-1), 0);
    assert_eq!(
        String::from_utf8_lossy(&show_url.stdout).trim(),
        "https://example.com"
    );

    let show_password = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["show", "--sync=no", "--password", "team/server-note"])
        .output()
        .expect("run show password");
    assert_eq!(show_password.status.code().unwrap_or(-1), 0);
    assert_eq!(
        String::from_utf8_lossy(&show_password.stdout).trim(),
        password
    );

    let _ = temp;
}

#[test]
fn export_skips_group_rows_in_mock_mode() {
    let (_temp, home) = unique_test_home();
    let mut group = account("0001", "Shared", "");
    group.url = "http://group".to_string();
    let normal = account("0002", "alpha", "team");
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![group, normal],
        attachments: Vec::new(),
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["export", "--sync=no", "--fields=name,url"])
        .output()
        .expect("run export");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("name,url"));
    assert!(stdout.contains("alpha,"));
    assert!(!stdout.contains("Shared,http://group"));
}

#[test]
fn import_from_stdin_reports_removed_duplicates_in_mock_mode() {
    let (_temp, home) = unique_test_home();
    let mut existing = account("0001", "entry", "");
    existing.url = "https://example.com".to_string();
    existing.username = "alice".to_string();
    existing.password = "secret".to_string();
    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![existing],
        attachments: Vec::new(),
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut child = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["import", "--sync=no"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn import");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"url,username,password,name\nhttps://example.com,alice,secret,entry\n")
        .expect("write csv");
    let output = child.wait_with_output().expect("wait import");
    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Parsed 1 accounts"));
    assert!(stdout.contains("Removed 1 duplicate accounts"));
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
        attachments: Vec::new(),
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
        attachments: Vec::new(),
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
        attachments: Vec::new(),
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
fn export_sync_no_queues_access_logs_and_sync_drains_them() {
    let (temp, home) = unique_test_home();
    let key = [9u8; KDF_HASH_LEN];
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
    write_session(&home, &key, &session);

    let blob = Blob {
        version: 1,
        local_version: false,
        shares: Vec::new(),
        accounts: vec![Account {
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
            note: String::new(),
            note_encrypted: None,
            last_touch: "now".to_string(),
            last_modified_gmt: "now".to_string(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        }],
        attachments: Vec::new(),
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let export = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["export", "--sync=no", "--fields=name"])
        .output()
        .expect("run export");
    assert_eq!(export.status.code().unwrap_or(-1), 0);

    let queue_dir = home.join("upload-queue");
    let queued: Vec<_> = fs::read_dir(&queue_dir)
        .expect("read queue dir")
        .filter_map(|entry| entry.ok())
        .collect();
    assert_eq!(queued.len(), 1);

    let sync = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .arg("sync")
        .output()
        .expect("run sync");
    assert_eq!(sync.status.code().unwrap_or(-1), 0);

    let queued_after: Vec<_> = fs::read_dir(&queue_dir)
        .expect("read queue dir")
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(queued_after.is_empty());

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
        attachments: Vec::new(),
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
        attachments: Vec::new(),
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

#[test]
fn generate_rejects_readonly_shared_entries() {
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
        attachments: Vec::new(),
    };
    write_mock_blob(&home, &blob);

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(["generate", "--sync=no", "Team/entry", "20"])
        .output()
        .expect("run generate");
    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("readonly shared entry"), "stderr: {stderr}");

    let _ = temp;
}
