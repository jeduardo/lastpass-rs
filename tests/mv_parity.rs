use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use lpass_core::blob::{Account, Blob, Share};
use lpass_core::config::{ConfigEnv, ConfigStore};
use lpass_core::kdf::KDF_HASH_LEN;
use lpass_core::session::{Session, session_save_with_store};
use tempfile::TempDir;

const MOCK_KEY: [u8; KDF_HASH_LEN] = [7u8; KDF_HASH_LEN];

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
    write_key_and_session(home, &MOCK_KEY);
    let json = serde_json::to_vec(blob).expect("blob json");
    store
        .write_encrypted_buffer("blob.json", &json, &MOCK_KEY)
        .expect("blob write");
}

fn read_mock_blob(home: &Path) -> Blob {
    let store = store_for(home);
    let buffer = store
        .read_encrypted_buffer("blob.json", &MOCK_KEY)
        .expect("read blob")
        .expect("blob contents");
    serde_json::from_slice(&buffer).expect("parse blob")
}

fn write_key_and_session(home: &Path, key: &[u8; KDF_HASH_LEN]) {
    let store = store_for(home);
    store
        .write_buffer("plaintext_key", key)
        .expect("plaintext key");
    store
        .write_encrypted_string("verify", "`lpass` was written by LastPass.\n", key)
        .expect("verify");
    store.write_string("username", "tester").expect("username");
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
    group: &str,
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
        group: group.to_string(),
        group_encrypted: None,
        fullname: fullname.to_string(),
        url: "https://example.com".to_string(),
        url_encrypted: None,
        username: "alice".to_string(),
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
    }
}

fn move_blob(target_readonly: bool) -> Blob {
    Blob {
        version: 1,
        local_version: false,
        shares: vec![
            Share {
                id: "77".to_string(),
                name: "Shared-team".to_string(),
                readonly: false,
                key: Some([7u8; KDF_HASH_LEN]),
            },
            Share {
                id: "88".to_string(),
                name: "Shared-other".to_string(),
                readonly: target_readonly,
                key: Some([8u8; KDF_HASH_LEN]),
            },
        ],
        accounts: vec![shared_account(
            "100",
            "entry",
            "apps",
            "Shared-team/apps/entry",
            "Shared-team",
            "77",
        )],
        attachments: Vec::new(),
    }
}

fn run_lpass(home: &Path, args: &[&str]) -> Output {
    let exe = env!("CARGO_BIN_EXE_lpass");
    Command::new(exe)
        .env("LPASS_HOME", home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(args)
        .output()
        .expect("run lpass")
}

#[test]
fn mv_rejects_invalid_space_separated_color_value() {
    let (_temp, home) = unique_test_home();
    let output = run_lpass(&home, &["mv", "--color", "rainbow", "entry", "group"]);

    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:") && stderr.contains(" mv "), "stderr: {stderr}");
}

#[test]
fn mv_moves_entry_between_shared_folders_through_cli() {
    let (_temp, home) = unique_test_home();
    write_key_and_session(&home, &[7u8; KDF_HASH_LEN]);
    write_mock_blob(&home, &move_blob(false));

    let output = run_lpass(
        &home,
        &[
            "mv",
            "--sync=no",
            "Shared-team/apps/entry",
            "Shared-other/ops",
        ],
    );

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let blob = read_mock_blob(&home);
    assert!(
        blob.accounts.iter().all(|account| account.id != "100"),
        "moved shared entry should be removed from local blob after upload"
    );
}

#[test]
fn mv_moves_entry_out_of_shared_folder_through_cli() {
    let (_temp, home) = unique_test_home();
    write_key_and_session(&home, &[7u8; KDF_HASH_LEN]);
    write_mock_blob(&home, &move_blob(false));

    let output = run_lpass(&home, &["mv", "--sync=no", "Shared-team/apps/entry", "ops"]);

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let blob = read_mock_blob(&home);
    assert!(
        blob.accounts.iter().all(|account| account.id != "100"),
        "entry moved out of a shared folder should be removed from the local blob"
    );
}

#[test]
fn mv_rejects_readonly_target_shared_folder_through_cli() {
    let (_temp, home) = unique_test_home();
    write_key_and_session(&home, &[7u8; KDF_HASH_LEN]);
    write_mock_blob(&home, &move_blob(true));

    let output = run_lpass(
        &home,
        &[
            "mv",
            "--sync=no",
            "Shared-team/apps/entry",
            "Shared-other/ops",
        ],
    );

    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("You do not have access to move entry into Shared-other"),
        "stderr: {stderr}"
    );

    let blob = read_mock_blob(&home);
    let account = blob
        .accounts
        .iter()
        .find(|account| account.id == "100")
        .expect("original account retained");
    assert_eq!(account.fullname, "Shared-team/apps/entry");
    assert_eq!(account.share_name.as_deref(), Some("Shared-team"));
    assert_eq!(account.share_id.as_deref(), Some("77"));
}
