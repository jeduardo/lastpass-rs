use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use lpass_core::blob::{Account, Blob, Share};
use lpass_core::config::{ConfigEnv, ConfigStore};
use lpass_core::kdf::KDF_HASH_LEN;
use lpass_core::session::{Session, session_save_with_store};
use tempfile::TempDir;

const MOCK_KEY: [u8; KDF_HASH_LEN] = [7u8; KDF_HASH_LEN];
const MOCK_PRIVATE_KEY_HEX: &str = "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100a1a227a8887870284bd831eb4a16dbba04c1092ce93e821b1523dcac45c84e34ea07139bee3a21b703fe78a3765995944c6646f4820341486a0f1c4472050110099b28b410d89d9fe2ebc2af752e95efdbaa9393a70dd09024719ea4fbb98c4498f7feced228a29462239f955ae0d028bb0cc5a641bdedc66f67fd2b5b4514d5020301000102818100920fadd4df962e8c4b958feeb6e217276f5a5d874733647142d64879290a4c9a068de48b7968f0c4a908514e2e09e060c5f57ad34395db6dabe201c25c62e7447dd91d051e1c614eaae5e51c90c6dc155665b91adc40c9b00dbcbcf7c3b86076274b7c0f411df082369e46788062afd6f6838be1eb0e92835d07ce9b3c80da55024100d49e0f79d17befdf79005e7f80a1cfe9b6c0875a1e157e1c0b8aac538e6bd387854718c0d1b5a75a1d73606be981ec4e7652c973dbfd3f650223b6787126fdb3024100c29cf9f94b7d3d48eaec0d7c6d7b91ec1c745ec6ae49f6d18550a1d63ef3864849eb8f4aac735f3c546514724c1e071d2b237927646c69bef2fffd14694b2f5702402a17385d17597fbd2fc920ec00dd07b9eed1e279b6a6ee9642baab2ec76d152d28f750312bd2d85480ac0c94905f86166a5a2d4360739c0f350338e6531032fd02400f081ceeba7bf3eddbe75bab4eb18ab5d804cd053f950af16800b05f6201614fd815cfbd8ed0627cc070064245cad3f5d6cd28a0784b3f67b6513b750624fe85024004ddedf0e84ddafcc86999697526fb0cad99928334f656f38ac14854db2551be0a683984f85dde12e1a5be921d1d86f5f53210a0c0f8e9de8495a10fee4d4fd3";

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
            private_key: Some(hex::decode(MOCK_PRIVATE_KEY_HEX).expect("private key")),
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
    assert!(
        stderr.contains("Usage:") && stderr.contains(" mv "),
        "stderr: {stderr}"
    );
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
fn mv_between_shared_folders_round_trips_through_sync_now() {
    let (_temp, home) = unique_test_home();
    write_key_and_session(&home, &[7u8; KDF_HASH_LEN]);
    write_mock_blob(&home, &move_blob(false));

    let moved = run_lpass(&home, &["mv", "Shared-team/apps/entry", "Shared-other/ops"]);
    assert_eq!(
        moved.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&moved.stderr)
    );

    let shown = run_lpass(
        &home,
        &["show", "--sync=now", "--username", "Shared-other/ops/entry"],
    );
    assert_eq!(
        shown.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&shown.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&shown.stdout).trim(), "alice");
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
