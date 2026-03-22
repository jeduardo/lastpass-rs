use super::*;
use crate::blob::{Account, Share};
use crate::commands::data::{SyncMode, load_blob, save_blob};
use crate::config::{
    ConfigEnv, config_path, config_read_encrypted_buffer, config_write_buffer,
    config_write_encrypted_string, set_test_env,
};
use crate::kdf::KDF_HASH_LEN;
use crate::session::{Session, session_save};
use tempfile::TempDir;

fn account(id: &str, name: &str, fullname: &str, share_name: Option<&str>) -> Account {
    Account {
        id: id.to_string(),
        share_name: share_name.map(|value| value.to_string()),
        share_id: None,
        share_readonly: false,
        name: name.to_string(),
        name_encrypted: None,
        group: String::new(),
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

#[test]
fn find_unique_account_prefers_id_and_detects_ambiguity() {
    let accounts = vec![
        account("100", "shared", "team/shared", None),
        account("200", "shared", "other/shared", None),
    ];
    assert_eq!(
        find_unique_account_index(&accounts, "200").expect("id match"),
        1
    );
    let err = find_unique_account_index(&accounts, "shared").expect_err("ambiguous");
    assert!(err.contains("Multiple matches found"));
}

#[test]
fn update_location_sets_group_and_fullname() {
    let mut account = account("1", "entry", "team/entry", None);
    update_location(&mut account, "ops", &[]);
    assert_eq!(account.share_name, None);
    assert_eq!(account.group, "ops");
    assert_eq!(account.fullname, "ops/entry");
}

#[test]
fn update_location_infers_share_from_folder_prefix() {
    let mut account = account("1", "entry", "team/entry", Some("Team"));
    update_location(
        &mut account,
        "Team/dev",
        &[ShareRef {
            id: Some("42".to_string()),
            name: "Team".to_string(),
            readonly: false,
        }],
    );
    assert_eq!(account.share_name.as_deref(), Some("Team"));
    assert_eq!(account.share_id.as_deref(), Some("42"));
    assert_eq!(account.group, "dev");
    assert_eq!(account.fullname, "Team/dev/entry");
}

#[test]
fn update_location_handles_share_root_and_plain_root() {
    let mut shared = account("1", "entry", "Team/dev/entry", Some("Team"));
    update_location(
        &mut shared,
        "Team/",
        &[ShareRef {
            id: Some("42".to_string()),
            name: "Team".to_string(),
            readonly: false,
        }],
    );
    assert_eq!(shared.share_name.as_deref(), Some("Team"));
    assert_eq!(shared.share_id.as_deref(), Some("42"));
    assert_eq!(shared.group, "");
    assert_eq!(shared.fullname, "Team/entry");

    let mut plain = account("2", "entry", "ops/entry", None);
    update_location(
        &mut plain,
        "",
        &[ShareRef {
            id: Some("42".to_string()),
            name: "Team".to_string(),
            readonly: false,
        }],
    );
    assert_eq!(plain.share_name, None);
    assert_eq!(plain.share_id, None);
    assert_eq!(plain.group, "");
    assert_eq!(plain.fullname, "entry");
}

#[test]
fn collect_shares_deduplicates_and_prefers_longest_prefix() {
    let accounts = vec![
        account("1", "one", "Team/one", Some("Team")),
        account("2", "two", "Team/Platform/two", Some("Team/Platform")),
        account("3", "three", "Team/three", Some("Team")),
    ];
    let share_names = collect_shares(&accounts, &[]);
    assert_eq!(
        share_names
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Team/Platform", "Team"]
    );
    assert_eq!(
        infer_share("Team/Platform/dev", &share_names).map(|s| s.name.as_str()),
        Some("Team/Platform")
    );
    assert_eq!(infer_share("Elsewhere/dev", &share_names), None);
}

#[test]
fn collect_shares_prefers_explicit_share_metadata() {
    let shares = vec![Share {
        id: "abc".to_string(),
        name: "Shared".to_string(),
        readonly: true,
        key: None,
    }];
    let out = collect_shares(&[], &shares);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].id.as_deref(), Some("abc"));
    assert_eq!(out[0].name, "Shared");
    assert!(out[0].readonly);
}

#[test]
fn readonly_move_error_reports_share_name() {
    let mut acct = account("1", "entry", "Team/entry", Some("Team"));
    acct.share_readonly = true;
    let err = readonly_move_error(&acct).expect("readonly error");
    assert!(err.contains("move entry into Team"));
    assert_eq!(
        readonly_move_error(&account("2", "entry", "entry", None)),
        None
    );
}

#[test]
fn find_unique_account_reports_missing() {
    let accounts = vec![account("100", "alpha", "team/alpha", None)];
    let err = find_unique_account_index(&accounts, "missing").expect_err("missing");
    assert!(err.contains("Unable to find account"));
}

#[test]
fn run_inner_rejects_invalid_arguments() {
    let err = run_inner(&[]).expect_err("missing args");
    assert!(err.contains("usage: mv"));

    let err = run_inner(&["--color".to_string()]).expect_err("missing color value");
    assert!(err.contains("usage: mv"));

    let err = run_inner(&["--color=rainbow".to_string()]).expect_err("bad color");
    assert!(err.contains("usage: mv"));

    let err = run_inner(&["--sync".to_string()]).expect_err("missing sync");
    assert!(err.contains("usage: mv"));

    let err = run_inner(&["--sync=bad".to_string(), "a".to_string(), "b".to_string()])
        .expect_err("bad sync");
    assert!(err.contains("usage: mv"));

    let err = run_inner(&["--sync".to_string(), "auto".to_string(), "a".to_string()])
        .expect_err("missing destination");
    assert!(err.contains("usage: mv"));

    let err = run_inner(&["--bogus".to_string(), "a".to_string(), "b".to_string()])
        .expect_err("unknown option");
    assert!(err.contains("usage: mv"));
}

#[test]
fn run_and_parse_color_paths() {
    let _guard = crate::lpenv::begin_test_overrides();
    let home = TempDir::new().expect("temp home");
    crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
    crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");

    assert_eq!(run(&["--color".to_string()]), 1);

    let err = run_inner(&[
        "--color".to_string(),
        "rainbow".to_string(),
        "entry".to_string(),
        "group".to_string(),
    ])
    .expect_err("invalid separate color");
    assert!(err.contains("usage: mv"));

    let err = run_inner(&[
        "--color".to_string(),
        "never".to_string(),
        "entry".to_string(),
        "group".to_string(),
    ])
    .expect_err("runtime error after parse");
    assert!(err.contains("Unable to find account"));

    let err = run_inner(&[
        "--color=always".to_string(),
        "entry".to_string(),
        "group".to_string(),
    ])
    .expect_err("runtime error after parse");
    assert!(err.contains("Unable to find account"));
}

#[test]
fn run_returns_zero_for_successful_plain_move() {
    let (_temp, _guard, _env_guard) = configure_logged_in_mock_home();
    let mut blob = load_blob(SyncMode::No).expect("mock blob");
    blob.accounts.truncate(1);
    save_blob(&blob).expect("save blob");

    let code = run(&[
        "--sync=no".to_string(),
        "test-group/test-account".to_string(),
        "ops".to_string(),
    ]);
    assert_eq!(code, 0);

    let updated = load_blob(SyncMode::No).expect("load blob");
    assert_eq!(updated.accounts[0].fullname, "ops/test-account");
}

#[test]
fn run_inner_reports_load_blob_errors() {
    let _guard = crate::lpenv::begin_test_overrides();
    let home = TempDir::new().expect("temp home");
    crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());

    let err = run_inner(&["entry".to_string(), "ops".to_string()]).expect_err("load blob error");
    assert!(err.contains("Could not find decryption key"));
}

#[test]
fn run_inner_reports_readonly_move_error_in_mock_mode() {
    let _guard = crate::lpenv::begin_test_overrides();
    let home = TempDir::new().expect("temp home");
    crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
    crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");

    let mut blob = load_blob(SyncMode::No).expect("mock blob");
    let account = blob
        .accounts
        .iter_mut()
        .find(|item| item.fullname == "test-group/test-account")
        .expect("account");
    account.share_readonly = true;
    account.share_name = Some("Shared Team".to_string());
    save_blob(&blob).expect("save blob");

    let err = run_inner(&[
        "--sync=no".to_string(),
        "test-group/test-account".to_string(),
        "Shared Team/target".to_string(),
    ])
    .expect_err("readonly move should fail");
    assert!(err.contains("You do not have access to move"));
}

#[test]
fn find_unique_account_allows_name_zero_without_id_match() {
    let accounts = vec![account("10", "0", "0", None)];
    let idx = find_unique_account_index(&accounts, "0").expect("match by name");
    assert_eq!(idx, 0);
}

#[test]
fn share_changed_only_when_membership_changes() {
    let mut original = account("1", "entry", "Team/old/entry", Some("Team"));
    original.share_id = Some("77".to_string());

    let mut updated = original.clone();
    updated.group = "new".to_string();
    updated.fullname = "Team/new/entry".to_string();
    assert!(!share_changed(&original, &updated));

    updated.share_name = None;
    updated.share_id = None;
    updated.group = "plain".to_string();
    updated.fullname = "plain/entry".to_string();
    assert!(share_changed(&original, &updated));

    let mut plain = account("2", "entry", "plain/entry", None);
    plain.share_name = None;
    plain.share_id = None;
    let mut shared = plain.clone();
    shared.share_name = Some("Team".to_string());
    shared.share_id = Some("77".to_string());
    shared.group = "apps".to_string();
    shared.fullname = "Team/apps/entry".to_string();
    assert!(share_changed(&plain, &shared));

    let mut plain_case = account("3", "entry", "shared/entry", None);
    plain_case.share_name = Some("Shared-Team".to_string());
    let mut same_case_insensitive = account("3", "entry", "shared/entry", None);
    same_case_insensitive.share_name = Some("shared-team".to_string());
    assert!(!share_changed(&plain_case, &same_case_insensitive));
}

#[test]
fn share_name_eq_ignore_ascii_case_covers_matching_and_missing_values() {
    assert!(share_name_eq_ignore_ascii_case(Some("Team"), Some("team")));
    assert!(share_name_eq_ignore_ascii_case(None, None));
    assert!(!share_name_eq_ignore_ascii_case(Some("Team"), Some("Other")));
    assert!(!share_name_eq_ignore_ascii_case(Some("Team"), None));
}

#[test]
fn share_transition_has_api_ids_requires_non_empty_ids() {
    let mut original = account("1", "entry", "Team/entry", Some("Team"));
    let mut updated = account("1", "entry", "Other/entry", Some("Other"));

    original.share_id = Some("77".to_string());
    updated.share_id = None;
    assert!(share_transition_has_api_ids(&original, &updated));

    original.share_id = None;
    updated.share_id = Some("88".to_string());
    assert!(share_transition_has_api_ids(&original, &updated));

    original.share_id = Some(String::new());
    updated.share_id = Some(String::new());
    assert!(!share_transition_has_api_ids(&original, &updated));
}

#[test]
fn lpass_error_to_string_uses_display_text() {
    let err = lpass_error_to_string(crate::error::LpassError::User("boom"));
    assert_eq!(err, "boom");
}

#[test]
fn non_empty_share_id_filters_missing_and_empty_values() {
    assert_eq!(non_empty_share_id(None), None);
    assert_eq!(non_empty_share_id(Some("")), None);
    assert_eq!(non_empty_share_id(Some("77")), Some("77"));
}

fn configure_logged_in_mock_home(
) -> (
    TempDir,
    crate::config::TestEnvGuard,
    crate::lpenv::TestOverrideGuard,
) {
    let temp = TempDir::new().expect("tempdir");
    let guard = set_test_env(ConfigEnv {
        lpass_home: Some(temp.path().to_path_buf()),
        ..ConfigEnv::default()
    });

    let env_guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");

    let key = [7u8; KDF_HASH_LEN];
    config_write_buffer("plaintext_key", &key).expect("write key");
    config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
        .expect("write verify");
    session_save(
        &Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: true,
            server: None,
            private_key: None,
            private_key_enc: None,
        },
        &key,
    )
    .expect("save session");

    (temp, guard, env_guard)
}

fn mock_blob_with_shared_entry() -> crate::blob::Blob {
    let mut account = account("42", "entry", "Shared-team/apps/entry", Some("Shared-team"));
    account.share_id = Some("77".to_string());
    account.group = "apps".to_string();
    account.url = "https://example.com".to_string();
    account.username = "user".to_string();
    account.password = "pass".to_string();
    account.note = "note".to_string();

    crate::blob::Blob {
        version: 1,
        local_version: false,
        shares: vec![
            Share {
                id: "77".to_string(),
                name: "Shared-team".to_string(),
                readonly: false,
                key: Some([9u8; KDF_HASH_LEN]),
            },
            Share {
                id: "88".to_string(),
                name: "Shared-other".to_string(),
                readonly: false,
                key: Some([5u8; KDF_HASH_LEN]),
            },
        ],
        accounts: vec![account],
        attachments: Vec::new(),
    }
}

#[test]
fn run_inner_same_share_move_updates_blob_and_queues_standard_update() {
    let (_temp, _guard, _env_guard) = configure_logged_in_mock_home();
    let blob = mock_blob_with_shared_entry();
    crate::commands::data::save_blob(&blob).expect("save blob");

    let code = run_inner(&[
        "--sync=no".to_string(),
        "Shared-team/apps/entry".to_string(),
        "Shared-team/ops".to_string(),
    ])
    .expect("move");
    assert_eq!(code, 0);

    let updated = load_blob(SyncMode::No).expect("load blob");
    assert_eq!(updated.accounts.len(), 1);
    assert_eq!(updated.accounts[0].fullname, "Shared-team/ops/entry");

    let key = [7u8; KDF_HASH_LEN];
    let queue_dir = config_path("upload-queue/.marker")
        .expect("queue marker")
        .parent()
        .expect("queue dir")
        .to_path_buf();
    let name = std::fs::read_dir(queue_dir)
        .expect("read queue")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .find(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        .expect("queued file");
    let queued = config_read_encrypted_buffer(&format!("upload-queue/{name}"), &key)
        .expect("read queue entry")
        .expect("queue data");
    let request: serde_json::Value = serde_json::from_slice(&queued).expect("decode queue");
    assert_eq!(request["page"], "show_website.php");
    assert!(
        request["params"]
            .as_array()
            .expect("params array")
            .iter()
            .any(|entry| entry[0] == "sharedfolderid" && entry[1] == "77")
    );
}

#[test]
fn run_inner_share_boundary_move_removes_local_entry_after_success() {
    let (_temp, _guard, _env_guard) = configure_logged_in_mock_home();
    let blob = mock_blob_with_shared_entry();
    crate::commands::data::save_blob(&blob).expect("save blob");

    let code = run_inner(&[
        "--sync=no".to_string(),
        "Shared-team/apps/entry".to_string(),
        "Shared-other/ops".to_string(),
    ])
    .expect("move");
    assert_eq!(code, 0);

    let updated = load_blob(SyncMode::No).expect("load blob");
    assert!(updated.accounts.is_empty());
}

#[test]
fn run_inner_share_boundary_move_without_share_ids_errors_and_keeps_local_entry() {
    let (_temp, _guard, _env_guard) = configure_logged_in_mock_home();
    let mut blob = mock_blob_with_shared_entry();
    blob.accounts[0].share_id = None;
    blob.shares.clear();
    crate::commands::data::save_blob(&blob).expect("save blob");

    let err = run_inner(&[
        "--sync=no".to_string(),
        "Shared-team/apps/entry".to_string(),
        "plain".to_string(),
    ])
    .expect_err("share move should fail");
    assert!(err.contains("Move to/from shared folder failed (-22)"));

    let updated = load_blob(SyncMode::No).expect("load blob");
    assert_eq!(updated.accounts.len(), 1);
    assert_eq!(updated.accounts[0].fullname, "Shared-team/apps/entry");
    assert_eq!(updated.accounts[0].share_name.as_deref(), Some("Shared-team"));
    assert_eq!(updated.accounts[0].share_id, None);
}

#[test]
fn run_inner_share_boundary_move_keeps_local_entry_when_upload_fails() {
    let (_temp, _guard, _env_guard) = configure_logged_in_mock_home();
    let mut blob = mock_blob_with_shared_entry();
    let mut target = account("99", "other", "Shared-other/ops/other", Some("Shared-other"));
    target.share_id = Some("88".to_string());
    target.group = "ops".to_string();
    blob.accounts.push(target);
    blob.shares.clear();
    save_blob(&blob).expect("save blob");

    let err = run_inner(&[
        "--sync=no".to_string(),
        "Shared-team/apps/entry".to_string(),
        "Shared-other/ops".to_string(),
    ])
    .expect_err("share move upload should fail");
    assert!(err.contains("Unable to find shared folder key"));

    let updated = load_blob(SyncMode::No).expect("load blob");
    assert_eq!(updated.accounts.len(), 2);
    assert_eq!(updated.accounts[0].fullname, "Shared-team/apps/entry");
}

#[test]
fn run_inner_same_share_move_keeps_local_entry_when_update_fails() {
    let (_temp, _guard, _env_guard) = configure_logged_in_mock_home();
    let mut blob = mock_blob_with_shared_entry();
    blob.shares.clear();
    save_blob(&blob).expect("save blob");

    let err = run_inner(&[
        "--sync=no".to_string(),
        "Shared-team/apps/entry".to_string(),
        "Shared-team/ops".to_string(),
    ])
    .expect_err("standard update should fail");
    assert!(err.contains("Unable to find shared folder key"));

    let updated = load_blob(SyncMode::No).expect("load blob");
    assert_eq!(updated.accounts.len(), 1);
    assert_eq!(updated.accounts[0].fullname, "Shared-team/apps/entry");
}
