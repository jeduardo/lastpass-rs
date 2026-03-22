use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use lpass_core::blob::{Account, Blob, Share};
use lpass_core::config::{ConfigEnv, ConfigStore};
use lpass_core::kdf::KDF_HASH_LEN;
use lpass_core::session::{Session, session_save_with_store};

const MOCK_KEY: [u8; KDF_HASH_LEN] = [7u8; KDF_HASH_LEN];

fn unique_test_home() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("lpass-add-edit-parity-{nanos}"))
}

#[cfg(unix)]
fn write_editor_script(home: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let script = home.join("editor.sh");
    fs::write(
        &script,
        "#!/bin/sh\nset -eu\nif [ -n \"${LPASS_EDITOR_PATH_OUT:-}\" ]; then\n  printf '%s\n' \"$1\" > \"$LPASS_EDITOR_PATH_OUT\"\nfi\nsrc=\"$LPASS_EDITOR_CONTENT\"\ntmp=\"$1.tmp-replace\"\ncat \"$src\" > \"$tmp\"\nmv \"$tmp\" \"$1\"\n",
    )
    .expect("write editor");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod editor");
    script
}

#[cfg(unix)]
fn write_editor_content(home: &Path, name: &str, content: &str) -> PathBuf {
    let path = home.join(name);
    fs::write(&path, content).expect("write editor content");
    path
}

fn run(home: &Path, args: &[&str], stdin: Option<&str>, editor: Option<(&Path, &Path)>) -> Output {
    ensure_mock_state(home);
    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut command = Command::new(exe);
    command
        .env("LPASS_HOME", home)
        .env("LPASS_HTTP_MOCK", "1")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some((editor_script, editor_content)) = editor {
        command
            .env_remove("VISUAL")
            .env("EDITOR", editor_script)
            .env("LPASS_EDITOR_CONTENT", editor_content);
    }

    if let Some(stdin_value) = stdin {
        command.stdin(Stdio::piped());
        let mut child = command.spawn().expect("spawn lpass");
        {
            let input = child.stdin.as_mut().expect("stdin available");
            if let Err(err) = input.write_all(stdin_value.as_bytes())
                && err.kind() != std::io::ErrorKind::BrokenPipe
            {
                panic!("write stdin: {err}");
            }
        }
        child.wait_with_output().expect("wait output")
    } else {
        command.output().expect("run lpass")
    }
}

fn store_for(home: &Path) -> ConfigStore {
    ConfigStore::with_env(ConfigEnv {
        lpass_home: Some(home.to_path_buf()),
        ..ConfigEnv::default()
    })
}

fn write_mock_blob(home: &Path, blob: &Blob) {
    let store = store_for(home);
    seed_mock_auth(home);
    let json = serde_json::to_vec(blob).expect("blob json");
    store
        .write_encrypted_buffer("blob.json", &json, &MOCK_KEY)
        .expect("write blob");
}

fn read_mock_blob(home: &Path) -> Blob {
    let store = store_for(home);
    let buffer = store
        .read_encrypted_buffer("blob.json", &MOCK_KEY)
        .expect("read blob")
        .expect("blob contents");
    serde_json::from_slice(&buffer).expect("parse blob")
}

fn seed_mock_auth(home: &Path) {
    let store = store_for(home);
    store
        .write_buffer("plaintext_key", &MOCK_KEY)
        .expect("plaintext key");
    store
        .write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &MOCK_KEY)
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
        &MOCK_KEY,
    )
    .expect("session save");
}

fn ensure_mock_state(home: &Path) {
    let store = store_for(home);
    if store
        .read_buffer("plaintext_key")
        .expect("read plaintext key")
        .is_none()
    {
        seed_mock_auth(home);
    }
    if store
        .read_buffer("blob.json")
        .expect("read blob json")
        .is_none()
    {
        write_mock_blob(
            home,
            &Blob {
                version: 1,
                local_version: false,
                shares: Vec::new(),
                accounts: Vec::new(),
                attachments: Vec::new(),
            },
        );
    }
}

fn shared_blob() -> Blob {
    Blob {
        version: 1,
        local_version: false,
        shares: vec![Share {
            id: "77".to_string(),
            name: "Shared-team".to_string(),
            readonly: false,
            key: Some([7u8; KDF_HASH_LEN]),
        }],
        accounts: Vec::new(),
        attachments: Vec::new(),
    }
}

fn plain_account(fullname: &str) -> Account {
    let (group, name) = fullname
        .rsplit_once('/')
        .map(|(group, name)| (group.to_string(), name.to_string()))
        .unwrap_or_else(|| (String::new(), fullname.to_string()));
    Account {
        id: "100".to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name,
        name_encrypted: None,
        group,
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

#[cfg(unix)]
fn interactive_add_and_edit_any_paths_work() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let editor = write_editor_script(&home);

    let add_content = write_editor_content(
        &home,
        "add-any.txt",
        "Name: team/interactive\nURL: https://example.com\nUsername: bob\nPassword: pass\nNotes: initial\n",
    );
    let add = run(
        &home,
        &["add", "--sync=no", "team/interactive"],
        None,
        Some((&editor, &add_content)),
    );
    assert_eq!(
        add.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let edit_content = write_editor_content(
        &home,
        "edit-any.txt",
        "Name: team/interactive\nURL: https://new.example.com\nUsername: alice\nPassword: updated\nNotes: changed\n",
    );
    let edit = run(
        &home,
        &["edit", "--sync=no", "team/interactive"],
        None,
        Some((&editor, &edit_content)),
    );
    assert_eq!(
        edit.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&edit.stderr)
    );

    let show_user = run(
        &home,
        &["show", "--sync=no", "--username", "team/interactive"],
        None,
        None,
    );
    assert_eq!(show_user.status.code().unwrap_or(-1), 0);
    assert_eq!(String::from_utf8_lossy(&show_user.stdout).trim(), "alice");

    let show_url = run(
        &home,
        &["show", "--sync=no", "--url", "team/interactive"],
        None,
        None,
    );
    assert_eq!(show_url.status.code().unwrap_or(-1), 0);
    assert_eq!(
        String::from_utf8_lossy(&show_url.stdout).trim(),
        "https://new.example.com"
    );

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
fn edit_missing_entry_creates_new_entry() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let edit = run(
        &home,
        &[
            "edit",
            "--sync=no",
            "--non-interactive",
            "--username",
            "team/new-entry",
        ],
        Some("new-user\n"),
        None,
    );
    assert_eq!(
        edit.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&edit.stderr)
    );

    let show = run(
        &home,
        &["show", "--sync=no", "--username", "team/new-entry"],
        None,
        None,
    );
    assert_eq!(show.status.code().unwrap_or(-1), 0);
    assert_eq!(String::from_utf8_lossy(&show.stdout).trim(), "new-user");

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
fn interactive_secure_note_field_edit_updates_and_removes() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let editor = write_editor_script(&home);

    let add = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "--note-type=server",
            "team/server-entry",
        ],
        Some("Hostname: one\nUsername: user\nPassword: pass\n"),
        None,
    );
    assert_eq!(
        add.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let field_update = write_editor_content(&home, "field-update.txt", "two\n");
    let edit_update = run(
        &home,
        &["edit", "--sync=no", "--field=Hostname", "team/server-entry"],
        None,
        Some((&editor, &field_update)),
    );
    assert_eq!(
        edit_update.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&edit_update.stderr)
    );

    let show_field = run(
        &home,
        &["show", "--sync=no", "--field=Hostname", "team/server-entry"],
        None,
        None,
    );
    assert_eq!(show_field.status.code().unwrap_or(-1), 0);
    assert_eq!(String::from_utf8_lossy(&show_field.stdout).trim(), "two");

    let field_remove = write_editor_content(&home, "field-remove.txt", "\n");
    let edit_remove = run(
        &home,
        &["edit", "--sync=no", "--field=Hostname", "team/server-entry"],
        None,
        Some((&editor, &field_remove)),
    );
    assert_eq!(
        edit_remove.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&edit_remove.stderr)
    );

    let show_missing = run(
        &home,
        &["show", "--sync=no", "--field=Hostname", "team/server-entry"],
        None,
        None,
    );
    assert_eq!(show_missing.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&show_missing.stderr).contains("Could not find specified field"),
        "stderr: {}",
        String::from_utf8_lossy(&show_missing.stderr)
    );

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
fn add_non_interactive_choice_paths_work() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let add_user = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "--username",
            "team/user-only",
        ],
        Some("just-user\n"),
        None,
    );
    assert_eq!(add_user.status.code().unwrap_or(-1), 0);

    let show_user = run(
        &home,
        &["show", "--sync=no", "--username", "team/user-only"],
        None,
        None,
    );
    assert_eq!(show_user.status.code().unwrap_or(-1), 0);
    assert_eq!(
        String::from_utf8_lossy(&show_user.stdout).trim(),
        "just-user"
    );

    let add_pass = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "--password",
            "team/pass-only",
        ],
        Some("just-pass\n"),
        None,
    );
    assert_eq!(add_pass.status.code().unwrap_or(-1), 0);

    let show_pass = run(
        &home,
        &["show", "--sync=no", "--password", "team/pass-only"],
        None,
        None,
    );
    assert_eq!(show_pass.status.code().unwrap_or(-1), 0);
    assert_eq!(
        String::from_utf8_lossy(&show_pass.stdout).trim(),
        "just-pass"
    );

    let add_url = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "--url",
            "team/url-only",
        ],
        Some("https://one.example.com\n"),
        None,
    );
    assert_eq!(add_url.status.code().unwrap_or(-1), 0);

    let show_url = run(
        &home,
        &["show", "--sync=no", "--url", "team/url-only"],
        None,
        None,
    );
    assert_eq!(show_url.status.code().unwrap_or(-1), 0);
    assert_eq!(
        String::from_utf8_lossy(&show_url.stdout).trim(),
        "https://one.example.com"
    );

    let add_notes = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "--notes",
            "team/notes-only",
        ],
        Some("note body\n"),
        None,
    );
    assert_eq!(add_notes.status.code().unwrap_or(-1), 0);

    let show_notes = run(
        &home,
        &["show", "--sync=no", "--notes", "team/notes-only"],
        None,
        None,
    );
    assert_eq!(show_notes.status.code().unwrap_or(-1), 0);
    assert_eq!(
        String::from_utf8_lossy(&show_notes.stdout).trim(),
        "note body"
    );

    let add_field_non_secure = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "--field=Hostname",
            "team/field-unsupported",
        ],
        Some("x\n"),
        None,
    );
    assert_eq!(add_field_non_secure.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&add_field_non_secure.stderr).contains("not secure notes"),
        "stderr: {}",
        String::from_utf8_lossy(&add_field_non_secure.stderr)
    );

    let add_app = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "--app",
            "team/app-entry",
        ],
        Some("Application: demo-app\n"),
        None,
    );
    assert_eq!(add_app.status.code().unwrap_or(-1), 0);

    let show_app = run(
        &home,
        &["show", "--sync=no", "--field=Application", "team/app-entry"],
        None,
        None,
    );
    assert_eq!(show_app.status.code().unwrap_or(-1), 0);
    assert_eq!(String::from_utf8_lossy(&show_app.stdout).trim(), "demo-app");

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn add_edit_parity_paths() {
    interactive_add_and_edit_any_paths_work();
    edit_missing_entry_creates_new_entry();
    interactive_secure_note_field_edit_updates_and_removes();
    add_non_interactive_choice_paths_work();
}

#[cfg(unix)]
#[test]
fn add_editor_uses_secure_tempdir_path() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    ensure_mock_state(&home);
    let editor = write_editor_script(&home);
    let add_content = write_editor_content(
        &home,
        "add-secure-path.txt",
        "Name: team/secure-temp\nURL: https://example.com\nUsername: bob\nPassword: pass\nNotes: note\n",
    );
    let path_out = home.join("editor-path.txt");

    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env("LPASS_HTTP_MOCK", "1")
        .env_remove("VISUAL")
        .env("EDITOR", &editor)
        .env("LPASS_EDITOR_CONTENT", &add_content)
        .env("LPASS_EDITOR_PATH_OUT", &path_out)
        .args(["add", "--sync=no", "team/secure-temp"])
        .output()
        .expect("run add");

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    #[cfg(target_os = "linux")]
    {
        let path = fs::read_to_string(&path_out).expect("editor path");
        assert!(path.trim().starts_with("/dev/shm/lpass."));
    }

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn add_under_shared_folder_persists_shared_folder_metadata() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    write_mock_blob(&home, &shared_blob());

    let add = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "Shared-team/shared-credential",
        ],
        Some("URL: https://example.com\nUsername: alice\nPassword: secret\nNotes:\n"),
        None,
    );
    assert_eq!(
        add.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let blob = read_mock_blob(&home);
    let account = blob
        .accounts
        .iter()
        .find(|account| account.fullname == "Shared-team/shared-credential")
        .expect("shared account");
    assert_eq!(account.share_name.as_deref(), Some("Shared-team"));
    assert_eq!(account.share_id.as_deref(), Some("77"));
    assert_eq!(account.group, "");
    assert_eq!(account.name, "shared-credential");

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn edit_missing_entry_under_shared_folder_persists_shared_folder_metadata() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    write_mock_blob(&home, &shared_blob());

    let edit = run(
        &home,
        &[
            "edit",
            "--sync=no",
            "--non-interactive",
            "--username",
            "Shared-team/new-entry",
        ],
        Some("new-user\n"),
        None,
    );
    assert_eq!(
        edit.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&edit.stderr)
    );

    let blob = read_mock_blob(&home);
    let account = blob
        .accounts
        .iter()
        .find(|account| account.fullname == "Shared-team/new-entry")
        .expect("shared account");
    assert_eq!(account.share_name.as_deref(), Some("Shared-team"));
    assert_eq!(account.share_id.as_deref(), Some("77"));
    assert_eq!(account.group, "");
    assert_eq!(account.name, "new-entry");

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn edit_rejects_moving_existing_entry_into_shared_folder() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let mut blob = shared_blob();
    blob.accounts.push(plain_account("team/plain"));
    write_mock_blob(&home, &blob);

    let edit = run(
        &home,
        &[
            "edit",
            "--sync=no",
            "--non-interactive",
            "--name",
            "team/plain",
        ],
        Some("Shared-team/plain\n"),
        None,
    );
    assert_eq!(edit.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&edit.stderr)
            .contains("Use lpass mv to move items to/from shared folders"),
        "stderr: {}",
        String::from_utf8_lossy(&edit.stderr)
    );

    let blob = read_mock_blob(&home);
    let account = blob
        .accounts
        .iter()
        .find(|account| account.id == "100")
        .expect("plain account");
    assert_eq!(account.fullname, "team/plain");
    assert_eq!(account.share_id, None);

    let _ = fs::remove_dir_all(&home);
}
