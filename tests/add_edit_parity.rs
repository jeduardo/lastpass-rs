use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use lpass_core::blob::{Account, Blob, Share};
use lpass_core::config::{ConfigEnv, ConfigStore};
use lpass_core::kdf::KDF_HASH_LEN;

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
        "#!/bin/sh\nset -eu\nsrc=\"$LPASS_EDITOR_CONTENT\"\ntmp=\"$1.tmp-replace\"\ncat \"$src\" > \"$tmp\"\nmv \"$tmp\" \"$1\"\n",
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

#[cfg(target_os = "linux")]
fn write_editor_capture_script(home: &Path, capture: &Path, replacement: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let script = home.join("editor-capture.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nset -eu\nprintf '%s' \"$1\" > '{}'\nprintf '%s' '{}' > \"$1\"\n",
            capture.display(),
            replacement
        ),
    )
    .expect("write editor");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod editor");
    script
}

#[cfg(unix)]
fn write_editor_snapshot_script(home: &Path, capture: &Path, replacement: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let script = home.join("editor-snapshot.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nset -eu\ncp \"$1\" '{}'\nprintf '%s' '{}' > \"$1\"\n",
            capture.display(),
            replacement
        ),
    )
    .expect("write editor");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod editor");
    script
}

fn run(home: &Path, args: &[&str], stdin: Option<&str>, editor: Option<(&Path, &Path)>) -> Output {
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
    let json = serde_json::to_vec(blob).expect("blob json");
    store.write_buffer("blob", &json).expect("write blob");
}

fn read_mock_blob(home: &Path) -> Blob {
    let store = store_for(home);
    let buffer = store
        .read_buffer("blob")
        .expect("read blob")
        .expect("blob contents");
    serde_json::from_slice(&buffer).expect("parse blob")
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

#[cfg(target_os = "linux")]
#[test]
fn interactive_add_uses_dev_shm_tempdir() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let capture = home.join("editor-path.txt");
    let editor = write_editor_capture_script(
        &home,
        &capture,
        "Name: team/secure-temp\nURL: https://example.com\nUsername: bob\nPassword: pass\nNotes: initial\n",
    );

    let add = run(
        &home,
        &["add", "--sync=no", "team/secure-temp"],
        None,
        Some((&editor, Path::new("/dev/null"))),
    );
    assert_eq!(
        add.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let edited_path = fs::read_to_string(capture).expect("read capture");
    assert!(edited_path.starts_with("/dev/shm/lpass."), "{edited_path}");

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
fn add_app_without_application_field_adds_empty_application_field() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let add_app = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--non-interactive",
            "--app",
            "team/app-empty",
        ],
        Some("Notes: app note\n"),
        None,
    );
    assert_eq!(
        add_app.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&add_app.stderr)
    );

    let show_app = run(
        &home,
        &["show", "--sync=no", "--field=Application", "team/app-empty"],
        None,
        None,
    );
    assert_eq!(
        show_app.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&show_app.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&show_app.stdout), "\n");

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn add_usage_paths_cover_parser_errors() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let cases = [
        (vec!["add", "first", "second"], "usage: add"),
        (vec!["add", "--field"], "usage: add"),
        (vec!["add", "--note-type"], "--note-type=TYPE"),
        (vec!["add", "--note-type", "unknown"], "--note-type=TYPE"),
        (vec!["add", "--color"], "usage: add"),
        (vec!["add", "--color", "bogus", "entry"], "usage: add"),
        (vec!["add", "--color=bogus", "entry"], "usage: add"),
    ];

    for (args, expected) in cases {
        let output = run(&home, &args, None, None);
        assert_eq!(output.status.code().unwrap_or(-1), 1);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn add_secure_note_editor_parses_multiline_private_key_and_reprompt() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let editor = write_editor_script(&home);
    let content = write_editor_content(
        &home,
        "add-ssh.txt",
        "Name: team/ssh-entry\nName: alias\nNoteType: SSH Key\nPrivate Key: line1\nline two\nReprompt: Yes\nNotes:    # Add notes below this line.\nssh body\n",
    );

    let add = run(
        &home,
        &["add", "--sync=no", "team/ssh-entry"],
        None,
        Some((&editor, &content)),
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
        .find(|account| account.fullname == "team/ssh-entry")
        .expect("ssh account");
    assert!(account.pwprotect);

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
fn edit_existing_entry_username_choice_path_works() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let mut blob = shared_blob();
    blob.accounts.push(plain_account("team/existing"));
    write_mock_blob(&home, &blob);

    let edit = run(
        &home,
        &[
            "edit",
            "--sync=no",
            "--non-interactive",
            "--username",
            "team/existing",
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
        &["show", "--sync=no", "--username", "team/existing"],
        None,
        None,
    );
    assert_eq!(show.status.code().unwrap_or(-1), 0);
    assert_eq!(String::from_utf8_lossy(&show.stdout).trim(), "new-user");

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn edit_usage_paths_cover_parser_errors() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let cases = [
        (vec!["edit", "first", "second"], "usage: edit"),
        (vec!["edit", "--field"], "usage: edit"),
        (vec!["edit", "--sync"], "usage: edit"),
        (vec!["edit", "--sync", "bad", "entry"], "usage: edit"),
        (vec!["edit", "--sync=bad", "entry"], "usage: edit"),
    ];

    for (args, expected) in cases {
        let output = run(&home, &args, None, None);
        assert_eq!(output.status.code().unwrap_or(-1), 1);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn edit_interactive_plain_entry_initial_text_contains_login_fields() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let capture = home.join("edit-initial.txt");
    let editor = write_editor_snapshot_script(&home, &capture, "Name: team/plain\n");

    let mut blob = shared_blob();
    blob.accounts.push(plain_account("team/plain"));
    write_mock_blob(&home, &blob);

    let edit = run(
        &home,
        &["edit", "--sync=no", "team/plain"],
        None,
        Some((&editor, Path::new("/dev/null"))),
    );
    assert_eq!(
        edit.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&edit.stderr)
    );

    let initial = fs::read_to_string(capture).expect("read captured editor content");
    assert!(initial.contains("URL: https://example.com"), "{initial}");
    assert!(initial.contains("Username: alice"), "{initial}");
    assert!(initial.contains("Password: secret"), "{initial}");

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn edit_interactive_any_path_updates_name_notes_reprompt_and_custom_fields() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let editor = write_editor_script(&home);
    let content = write_editor_content(
        &home,
        "edit-any-custom.txt",
        "Name: team/renamed\nCustom: value\nReprompt: Yes\nNotes:    # Add notes below this line.\nupdated body\n",
    );

    let mut blob = shared_blob();
    blob.accounts.push(plain_account("team/plain"));
    write_mock_blob(&home, &blob);

    let edit = run(
        &home,
        &["edit", "--sync=no", "team/plain"],
        None,
        Some((&editor, &content)),
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
        .find(|account| account.fullname == "team/renamed")
        .expect("updated account");
    assert!(account.pwprotect);
    assert_eq!(account.note.trim_end(), "updated body");
    assert!(
        account
            .fields
            .iter()
            .any(|field| field.name == "Custom" && field.value == "value")
    );

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn add_edit_parity_paths() {
    interactive_add_and_edit_any_paths_work();
    edit_missing_entry_creates_new_entry();
    interactive_secure_note_field_edit_updates_and_removes();
    add_non_interactive_choice_paths_work();
    add_app_without_application_field_adds_empty_application_field();
    edit_existing_entry_username_choice_path_works();
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
