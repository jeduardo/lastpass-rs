use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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
