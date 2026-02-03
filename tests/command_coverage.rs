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
    std::env::temp_dir().join(format!("lpass-command-cov-{nanos}"))
}

fn run_with_mock(home: &Path, args: &[&str], stdin: Option<&str>, http_mock: bool) -> Output {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut command = Command::new(exe);
    command.env("LPASS_HOME", home);
    if http_mock {
        command.env("LPASS_HTTP_MOCK", "1");
    } else {
        command.env_remove("LPASS_HTTP_MOCK");
    }
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.args(args);
    if let Some(stdin_value) = stdin {
        command.stdin(Stdio::piped());
        let mut child = command.spawn().expect("spawn lpass");
        {
            let input = child.stdin.as_mut().expect("stdin available");
            if let Err(err) = input.write_all(stdin_value.as_bytes()) {
                if err.kind() != std::io::ErrorKind::BrokenPipe {
                    panic!("write stdin: {err}");
                }
            }
        }
        child.wait_with_output().expect("wait output")
    } else {
        command.output().expect("run lpass")
    }
}

fn run(home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    run_with_mock(home, args, stdin, true)
}

#[cfg(unix)]
fn write_askpass(home: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let askpass = home.join("askpass.sh");
    fs::write(&askpass, "#!/bin/sh\necho 123456\n").expect("write askpass");
    fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).expect("chmod askpass");
    askpass
}

#[cfg(unix)]
fn write_askpass_value(home: &Path, value: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let askpass = home.join("askpass-value.sh");
    let script = format!("#!/bin/sh\necho {value}\n");
    fs::write(&askpass, script).expect("write askpass");
    fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).expect("chmod askpass");
    askpass
}

#[test]
fn add_edit_duplicate_generate_and_export_flow() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let add_in = "URL: https://svc.example.com\nUsername: user-a\nPassword: pass-a\nNotes:\ninitial note\n";
    let add_out = run(&home, &["add", "--sync=no", "--non-interactive", "team/service-one"], Some(add_in));
    assert_eq!(add_out.status.code().unwrap_or(-1), 0);

    let show_id = run(&home, &["show", "--sync=no", "--id", "team/service-one"], None);
    assert_eq!(show_id.status.code().unwrap_or(-1), 0);
    let original_id = String::from_utf8_lossy(&show_id.stdout).trim().to_string();

    let show_pw = run(&home, &["show", "--sync=no", "--password", "team/service-one"], None);
    assert_eq!(String::from_utf8_lossy(&show_pw.stdout).trim(), "pass-a");

    let edit_user = run(
        &home,
        &[
            "edit",
            "--sync=no",
            "--username",
            "--non-interactive",
            &original_id,
        ],
        Some("user-b\n"),
    );
    assert_eq!(edit_user.status.code().unwrap_or(-1), 0);

    let show_user = run(&home, &["show", "--sync=no", "--username", &original_id], None);
    assert_eq!(String::from_utf8_lossy(&show_user.stdout).trim(), "user-b");

    let dup_out = run(&home, &["duplicate", "--sync=no", "team/service-one"], None);
    assert_eq!(dup_out.status.code().unwrap_or(-1), 0);

    let ls_out = run(&home, &["ls", "--sync=no", "--color=never"], None);
    assert_eq!(ls_out.status.code().unwrap_or(-1), 0);
    let ls_text = String::from_utf8_lossy(&ls_out.stdout);
    assert!(ls_text.matches("team/service-one").count() >= 2, "{ls_text}");

    let gen_existing = run(
        &home,
        &[
            "generate",
            "--sync=no",
            "--username=gen-user",
            "--url=https://gen.example.com",
            &original_id,
            "20",
        ],
        None,
    );
    assert_eq!(gen_existing.status.code().unwrap_or(-1), 0);

    let show_user2 = run(&home, &["show", "--sync=no", "--username", &original_id], None);
    assert_eq!(String::from_utf8_lossy(&show_user2.stdout).trim(), "gen-user");
    let show_url = run(&home, &["show", "--sync=no", "--url", &original_id], None);
    assert_eq!(
        String::from_utf8_lossy(&show_url.stdout).trim(),
        "https://gen.example.com"
    );
    let show_pw2 = run(&home, &["show", "--sync=no", "--password", &original_id], None);
    assert_eq!(String::from_utf8_lossy(&show_pw2.stdout).trim().len(), 20);

    let gen_new = run(
        &home,
        &[
            "generate",
            "--sync=no",
            "--username=new-user",
            "--url=https://new.example.com",
            "team/new-generated",
            "16",
        ],
        None,
    );
    assert_eq!(gen_new.status.code().unwrap_or(-1), 0);
    let show_new_pw = run(
        &home,
        &["show", "--sync=no", "--password", "team/new-generated"],
        None,
    );
    assert_eq!(String::from_utf8_lossy(&show_new_pw.stdout).trim().len(), 16);

    let export = run(
        &home,
        &["export", "--sync=no", "--fields=name,username,url,grouping"],
        None,
    );
    assert_eq!(export.status.code().unwrap_or(-1), 0);
    let export_text = String::from_utf8_lossy(&export.stdout);
    assert!(export_text.contains("name,username,url,grouping"));
    assert!(export_text.contains("service-one,gen-user,https://gen.example.com,team"));
    assert!(export_text.contains("new-generated,new-user,https://new.example.com,team"));

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn secure_note_edit_paths_work() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let add_note = "Name: secure-note\nNumber: 000-00-0000\nNoteType: Social Security\n";
    let out = run(
        &home,
        &[
            "add",
            "--sync=no",
            "--note-type=ssn",
            "--non-interactive",
            "secure-note",
        ],
        Some(add_note),
    );
    assert_eq!(out.status.code().unwrap_or(-1), 0);

    let show_number = run(
        &home,
        &["show", "--sync=no", "--field=Number", "secure-note"],
        None,
    );
    assert_eq!(String::from_utf8_lossy(&show_number.stdout).trim(), "000-00-0000");

    let edit_field = run(
        &home,
        &[
            "edit",
            "--sync=no",
            "--field=Number",
            "--non-interactive",
            "secure-note",
        ],
        Some("111-11-1111"),
    );
    assert_eq!(edit_field.status.code().unwrap_or(-1), 0);
    let show_number2 = run(
        &home,
        &["show", "--sync=no", "--field=Number", "secure-note"],
        None,
    );
    assert_eq!(String::from_utf8_lossy(&show_number2.stdout).trim(), "111-11-1111");

    let edit_any = run(
        &home,
        &["edit", "--sync=no", "--non-interactive", "secure-note"],
        Some("Reprompt: Yes\nNotes: updated note"),
    );
    assert_eq!(edit_any.status.code().unwrap_or(-1), 0);

    let show_all = run(&home, &["show", "--sync=no", "secure-note"], None);
    let show_text = String::from_utf8_lossy(&show_all.stdout);
    assert!(show_text.contains("Reprompt: Yes"), "{show_text}");
    assert!(show_text.contains("Notes: updated note"), "{show_text}");

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn usage_and_error_paths_are_reported() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let add_no_non_interactive = run(&home, &["add", "x"], Some("Name: x\n"));
    assert_eq!(add_no_non_interactive.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&add_no_non_interactive.stderr)
            .contains("interactive add not implemented")
    );

    let edit_no_non_interactive = run(&home, &["edit", "--username", "x"], Some("u\n"));
    assert_eq!(edit_no_non_interactive.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&edit_no_non_interactive.stderr)
            .contains("interactive edit not implemented")
    );

    let duplicate_bad = run(&home, &["duplicate", "--bogus"], None);
    assert_eq!(duplicate_bad.status.code().unwrap_or(-1), 1);
    assert!(String::from_utf8_lossy(&duplicate_bad.stderr).contains("usage: duplicate"));

    let generate_bad = run(&home, &["generate", "name", "abc"], None);
    assert_eq!(generate_bad.status.code().unwrap_or(-1), 1);
    assert!(String::from_utf8_lossy(&generate_bad.stderr).contains("length must be a number"));

    let export_bad = run(&home, &["export", "unexpected"], None);
    assert_eq!(export_bad.status.code().unwrap_or(-1), 1);
    assert!(String::from_utf8_lossy(&export_bad.stderr).contains("usage: export"));

    let status_bad = run(&home, &["status", "unexpected"], None);
    assert_eq!(status_bad.status.code().unwrap_or(-1), 1);
    assert!(String::from_utf8_lossy(&status_bad.stderr).contains("usage: status"));

    let show_bad = run(&home, &["show", "--bogus"], None);
    assert_eq!(show_bad.status.code().unwrap_or(-1), 1);
    assert!(String::from_utf8_lossy(&show_bad.stderr).contains("usage: show"));

    let rm_missing = run(&home, &["rm", "x"], None);
    assert_eq!(rm_missing.status.code().unwrap_or(-1), 1);
    assert!(String::from_utf8_lossy(&rm_missing.stderr).contains("Could not find specified account"));

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn mv_rm_import_and_sync_paths_work_with_mock_blob() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let add_in = "URL: https://svc.example.com\nUsername: user-a\nPassword: pass-a\n";
    let add_out = run(
        &home,
        &["add", "--sync=no", "--non-interactive", "team/service-one"],
        Some(add_in),
    );
    assert_eq!(add_out.status.code().unwrap_or(-1), 0);

    let mv_out = run(&home, &["mv", "team/service-one", "ops"], None);
    assert_eq!(mv_out.status.code().unwrap_or(-1), 0);
    let show_name = run(&home, &["show", "--name", "ops/service-one"], None);
    assert_eq!(show_name.status.code().unwrap_or(-1), 0);
    assert_eq!(String::from_utf8_lossy(&show_name.stdout).trim(), "service-one");

    let rm_out = run(&home, &["rm", "ops/service-one"], None);
    assert_eq!(rm_out.status.code().unwrap_or(-1), 0);
    let show_removed = run(&home, &["show", "ops/service-one"], None);
    assert_eq!(show_removed.status.code().unwrap_or(-1), 1);

    let csv = "url,username,password,extra,name,grouping,fav\nhttps://one.example.com,u1,p1,n1,entry1,team,1\n";
    let import_out = run(&home, &["import", "--keep-dupes"], Some(csv));
    assert_eq!(import_out.status.code().unwrap_or(-1), 0);
    let import_stdout = String::from_utf8_lossy(&import_out.stdout);
    assert!(import_stdout.contains("Parsed 1 accounts"), "{import_stdout}");

    let sync_out = run(&home, &["sync", "--background"], None);
    assert_eq!(sync_out.status.code().unwrap_or(-1), 0);

    let ls_fmt = run(&home, &["ls", "--color=never", "--format", "%an"], None);
    assert_eq!(ls_fmt.status.code().unwrap_or(-1), 0);
    let ls_fmt_stdout = String::from_utf8_lossy(&ls_fmt.stdout);
    assert!(ls_fmt_stdout.contains("entry1"), "{ls_fmt_stdout}");

    let show_fmt = run(
        &home,
        &["show", "--format=%fn=%fv", "--title-format=%an", "team/entry1"],
        None,
    );
    assert_eq!(show_fmt.status.code().unwrap_or(-1), 0);

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn sync_without_mock_reaches_server_fetch_path_and_reports_network_error() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let askpass = write_askpass_value(&home, "123456");

    let login = Command::new(exe)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_HOME", &home)
        .env("LPASS_ASKPASS", &askpass)
        .args(["login", "user@example.com"])
        .output()
        .expect("run login");
    assert_eq!(
        login.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&login.stderr)
    );

    let sync = Command::new(exe)
        .env("LPASS_HOME", &home)
        .env_remove("LPASS_HTTP_MOCK")
        .env("LPASS_ASKPASS", &askpass)
        .arg("sync")
        .output()
        .expect("run sync");
    assert_eq!(sync.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&sync.stderr);
    assert!(
        stderr.contains("http post") || stderr.contains("Unable to fetch blob"),
        "{stderr}"
    );

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn login_status_and_logout_cycle() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let askpass = write_askpass(&home);

    let login = Command::new(exe)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_HOME", &home)
        .env("LPASS_ASKPASS", &askpass)
        .args([
            "login",
            "--trust",
            "--plaintext-key",
            "--force",
            "--color=always",
            "user@example.com",
        ])
        .output()
        .expect("run login");
    assert_eq!(
        login.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&login.stderr)
    );

    let status_ok = run(&home, &["status", "--quiet"], None);
    assert_eq!(status_ok.status.code().unwrap_or(-1), 0);

    let status_verbose = run(&home, &["status", "--color=always"], None);
    assert_eq!(status_verbose.status.code().unwrap_or(-1), 0);
    assert!(
        String::from_utf8_lossy(&status_verbose.stdout).contains("Logged in"),
        "stdout: {}",
        String::from_utf8_lossy(&status_verbose.stdout)
    );

    let logout = run(&home, &["logout", "--force"], None);
    assert_eq!(logout.status.code().unwrap_or(-1), 0);

    let status_after = run(&home, &["status", "--quiet"], None);
    assert_eq!(status_after.status.code().unwrap_or(-1), 1);

    let _ = fs::remove_dir_all(&home);
}
