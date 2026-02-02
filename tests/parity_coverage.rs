use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_home() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("lpass-parity-cov-{nanos}"))
}

#[cfg(unix)]
fn write_askpass(home: &Path, content: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let askpass = home.join("askpass.sh");
    fs::write(&askpass, content).expect("write askpass");
    fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).expect("chmod askpass");
    askpass
}

fn run(home: &Path, askpass: Option<&Path>, args: &[&str]) -> Output {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut command = Command::new(exe);
    command.env("LPASS_HOME", home);
    command.env("LPASS_HTTP_MOCK", "1");
    command.env("LPASS_AGENT_DISABLE", "0");
    if let Some(askpass) = askpass {
        command.env("LPASS_ASKPASS", askpass);
    }
    command.args(args);
    command.output().expect("run command")
}

#[cfg(unix)]
#[test]
fn login_agent_status_ls_show_and_logout_cycle() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let askpass = write_askpass(&home, "#!/bin/sh\necho 123456\n");

    let login = run(
        &home,
        Some(&askpass),
        &["login", "--plaintext-key", "--force", "user@example.com"],
    );
    assert_eq!(
        login.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&login.stderr)
    );

    let status_quiet = run(&home, None, &["status", "--quiet"]);
    assert_eq!(status_quiet.status.code().unwrap_or(-1), 0);

    let status_verbose = run(&home, None, &["status", "--color=always"]);
    assert_eq!(status_verbose.status.code().unwrap_or(-1), 0);
    assert!(
        String::from_utf8_lossy(&status_verbose.stdout).contains("Logged in"),
        "stdout: {}",
        String::from_utf8_lossy(&status_verbose.stdout)
    );

    let ls = run(&home, None, &["ls", "--sync=no", "--long", "-u", "--color=never"]);
    assert_eq!(ls.status.code().unwrap_or(-1), 0);
    let ls_out = String::from_utf8_lossy(&ls.stdout);
    assert!(ls_out.contains("test-group/test-account"), "{ls_out}");
    assert!(ls_out.contains("[username: xyz@example.com]"), "{ls_out}");

    let show_json = run(&home, None, &["show", "--json", "test-group/test-account"]);
    assert_eq!(show_json.status.code().unwrap_or(-1), 0);
    assert!(
        String::from_utf8_lossy(&show_json.stdout).contains("\"name\": \"test-account\""),
        "stdout: {}",
        String::from_utf8_lossy(&show_json.stdout)
    );

    let logout = run(&home, None, &["logout", "--force"]);
    assert_eq!(logout.status.code().unwrap_or(-1), 0);

    let status_after = run(&home, None, &["status", "--quiet"]);
    assert_eq!(status_after.status.code().unwrap_or(-1), 1);

    let _ = fs::remove_dir_all(&home);
}

#[cfg(unix)]
#[test]
fn login_warning_failure_and_option_error_paths() {
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");
    let askpass_ok = write_askpass(&home, "#!/bin/sh\necho 123456\n");

    let login_warn = run(
        &home,
        Some(&askpass_ok),
        &["login", "--plaintext-key", "user@example.com"],
    );
    assert_eq!(login_warn.status.code().unwrap_or(-1), 0);
    assert!(
        String::from_utf8_lossy(&login_warn.stderr).contains("--plaintext-key reduces security"),
        "stderr: {}",
        String::from_utf8_lossy(&login_warn.stderr)
    );

    let ls_bad_args = run(&home, None, &["ls", "group1", "group2"]);
    assert_eq!(ls_bad_args.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&ls_bad_args.stderr).contains("usage: ls"),
        "stderr: {}",
        String::from_utf8_lossy(&ls_bad_args.stderr)
    );

    let missing_field = run(&home, None, &["show", "--field=Missing", "test-group/test-note"]);
    assert_eq!(missing_field.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&missing_field.stderr).contains("Could not find specified field"),
        "stderr: {}",
        String::from_utf8_lossy(&missing_field.stderr)
    );

    let show_attach = run(&home, None, &["show", "--attach=1", "test-group/test-account"]);
    assert_eq!(show_attach.status.code().unwrap_or(-1), 0);

    let status_bad = run(&home, None, &["status", "unexpected"]);
    assert_eq!(status_bad.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&status_bad.stderr).contains("usage: status"),
        "stderr: {}",
        String::from_utf8_lossy(&status_bad.stderr)
    );

    let logout_bad_color = run(&home, None, &["logout", "--color=rainbow"]);
    assert_eq!(logout_bad_color.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&logout_bad_color.stderr).contains("usage: logout"),
        "stderr: {}",
        String::from_utf8_lossy(&logout_bad_color.stderr)
    );

    let logout = run(&home, None, &["logout", "--force"]);
    assert_eq!(logout.status.code().unwrap_or(-1), 0);

    let askpass_bad = write_askpass(&home, "#!/bin/sh\necho wrong\n");
    let login_bad = run(&home, Some(&askpass_bad), &["login", "user@example.com"]);
    assert_eq!(login_bad.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&login_bad.stderr).contains("login failed"),
        "stderr: {}",
        String::from_utf8_lossy(&login_bad.stderr)
    );

    let _ = fs::remove_dir_all(&home);
}
