use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_TEST_HOME_ID: AtomicU64 = AtomicU64::new(0);

fn unique_test_home() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let seq = NEXT_TEST_HOME_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "lpass-logout-compat-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

fn write_test_file(home: &Path, name: &str) {
    let path = home.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, b"test").expect("write file");
}

#[test]
fn logout_force_clears_local_session_state() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");

    for file in [
        "verify",
        "username",
        "session_sessionid",
        "iterations",
        "blob",
        "blob.json",
        "session_token",
        "session_uid",
        "session_privatekey",
        "session_privatekeyenc",
        "session_server",
        "plaintext_key",
        "uploader.pid",
        "agent.sock",
        "session_ff_url_encryption",
        "session_ff_url_logging",
    ] {
        write_test_file(&test_home, file);
    }

    let output = Command::new(exe)
        .env("LPASS_HOME", &test_home)
        .arg("logout")
        .arg("--force")
        .output()
        .expect("run lpass logout --force");

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Log out: complete."),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    for file in [
        "verify",
        "username",
        "session_sessionid",
        "iterations",
        "blob",
        "blob.json",
        "session_token",
        "session_uid",
        "session_privatekey",
        "session_privatekeyenc",
        "session_server",
        "plaintext_key",
        "uploader.pid",
        "agent.sock",
        "session_ff_url_encryption",
        "session_ff_url_logging",
    ] {
        assert!(
            !test_home.join(file).exists(),
            "expected {} to be removed",
            file
        );
    }

    let _ = fs::remove_dir_all(&test_home);
}

#[test]
fn logout_without_force_can_be_aborted() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");
    write_test_file(&test_home, "username");

    let mut child = Command::new(exe)
        .env("LPASS_HOME", &test_home)
        .arg("logout")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lpass logout");
    {
        let stdin = child.stdin.as_mut().expect("stdin available");
        stdin.write_all(b"n\n").expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait output");

    assert_eq!(output.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Log out: aborted."),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(test_home.join("username").exists());

    let _ = fs::remove_dir_all(&test_home);
}

#[cfg(unix)]
#[test]
fn logout_force_stops_agent_so_status_is_logged_out() {
    use std::os::unix::fs::PermissionsExt;

    let exe = env!("CARGO_BIN_EXE_lpass");
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");

    let askpass = test_home.join("askpass.sh");
    fs::write(&askpass, "#!/bin/sh\necho 123456\n").expect("write askpass");
    fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).expect("chmod askpass");

    let login = Command::new(exe)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_HOME", &test_home)
        .env("LPASS_ASKPASS", &askpass)
        .args(["login", "user@example.com"])
        .output()
        .expect("run lpass login");
    assert_eq!(
        login.status.code().unwrap_or(-1),
        0,
        "login stderr: {}",
        String::from_utf8_lossy(&login.stderr)
    );

    let logout = Command::new(exe)
        .env("LPASS_HOME", &test_home)
        .args(["logout", "--force"])
        .output()
        .expect("run lpass logout --force");
    assert_eq!(
        logout.status.code().unwrap_or(-1),
        0,
        "logout stderr: {}",
        String::from_utf8_lossy(&logout.stderr)
    );

    let status = Command::new(exe)
        .env("LPASS_HOME", &test_home)
        .args(["status", "--quiet"])
        .output()
        .expect("run lpass status --quiet");
    assert_eq!(
        status.status.code().unwrap_or(-1),
        1,
        "status stdout: {} stderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );

    let _ = fs::remove_dir_all(&test_home);
}
