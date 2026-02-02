use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_home() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("lpass-show-compat-{nanos}"))
}

#[test]
fn show_accepts_password_short_option_after_name() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");

    let output = Command::new(exe)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_HOME", &test_home)
        .args(["show", "test-account", "-p", "password"])
        .output()
        .expect("run lpass show");

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "test-account-password\n"
    );

    let _ = fs::remove_dir_all(&test_home);
}

#[test]
fn show_password_short_option_works_with_shared_style_fullname() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");

    let fullname = "Shared-Team/Infrastructure/Service API Token";
    let password = "service-api-token";

    let mut add = Command::new(exe)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_HOME", &test_home)
        .args(["add", "--sync=no", "--non-interactive", fullname])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lpass add");
    {
        let stdin = add.stdin.as_mut().expect("stdin available");
        write!(stdin, "Password: {password}\n").expect("write add stdin");
    }
    let add_output = add.wait_with_output().expect("wait add output");
    assert_eq!(
        add_output.status.code().unwrap_or(-1),
        0,
        "add stderr: {}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let show_output = Command::new(exe)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_HOME", &test_home)
        .args(["show", fullname, "-p", "password"])
        .output()
        .expect("run lpass show");

    assert_eq!(
        show_output.status.code().unwrap_or(-1),
        0,
        "show stderr: {}",
        String::from_utf8_lossy(&show_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&show_output.stdout),
        format!("{password}\n")
    );

    let _ = fs::remove_dir_all(&test_home);
}
