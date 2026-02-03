use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_home() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("lpass-ls-auth-{nanos}"))
}

#[test]
fn ls_without_login_shows_upstream_style_error() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");

    let output = Command::new(exe)
        .env("LPASS_HOME", &test_home)
        .arg("ls")
        .output()
        .expect("run lpass ls");

    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "Could not find decryption key. Perhaps you need to login with `lpass login`."
        ),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains("missing iterations"),
        "stderr unexpectedly leaked internal error: {stderr}"
    );

    let _ = fs::remove_dir_all(&test_home);
}
