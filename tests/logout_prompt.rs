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
    std::env::temp_dir().join(format!("lpass-logout-prompt-{nanos}"))
}

#[test]
fn logout_reprompts_on_invalid_answer_then_completes() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let home = unique_test_home();
    fs::create_dir_all(&home).expect("create home");

    let mut child = Command::new(exe)
        .env("LPASS_HOME", &home)
        .arg("logout")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn logout");

    {
        let stdin = child.stdin.as_mut().expect("stdin available");
        stdin
            .write_all(b"maybe\ny\n")
            .expect("write prompt responses");
    }

    let output = child.wait_with_output().expect("wait output");
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Response not understood."),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Log out: complete."),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let _ = fs::remove_dir_all(&home);
}
