use std::process::Command;

use tempfile::TempDir;

#[test]
fn mv_rejects_invalid_space_separated_color_value() {
    let home = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let output = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["mv", "--color", "rainbow", "entry", "group"])
        .output()
        .expect("run mv");

    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:") && stderr.contains(" mv "), "stderr: {stderr}");
}
