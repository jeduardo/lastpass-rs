use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .args(args)
        .output()
        .expect("failed to run lpass");
    let status = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (status, stdout, stderr)
}

#[test]
fn version_flag_prints_version() {
    let (status, stdout, stderr) = run(&["--version"]);
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(stdout.starts_with("LastPass CLI v"));
    assert!(stdout.contains("based on lastpass-cli"));
}

#[test]
fn version_command_prints_version() {
    let (status, stdout, stderr) = run(&["version"]);
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(stdout.starts_with("LastPass CLI v"));
    assert!(stdout.contains("based on lastpass-cli"));
}

#[test]
fn help_flag_prints_version_and_usage() {
    let (status, stdout, stderr) = run(&["--help"]);
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(stdout.contains("LastPass CLI v"));
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("lpass version"));
    assert!(stdout.contains("lpass login"));
    assert!(stdout.contains("lpass show"));
}

#[test]
fn no_args_prints_usage_only() {
    let (status, stdout, stderr) = run(&[]);
    assert_eq!(status, 1, "stderr: {stderr}");
    assert!(stdout.contains("Usage:"));
    assert!(!stdout.contains("LastPass CLI v"));
}

#[test]
fn unknown_command_prints_usage() {
    let (status, stdout, _stderr) = run(&["not-a-command"]);
    assert_eq!(status, 1);
    assert!(stdout.contains("Usage:"));
}
