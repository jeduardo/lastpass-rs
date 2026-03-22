use std::process::Command;

use tempfile::TempDir;

fn run(args: &[&str]) -> (i32, String, String) {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let output = Command::new(exe)
        .args(args)
        .output()
        .expect("failed to run lpass");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn help_lists_mv_and_import_usage_like_c_client() {
    let (status, stdout, stderr) = run(&["--help"]);
    assert_eq!(status, 0, "stderr: {stderr}");
    assert!(stdout.contains("  lpass mv [--color=auto|never|always] {UNIQUENAME|UNIQUEID} GROUP"));
    assert!(!stdout.contains("  lpass mv [--sync=auto|now|no]"));
    assert!(stdout.contains("  lpass import [--keep-dupes] [CSV_FILENAME]"));
    assert!(!stdout.contains("  lpass import [--sync=auto|now|no]"));
}

#[test]
fn mv_and_import_invalid_sync_show_c_usage_text() {
    let home = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let mv = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["mv", "--sync=bad", "entry", "group"])
        .output()
        .expect("run mv");
    assert_eq!(mv.status.code().unwrap_or(-1), 1);
    let mv_stderr = String::from_utf8_lossy(&mv.stderr);
    assert!(mv_stderr.contains("Usage:"), "stderr: {mv_stderr}");
    assert!(mv_stderr.contains(" mv "), "stderr: {mv_stderr}");
    assert!(!mv_stderr.contains("--sync=auto|now|no"), "stderr: {mv_stderr}");

    let import = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["import", "--sync=bad"])
        .output()
        .expect("run import");
    assert_eq!(import.status.code().unwrap_or(-1), 1);
    let import_stderr = String::from_utf8_lossy(&import.stderr);
    assert!(import_stderr.contains("Usage:"), "stderr: {import_stderr}");
    assert!(import_stderr.contains(" import "), "stderr: {import_stderr}");
    assert!(
        !import_stderr.contains("--sync=auto|now|no"),
        "stderr: {import_stderr}"
    );
}

#[test]
fn status_color_always_preserves_ansi_on_stdout() {
    let home = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let output = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .arg("status")
        .arg("--color=always")
        .output()
        .expect("run status");

    assert_eq!(output.status.code().unwrap_or(-1), 1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\x1b["), "stdout: {stdout}");
    assert!(stdout.contains("Not logged in"), "stdout: {stdout}");
}

#[test]
fn stderr_color_auto_strips_and_always_preserves_ansi() {
    let home = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let auto = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["show", "missing-entry"])
        .output()
        .expect("run show auto");
    assert_eq!(auto.status.code().unwrap_or(-1), 1);
    let auto_stderr = String::from_utf8_lossy(&auto.stderr);
    assert!(!auto_stderr.contains("\x1b["), "stderr: {auto_stderr}");
    assert!(
        auto_stderr.contains("Could not find specified account(s)."),
        "stderr: {auto_stderr}"
    );

    let always = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .env("LPASS_HTTP_MOCK", "1")
        .args(["show", "--color=always", "missing-entry"])
        .output()
        .expect("run show always");
    assert_eq!(always.status.code().unwrap_or(-1), 1);
    let always_stderr = String::from_utf8_lossy(&always.stderr);
    assert!(always_stderr.contains("\x1b["), "stderr: {always_stderr}");
    assert!(
        always_stderr.contains("Could not find specified account(s)."),
        "stderr: {always_stderr}"
    );
}

#[test]
fn saved_environment_read_errors_render_warning_prefix() {
    let home = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(home.path().join("env")).expect("make env dir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let output = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .arg("--version")
        .output()
        .expect("run version");

    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Warning: failed to load saved environment:"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("\x1b["), "stderr: {stderr}");
}

#[test]
fn saved_environment_warning_honors_color_flag() {
    let home = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(home.path().join("env")).expect("make env dir");
    let exe = env!("CARGO_BIN_EXE_lpass");

    let never = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .args(["status", "--color=never"])
        .output()
        .expect("run status --color=never");
    assert_eq!(never.status.code().unwrap_or(-1), 1);
    let never_stderr = String::from_utf8_lossy(&never.stderr);
    assert!(
        never_stderr.contains("Warning: failed to load saved environment:"),
        "stderr: {never_stderr}"
    );
    assert!(!never_stderr.contains("\x1b["), "stderr: {never_stderr}");

    let always = Command::new(exe)
        .env("LPASS_HOME", home.path())
        .args(["status", "--color=always"])
        .output()
        .expect("run status --color=always");
    assert_eq!(always.status.code().unwrap_or(-1), 1);
    let always_stderr = String::from_utf8_lossy(&always.stderr);
    assert!(
        always_stderr.contains("failed to load saved environment:"),
        "stderr: {always_stderr}"
    );
    assert!(always_stderr.contains("\x1b["), "stderr: {always_stderr}");
}
