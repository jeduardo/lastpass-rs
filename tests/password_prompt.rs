#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use tempfile::TempDir;

fn script_command(shell_command: &str) -> Command {
    let mut command = Command::new("script");
    command.arg("-qec").arg(shell_command).arg("/dev/null");
    command
}

fn write_script(temp: &TempDir, name: &str, contents: &str) -> std::path::PathBuf {
    let path = temp.path().join(name);
    fs::write(&path, contents).expect("write script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod script");
    path
}

#[test]
fn login_prompt_reads_password_from_tty_without_askpass() {
    let temp = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");
    let shell_command = format!(
        "LPASS_HOME='{}' LPASS_HTTP_MOCK=1 LPASS_DISABLE_PINENTRY=1 '{}' login user@example.com",
        temp.path().display(),
        exe
    );

    let mut child = script_command(&shell_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn script");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(b"123456\n").expect("write password");
    }
    let output = child.wait_with_output().expect("wait output");

    assert_eq!(output.status.code().unwrap_or(-1), 0);
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        transcript.contains("Please enter the LastPass master password for <user@example.com>.")
    );
    assert!(transcript.contains("Master Password:"));
}

#[test]
fn login_prompt_reads_password_from_pinentry_when_available() {
    let temp = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");
    let pinentry = write_script(
        &temp,
        "pinentry-ok.sh",
        "#!/bin/sh\nprintf 'OK ready\\n'\nwhile IFS= read -r line; do\n  case \"$line\" in\n    GETPIN) printf 'D 123456\\nOK\\n' ;;\n    BYE) printf 'OK\\n'; exit 0 ;;\n    *) printf 'OK\\n' ;;\n  esac\ndone\n",
    );

    let output = Command::new(exe)
        .env("LPASS_HOME", temp.path())
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_PINENTRY", &pinentry)
        .arg("login")
        .arg("user@example.com")
        .output()
        .expect("run login");

    assert_eq!(output.status.code().unwrap_or(-1), 0);
}

#[test]
fn login_prompt_reports_failed_pinentry_without_fallback() {
    let temp = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");
    let pinentry = write_script(&temp, "pinentry-fail.sh", "#!/bin/sh\nprintf 'ERR fail\\n'\n");

    let output = Command::new(exe)
        .env("LPASS_HOME", temp.path())
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_PINENTRY", &pinentry)
        .arg("login")
        .arg("user@example.com")
        .output()
        .expect("run login");

    assert_ne!(output.status.code().unwrap_or(-1), 0);
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(transcript.contains("pinentry failed"));
}
