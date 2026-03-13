#![cfg(target_os = "linux")]

use std::io::Write;
use std::process::{Command, Stdio};

use tempfile::TempDir;

fn script_command(shell_command: &str) -> Command {
    let mut command = Command::new("script");
    command.arg("-qec").arg(shell_command).arg("/dev/null");
    command
}

#[test]
fn login_prompt_reads_password_from_tty_without_askpass() {
    let temp = TempDir::new().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_lpass");
    let shell_command = format!(
        "LPASS_HOME='{}' LPASS_HTTP_MOCK=1 LPASS_ASKPASS='' '{}' login user@example.com",
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
