#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

const DEFAULT_CLIPBOARD_COMMANDS: [(&str, &[&str]); 5] = [
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard", "-in"]),
    ("xsel", &["--clipboard", "--input"]),
    ("pbcopy", &[]),
    ("putclip", &["--dos"]),
];

pub(crate) fn copy_to_clipboard(data: &[u8]) -> Result<(), String> {
    let clipboard_command = crate::lpenv::var_os("LPASS_CLIPBOARD_COMMAND")
        .map(|value| value.to_string_lossy().into_owned());
    copy_to_clipboard_with_command(
        data,
        clipboard_command.as_deref(),
        &DEFAULT_CLIPBOARD_COMMANDS,
    )
}

fn copy_to_clipboard_with_command(
    data: &[u8],
    clipboard_command: Option<&str>,
    commands: &[(&str, &[&str])],
) -> Result<(), String> {
    if let Some(command) = clipboard_command {
        run_shell_clipboard_command(&command, data).map_err(|_| {
            "Unable to copy contents to clipboard. Please make sure you have `wl-clip`, `xclip`, `xsel`, `pbcopy`, or `putclip` installed.".to_string()
        })?;
        return Ok(());
    }

    if run_default_clipboard_commands(data, commands) {
        return Ok(());
    }

    Err(
        "Unable to copy contents to clipboard. Please make sure you have `xclip`, `xsel`, `pbcopy`, or `putclip` installed."
            .to_string(),
    )
}

fn run_default_clipboard_commands(data: &[u8], commands: &[(&str, &[&str])]) -> bool {
    for (program, args) in commands {
        match run_clipboard_command(program, args, data) {
            Ok(status) if status.success() => return true,
            _ => continue,
        }
    }
    false
}

fn run_shell_clipboard_command(command: &str, data: &[u8]) -> std::io::Result<()> {
    let shell = crate::lpenv::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let status = run_clipboard_command(&shell, &["-c", command], data)?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("clipboard command failed"))
    }
}

fn run_clipboard_command(
    program: &str,
    args: &[&str],
    data: &[u8],
) -> std::io::Result<std::process::ExitStatus> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(data))
        .transpose()?;

    child.wait()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_clipboard_command_writes_input_and_succeeds() {
        let status = run_clipboard_command("/bin/cat", &[], b"value").expect("run cat");
        assert!(status.success());
    }

    #[test]
    fn run_default_clipboard_commands_handles_success_and_failure() {
        let success =
            run_default_clipboard_commands(b"value", &[("/bin/false", &[]), ("/bin/cat", &[])]);
        assert!(success);

        let failure = run_default_clipboard_commands(b"value", &[("/bin/false", &[])]);
        assert!(!failure);
    }

    #[test]
    fn run_shell_clipboard_command_surfaces_nonzero_status() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("SHELL", "/bin/sh");
        let err = run_shell_clipboard_command("exit 1", b"v").expect_err("must fail");
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::Other | std::io::ErrorKind::BrokenPipe
        ));
    }

    #[test]
    fn run_shell_clipboard_command_maps_nonzero_status_after_successful_write() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("SHELL", "/bin/sh");
        let err =
            run_shell_clipboard_command("cat >/dev/null; exit 1", b"v").expect_err("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn copy_to_clipboard_maps_failed_custom_command_to_user_error() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_CLIPBOARD_COMMAND", "exit 1");
        crate::lpenv::set_override_for_tests("SHELL", "/bin/sh");
        let err = copy_to_clipboard(b"v").expect_err("must fail");
        assert!(err.contains("Unable to copy contents to clipboard"));
        assert!(err.contains("wl-clip"));
    }

    #[test]
    fn copy_to_clipboard_treats_empty_custom_command_as_active() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_CLIPBOARD_COMMAND", "");
        crate::lpenv::set_override_for_tests("SHELL", "/bin/sh");
        match copy_to_clipboard(b"v") {
            Ok(()) => {}
            Err(err) => {
                assert!(err.contains("Unable to copy contents to clipboard"));
                assert!(err.contains("wl-clip"));
            }
        }
    }

    #[test]
    fn copy_to_clipboard_with_command_uses_default_commands_when_available() {
        copy_to_clipboard_with_command(b"v", None, &[("/bin/false", &[]), ("/bin/cat", &[])])
            .expect("default clipboard command should succeed");
    }

    #[test]
    fn copy_to_clipboard_with_command_reports_default_command_failure() {
        let err = copy_to_clipboard_with_command(b"v", None, &[("/bin/false", &[])])
            .expect_err("default clipboard command should fail");
        assert!(err.contains("Unable to copy contents to clipboard"));
        assert!(!err.contains("wl-clip"));
    }
}
