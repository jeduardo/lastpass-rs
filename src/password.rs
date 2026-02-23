#![forbid(unsafe_code)]

use std::process::Command;

use crate::error::{LpassError, Result};

pub fn prompt_password(username: &str) -> Result<String> {
    let prompt = "Master Password";
    if let Some(askpass) = askpass_program_from_env() {
        let output = Command::new(askpass)
            .arg(prompt)
            .output()
            .map_err(|err| LpassError::io("askpass", err))?;
        if !output.status.success() {
            return Err(LpassError::Crypto("askpass failed"));
        }
        return Ok(decode_password_output(output.stdout));
    }

    eprintln!(
        "Please enter the LastPass master password for <{}>.",
        username
    );
    rpassword::prompt_password(format!("{prompt}: "))
        .map_err(|err| LpassError::io("password prompt", err))
}

fn askpass_program_from_env() -> Option<String> {
    askpass_program_from_value(crate::lpenv::var("LPASS_ASKPASS").ok())
}

fn askpass_program_from_value(value: Option<String>) -> Option<String> {
    value.filter(|item| !item.trim().is_empty())
}

fn decode_password_output(mut bytes: Vec<u8>) -> String {
    while matches!(bytes.last(), Some(b'\n') | Some(b'\r')) {
        bytes.pop();
    }
    String::from_utf8_lossy(&bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::{decode_password_output, prompt_password};
    use tempfile::TempDir;

    #[test]
    fn decode_password_output_trims_trailing_newlines() {
        let raw = b"passphrase with spaces\r\n".to_vec();
        assert_eq!(decode_password_output(raw), "passphrase with spaces");
    }

    #[test]
    fn askpass_uses_non_empty_value() {
        let value = super::askpass_program_from_value(Some("/tmp/lpass-askpass.sh".to_string()));
        assert_eq!(value.as_deref(), Some("/tmp/lpass-askpass.sh"));
    }

    #[test]
    fn askpass_ignores_empty_values() {
        let value = super::askpass_program_from_value(Some("   ".to_string()));
        assert!(value.is_none());
    }

    #[test]
    #[cfg(unix)]
    fn prompt_password_reads_value_from_askpass_program() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::lpenv::begin_test_overrides();
        let temp = TempDir::new().expect("tempdir");
        let script = temp.path().join("askpass-ok.sh");
        std::fs::write(&script, "#!/bin/sh\necho from-askpass\n").expect("write script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("chmod script");
        crate::lpenv::set_override_for_tests("LPASS_ASKPASS", &script.display().to_string());

        let value = prompt_password("user@example.com").expect("askpass value");
        assert_eq!(value, "from-askpass");
    }

    #[test]
    #[cfg(unix)]
    fn prompt_password_reports_askpass_failure() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::lpenv::begin_test_overrides();
        let temp = TempDir::new().expect("tempdir");
        let script = temp.path().join("askpass-fail.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 1\n").expect("write script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("chmod script");
        crate::lpenv::set_override_for_tests("LPASS_ASKPASS", &script.display().to_string());

        let err = prompt_password("user@example.com").expect_err("askpass must fail");
        assert!(format!("{err}").contains("askpass failed"));
    }
}
