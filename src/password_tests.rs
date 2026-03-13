use super::{
    askpass_program_from_env, askpass_program_from_value, decode_password_output, prompt_password,
    prompt_password_from_tty_with, write_prompt_description,
};
use tempfile::TempDir;

#[test]
fn decode_password_output_trims_trailing_newlines() {
    let raw = b"passphrase with spaces\r\n".to_vec();
    assert_eq!(decode_password_output(raw), "passphrase with spaces");
}

#[test]
fn askpass_uses_non_empty_value() {
    let value = askpass_program_from_value(Some("/tmp/lpass-askpass.sh".to_string()));
    assert_eq!(value.as_deref(), Some("/tmp/lpass-askpass.sh"));
}

#[test]
fn askpass_ignores_empty_values() {
    let value = askpass_program_from_value(Some("   ".to_string()));
    assert!(value.is_none());
}

#[test]
fn askpass_program_from_env_reads_override() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", "/tmp/lpass-askpass.sh");
    let value = askpass_program_from_env();
    assert_eq!(value.as_deref(), Some("/tmp/lpass-askpass.sh"));
}

#[test]
fn write_prompt_description_includes_optional_error() {
    let mut output = Vec::new();
    write_prompt_description(
        &mut output,
        "Please enter the LastPass master password for <user@example.com>.",
        Some("invalid password"),
    )
    .expect("write prompt description");

    let text = String::from_utf8(output).expect("utf8");
    assert_eq!(
        text,
        "Please enter the LastPass master password for <user@example.com>.\n\ninvalid password\n"
    );
}

#[test]
fn prompt_password_from_tty_with_writes_description_and_returns_value() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", "");

    let value = prompt_password_from_tty_with(
        "Master Password",
        Some("invalid password"),
        "Please enter the LastPass master password for <user@example.com>.",
        |prompt| {
            assert_eq!(prompt, "Master Password: ");
            Ok("from-tty".to_string())
        },
    )
    .expect("prompt");

    assert_eq!(value, "from-tty");
}

#[test]
fn prompt_password_from_tty_with_maps_prompt_errors() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", "");

    let err = prompt_password_from_tty_with("Prompt", None, "Description", |_| {
        Err(std::io::Error::other("tty failed"))
    })
    .expect_err("prompt must fail");

    assert!(format!("{err}").contains("tty failed"));
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
