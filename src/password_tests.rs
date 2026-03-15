use super::{
    askpass_program_from_env, askpass_program_from_value, decode_password_output, pinentry_escape,
    pinentry_is_disabled, pinentry_program_from_env, pinentry_unescape, prompt_password,
    prompt_password_from_tty_with, prompt_password_with_description_and_tty,
    write_prompt_description,
};
use tempfile::TempDir;

#[test]
fn decode_password_output_trims_trailing_newlines() {
    let raw = b"passphrase with spaces\r\n".to_vec();
    assert_eq!(decode_password_output(raw), "passphrase with spaces");
}

#[test]
fn askpass_uses_non_empty_value() {
    let value = askpass_program_from_value(Some("/tmp/lpass-askpass.sh".into()));
    assert_eq!(value.as_deref(), Some("/tmp/lpass-askpass.sh"));
}

#[test]
fn askpass_preserves_empty_values() {
    let value = askpass_program_from_value(Some("".into()));
    assert_eq!(value.as_deref(), Some(""));
}

#[test]
fn askpass_program_from_env_reads_override() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", "/tmp/lpass-askpass.sh");
    let value = askpass_program_from_env();
    assert_eq!(value.as_deref(), Some("/tmp/lpass-askpass.sh"));
}

#[test]
fn pinentry_helpers_respect_env_and_escape_protocol_values() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_DISABLE_PINENTRY", "1");
    crate::lpenv::set_override_for_tests("LPASS_PINENTRY", "/tmp/pinentry-custom");

    assert!(pinentry_is_disabled());
    assert_eq!(pinentry_program_from_env(), "/tmp/pinentry-custom");
    assert_eq!(pinentry_escape("a%b\r\n"), "a%25b%0d%0a");
    assert_eq!(pinentry_unescape("line%0abreak%25"), "line\nbreak%");
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
fn prompt_password_with_description_reads_value_from_askpass_program() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("askpass-description.sh");
    std::fs::write(&script, "#!/bin/sh\necho described-pass\n").expect("write script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
        .expect("chmod script");
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", &script.display().to_string());

    let value = super::prompt_password_with_description(
        "Master Password",
        Some("invalid password"),
        "Description",
    )
    .expect("askpass value");
    assert_eq!(value, "described-pass");
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

#[test]
#[cfg(unix)]
fn prompt_password_uses_tty_when_pinentry_is_disabled() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_DISABLE_PINENTRY", "1");

    let value = prompt_password_with_description_and_tty(
        "Master Password",
        None,
        "Description",
        |prompt| {
            assert_eq!(prompt, "Master Password: ");
            Ok("from-tty".to_string())
        },
    )
    .expect("prompt");

    assert_eq!(value, "from-tty");
}

#[test]
#[cfg(unix)]
fn prompt_password_uses_pinentry_when_available() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let log = temp.path().join("pinentry.log");
    let script = temp.path().join("pinentry-ok.sh");
    let body = format!(
        "#!/bin/sh\nprintf 'OK mock\\n'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    GETPIN) printf '%s\\n' 'D from%0apinentry'; printf 'OK\\n' ;;\n    BYE) exit 0 ;;\n    *) printf 'OK\\n' ;;\n  esac\ndone\n",
        log.display()
    );
    std::fs::write(&script, body).expect("write script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
        .expect("chmod script");

    crate::lpenv::set_override_for_tests("LPASS_PINENTRY", &script.display().to_string());
    crate::lpenv::set_override_for_tests("TERM", "xterm-256color");
    crate::lpenv::set_override_for_tests("DISPLAY", ":1");

    let value = prompt_password_with_description_and_tty(
        "Master Password",
        Some("invalid password"),
        "Please enter the LastPass master password for <user@example.com>.",
        |_| panic!("tty fallback should not be used"),
    )
    .expect("pinentry value");

    assert_eq!(value, "from\npinentry");
    let transcript = std::fs::read_to_string(&log).expect("read pinentry log");
    assert!(transcript.contains("SETTITLE LastPass CLI"));
    assert!(transcript.contains("SETPROMPT Master Password:"));
    assert!(transcript.contains("SETERROR invalid password"));
    assert!(
        transcript
            .contains("SETDESC Please enter the LastPass master password for <user@example.com>.")
    );
    assert!(transcript.contains("OPTION ttytype=xterm-256color"));
    assert!(transcript.contains("OPTION display=:1"));
    assert!(transcript.contains("GETPIN"));
}

#[test]
#[cfg(unix)]
fn prompt_password_falls_back_when_pinentry_cannot_execute() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_PINENTRY", "/definitely/missing/pinentry");

    let value = prompt_password_with_description_and_tty(
        "Master Password",
        None,
        "Description",
        |prompt| {
            assert_eq!(prompt, "Master Password: ");
            Ok("from-tty".to_string())
        },
    )
    .expect("tty fallback");

    assert_eq!(value, "from-tty");
}

#[test]
#[cfg(unix)]
fn prompt_password_reports_pinentry_failure() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-fail.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf 'OK mock\\n'\nexit 1\n").expect("write script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
        .expect("chmod script");
    crate::lpenv::set_override_for_tests("LPASS_PINENTRY", &script.display().to_string());

    let err =
        prompt_password_with_description_and_tty("Master Password", None, "Description", |_| {
            panic!("tty fallback should not be used")
        })
        .expect_err("pinentry must fail");

    assert!(format!("{err}").contains("pinentry failed"));
}
