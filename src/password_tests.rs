use std::ffi::OsString;
#[cfg(unix)]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;

use super::{
    PinentryError, askpass_program_from_env, askpass_program_from_value, decode_password_output,
    pinentry_disabled, pinentry_escape, pinentry_program_from_env, pinentry_unescape,
    prompt_password, prompt_password_from_tty_with, prompt_password_with_description_and_tty,
    prompt_password_with_pinentry, take_pinentry_stdio,
    write_prompt_description,
};
use tempfile::TempDir;

#[cfg(unix)]
fn write_script(path: &Path, contents: &str) {
    let mut file = std::fs::File::create(path).expect("create script");
    file.write_all(contents.as_bytes()).expect("write script");
    file.sync_all().expect("sync script");
    drop(file);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod script");
    std::thread::sleep(Duration::from_millis(10));
}

#[test]
fn decode_password_output_trims_trailing_newlines() {
    let raw = b"passphrase with spaces\r\n".to_vec();
    assert_eq!(decode_password_output(raw), "passphrase with spaces");
}

#[test]
fn askpass_program_from_value_preserves_empty_values() {
    let value = askpass_program_from_value(Some(OsString::from("")));
    assert_eq!(value, Some(OsString::from("")));
}

#[test]
fn askpass_program_from_value_preserves_non_empty_values() {
    let value = askpass_program_from_value(Some(OsString::from("/tmp/lpass-askpass.sh")));
    assert_eq!(value, Some(OsString::from("/tmp/lpass-askpass.sh")));
}

#[test]
fn askpass_program_from_env_reads_override() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", "/tmp/lpass-askpass.sh");
    let value = askpass_program_from_env();
    assert_eq!(value, Some(OsString::from("/tmp/lpass-askpass.sh")));
}

#[test]
fn pinentry_disabled_only_accepts_one() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_DISABLE_PINENTRY", "0");
    assert!(!pinentry_disabled());
    crate::lpenv::set_override_for_tests("LPASS_DISABLE_PINENTRY", "1");
    assert!(pinentry_disabled());
}

#[test]
fn pinentry_program_from_env_reads_override() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_PINENTRY", "/tmp/pinentry");
    assert_eq!(pinentry_program_from_env().as_deref(), Some("/tmp/pinentry"));
}

#[test]
fn pinentry_escape_matches_c_behavior() {
    assert_eq!(pinentry_escape("a%b\r\nc"), "a%25b%0d%0ac");
}

#[test]
fn pinentry_unescape_matches_c_behavior() {
    assert_eq!(pinentry_unescape("a%25b%0d%0ac"), "a%b\r\nc");
}

#[test]
fn pinentry_unescape_decodes_utf8_escape_bytes() {
    assert_eq!(pinentry_unescape("%C3%A9"), "é");
}

#[test]
fn pinentry_unescape_stops_on_truncated_sequence() {
    assert_eq!(pinentry_unescape("abc%"), "abc");
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
    let mut prompt = |prompt| {
        assert_eq!(prompt, "Master Password: ");
        Ok("from-tty".to_string())
    };
    let value = prompt_password_from_tty_with(
        "Master Password",
        Some("invalid password"),
        "Please enter the LastPass master password for <user@example.com>.",
        &mut prompt,
    )
    .expect("prompt");

    assert_eq!(value, "from-tty");
}

#[test]
fn prompt_password_from_tty_with_maps_prompt_errors() {
    let mut prompt = |_| Err(std::io::Error::other("tty failed"));
    let err = prompt_password_from_tty_with("Prompt", None, "Description", &mut prompt)
        .expect_err("prompt must fail");

    assert!(format!("{err}").contains("tty failed"));
}

#[test]
#[cfg(unix)]
fn prompt_password_reads_value_from_askpass_program() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("askpass-ok.sh");
    write_script(&script, "#!/bin/sh\necho from-askpass\n");
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", &script.display().to_string());

    let value = prompt_password("user@example.com").expect("askpass value");
    assert_eq!(value, "from-askpass");
}

#[test]
#[cfg(unix)]
fn prompt_password_reports_askpass_failure() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("askpass-fail.sh");
    write_script(&script, "#!/bin/sh\nexit 1\n");
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", &script.display().to_string());

    let err = prompt_password("user@example.com").expect_err("askpass must fail");
    assert!(format!("{err}").contains("askpass failed"));
}

#[test]
#[cfg(unix)]
fn prompt_password_treats_empty_askpass_as_active_override() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_ASKPASS", "");

    let err = prompt_password("user@example.com").expect_err("empty askpass must fail");
    assert!(format!("{err}").contains("askpass"));
}

#[test]
fn prompt_password_with_description_uses_tty_when_pinentry_is_disabled() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_DISABLE_PINENTRY", "1");

    let mut calls = 0;
    let mut prompt = |prompt| {
        calls += 1;
        assert_eq!(prompt, "Master Password: ");
        Ok("from-tty".to_string())
    };
    let password = prompt_password_with_description_and_tty(
        "Master Password",
        Some("invalid password"),
        "Prompt description",
        &mut prompt,
    )
    .expect("tty password");

    assert_eq!(password, "from-tty");
    assert_eq!(calls, 1);
}

#[test]
fn prompt_password_with_description_falls_back_to_tty_when_pinentry_is_unavailable() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_PINENTRY", "/path/that/does/not/exist");

    let mut calls = 0;
    let mut prompt = |_| {
        calls += 1;
        Ok("fallback".to_string())
    };
    let password = prompt_password_with_description_and_tty(
        "Master Password",
        None,
        "Prompt description",
        &mut prompt,
    )
    .expect("fallback password");

    assert_eq!(password, "fallback");
    assert_eq!(calls, 1);
}

#[test]
#[cfg(unix)]
fn prompt_password_with_pinentry_reads_password() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-ok.sh");
    write_script(
        &script,
        "#!/bin/sh\nprintf 'OK ready\\n'\nwhile IFS= read -r line; do\n  case \"$line\" in\n    GETPIN) printf 'D from%%0apinentry\\nOK\\n' ;;\n    BYE) printf 'OK\\n'; exit 0 ;;\n    *) printf 'OK\\n' ;;\n  esac\ndone\n",
    );

    let password = prompt_password_with_pinentry(
        &script.display().to_string(),
        "Master Password",
        Some("invalid password"),
        "Prompt description",
    )
    .expect("pinentry password");

    assert_eq!(password, "from\npinentry");
}

#[test]
#[cfg(unix)]
fn prompt_password_with_pinentry_sends_expected_option_commands() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("TERM", "xterm-256color");
    crate::lpenv::set_override_for_tests("DISPLAY", ":99");
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-log.sh");
    let log = temp.path().join("pinentry.log");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\nprintf 'OK ready\\n'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    GETPIN) printf 'D pass\\nOK\\n' ;;\n    BYE) printf 'OK\\n'; exit 0 ;;\n    *) printf 'OK\\n' ;;\n  esac\ndone\n",
            log.display()
        ),
    );

    let password = prompt_password_with_pinentry(
        &script.display().to_string(),
        "Master Password",
        Some("bad password"),
        "Prompt description",
    )
    .expect("pinentry password");

    assert_eq!(password, "pass");
    let transcript = std::fs::read_to_string(&log).expect("log");
    assert!(transcript.contains("SETTITLE LastPass CLI"));
    assert!(transcript.contains("SETPROMPT Master Password:"));
    assert!(transcript.contains("SETERROR bad password"));
    assert!(transcript.contains("SETDESC Prompt description"));
    assert!(transcript.contains("OPTION ttytype=xterm-256color"));
    assert!(transcript.contains("OPTION display=:99"));
    #[cfg(target_os = "linux")]
    {
        if std::io::stdin().is_terminal() {
            assert!(transcript.contains("OPTION ttyname="));
        } else {
            assert!(!transcript.contains("OPTION ttyname="));
        }
    }
    #[cfg(not(target_os = "linux"))]
    assert!(!transcript.contains("OPTION ttyname="));
    assert!(transcript.contains("GETPIN"));
    assert!(transcript.contains("BYE"));
}

#[test]
#[cfg(unix)]
fn prompt_password_with_pinentry_reports_bad_protocol() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-bad.sh");
    write_script(&script, "#!/bin/sh\nprintf 'ERR no\\n'\n");

    let err = prompt_password_with_pinentry(
        &script.display().to_string(),
        "Master Password",
        None,
        "Prompt description",
    )
    .expect_err("pinentry must fail");

    assert!(matches!(err, PinentryError::Failed));
}

#[test]
#[cfg(unix)]
fn prompt_password_with_description_uses_pinentry_success_path() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-wrapper-ok.sh");
    write_script(
        &script,
        "#!/bin/sh\nprintf 'OK ready\\n'\nwhile IFS= read -r line; do\n  case \"$line\" in\n    GETPIN) printf 'D wrapper-pass\\nOK\\n' ;;\n    BYE) printf 'OK\\n'; exit 0 ;;\n    *) printf 'OK\\n' ;;\n  esac\ndone\n",
    );
    crate::lpenv::set_override_for_tests("LPASS_PINENTRY", &script.display().to_string());

    let mut prompt = |_| panic!("tty fallback must not be used");
    let password = prompt_password_with_description_and_tty(
        "Master Password",
        None,
        "Prompt description",
        &mut prompt,
    )
    .expect("pinentry password");

    assert_eq!(password, "wrapper-pass");
}

#[test]
#[cfg(unix)]
fn prompt_password_with_pinentry_reports_invalid_getpin_response() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-invalid-data.sh");
    write_script(
        &script,
        "#!/bin/sh\nprintf 'OK ready\\n'\nwhile IFS= read -r line; do\n  case \"$line\" in\n    GETPIN) printf 'ERR failed\\n' ;;\n    BYE) printf 'OK\\n'; exit 0 ;;\n    *) printf 'OK\\n' ;;\n  esac\ndone\n",
    );

    let err = prompt_password_with_pinentry(
        &script.display().to_string(),
        "Master Password",
        None,
        "Prompt description",
    )
    .expect_err("pinentry must fail");

    assert!(matches!(err, PinentryError::Failed));
}

#[test]
#[cfg(unix)]
fn prompt_password_with_pinentry_reports_unexpected_eof() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-eof.sh");
    write_script(&script, "#!/bin/sh\nprintf 'OK ready\\n'\nexit 0\n");

    let err = prompt_password_with_pinentry(
        &script.display().to_string(),
        "Master Password",
        None,
        "Prompt description",
    )
    .expect_err("pinentry eof must fail");

    assert!(matches!(err, PinentryError::Failed));
}

#[test]
#[cfg(target_os = "linux")]
fn prompt_password_with_pinentry_reaps_child_after_error() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-reap.sh");
    let pidfile = temp.path().join("pinentry.pid");
    write_script(
        &script,
        &format!(
            "#!/bin/sh\necho $$ > '{}'\nprintf 'OK ready\\n'\nIFS= read -r _ || exit 0\nexit 0\n",
            pidfile.display()
        ),
    );

    let err = prompt_password_with_pinentry(
        &script.display().to_string(),
        "Master Password",
        None,
        "Prompt description",
    )
    .expect_err("pinentry must fail");
    assert!(matches!(err, PinentryError::Failed));

    let pid = std::fs::read_to_string(&pidfile)
        .expect("pidfile")
        .trim()
        .parse::<u32>()
        .expect("numeric pid");

    for _ in 0..50 {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("pinentry child was not reaped");
}

#[test]
#[cfg(unix)]
fn prompt_password_with_description_reports_failed_pinentry_without_fallback() {
    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let script = temp.path().join("pinentry-fail.sh");
    write_script(&script, "#!/bin/sh\nprintf 'ERR fail\\n'\n");
    crate::lpenv::set_override_for_tests("LPASS_PINENTRY", &script.display().to_string());

    let mut prompt = |_| Ok("fallback".to_string());
    let err = prompt_password_with_description_and_tty(
        "Master Password",
        None,
        "Prompt description",
        &mut prompt,
    )
    .expect_err("pinentry must fail");

    assert!(format!("{err}").contains("pinentry failed"));
}

#[test]
fn prompt_password_with_pinentry_reports_missing_program_as_unavailable() {
    let err = prompt_password_with_pinentry(
        "/path/that/does/not/exist",
        "Master Password",
        None,
        "Prompt description",
    )
    .expect_err("pinentry must be unavailable");

    assert!(matches!(err, PinentryError::Unavailable));
}

#[test]
fn take_pinentry_stdio_reports_missing_stdin() {
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn child");
    let err = take_pinentry_stdio(&mut child).expect_err("missing stdin");
    let _ = child.wait();
    assert!(matches!(err, PinentryError::Failed));
}

#[test]
fn take_pinentry_stdio_reports_missing_stdout() {
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn child");
    let err = take_pinentry_stdio(&mut child).expect_err("missing stdout");
    let _ = child.wait();
    assert!(matches!(err, PinentryError::Failed));
}
