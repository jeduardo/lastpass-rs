#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

fn write_askpass_script(temp: &TempDir, output: &str) -> std::path::PathBuf {
    let path = temp.path().join("askpass.sh");
    fs::write(&path, format!("#!/bin/sh\necho {output}\n")).expect("write askpass");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod askpass");
    path
}

fn run_helper(test_name: &str, askpass: &std::path::Path) {
    let output = Command::new(std::env::current_exe().expect("current exe"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env("LPASS_PASSWORD_HELPER", "1")
        .env("LPASS_ASKPASS", askpass)
        .output()
        .expect("run helper");

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn public_prompt_password_wrapper_uses_askpass() {
    if std::env::var_os("LPASS_PASSWORD_HELPER").is_some() {
        let password = lpass_core::password::prompt_password("user@example.com")
            .expect("prompt password through askpass");
        assert_eq!(password, "public-wrapper");
        return;
    }

    let temp = TempDir::new().expect("tempdir");
    let askpass = write_askpass_script(&temp, "public-wrapper");
    run_helper("public_prompt_password_wrapper_uses_askpass", &askpass);
}

#[test]
fn public_prompt_password_with_description_wrapper_uses_askpass() {
    if std::env::var_os("LPASS_PASSWORD_HELPER").is_some() {
        let password = lpass_core::password::prompt_password_with_description(
            "Master Password",
            None,
            "Prompt description",
        )
        .expect("prompt password with description through askpass");
        assert_eq!(password, "description-wrapper");
        return;
    }

    let temp = TempDir::new().expect("tempdir");
    let askpass = write_askpass_script(&temp, "description-wrapper");
    run_helper(
        "public_prompt_password_with_description_wrapper_uses_askpass",
        &askpass,
    );
}
