use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use lpass_core::blob::{Attachment, Blob};
use lpass_core::crypto::{aes_encrypt_lastpass, base64_lastpass_encode};
use lpass_core::kdf::KDF_HASH_LEN;

static NEXT_TEST_HOME_ID: AtomicU64 = AtomicU64::new(0);
const MOCK_ATTACH_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const MOCK_ATTACH_STORAGE_KEY_TEXT: &str = "mock-storage-0001-text";
const MOCK_ATTACH_STORAGE_KEY_BIN: &str = "mock-storage-0001-bin";

fn unique_test_home() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    let seq = NEXT_TEST_HOME_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "lpass-show-compat-{}-{nanos}-{seq}",
        std::process::id()
    ))
}

fn run(home: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> std::process::Output {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut command = Command::new(exe);
    command.env("LPASS_HTTP_MOCK", "1");
    command.env("LPASS_HOME", home);
    command.current_dir(home);
    for (name, value) in extra_env {
        command.env(name, value);
    }
    command.args(args);
    command.output().expect("run command")
}

fn run_with_input(
    home: &Path,
    args: &[&str],
    extra_env: &[(&str, &str)],
    input: &str,
) -> std::process::Output {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let mut command = Command::new(exe);
    command.env("LPASS_HTTP_MOCK", "1");
    command.env("LPASS_HOME", home);
    command.current_dir(home);
    for (name, value) in extra_env {
        command.env(name, value);
    }
    command.args(args);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn command");
    {
        let stdin = child.stdin.as_mut().expect("stdin available");
        stdin.write_all(input.as_bytes()).expect("write stdin");
    }
    child.wait_with_output().expect("wait output")
}

#[cfg(unix)]
fn write_askpass(home: &Path, content: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let askpass = home.join("askpass.sh");
    fs::write(&askpass, content).expect("write askpass");
    fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).expect("chmod askpass");
    askpass
}

fn inject_mock_attachments(home: &Path) {
    let blob_path = home.join("blob");
    let blob_text = fs::read_to_string(&blob_path).expect("read mock blob");
    let mut blob: Blob = serde_json::from_str(&blob_text).expect("parse mock blob");

    let account = blob
        .accounts
        .iter_mut()
        .find(|account| account.id == "0001")
        .expect("existing account");
    account.attachpresent = true;
    account.attachkey = MOCK_ATTACH_KEY_HEX.to_string();

    let decoded = hex::decode(MOCK_ATTACH_KEY_HEX).expect("decode attach key");
    let mut key = [0u8; KDF_HASH_LEN];
    key.copy_from_slice(&decoded);

    let filename_cipher = |name: &str| {
        let encrypted = aes_encrypt_lastpass(name.as_bytes(), &key).expect("encrypt filename");
        base64_lastpass_encode(&encrypted)
    };

    blob.attachments
        .retain(|attachment| attachment.parent != "0001");
    blob.attachments.push(Attachment {
        id: "1".to_string(),
        parent: "0001".to_string(),
        mimetype: "text/plain".to_string(),
        storagekey: MOCK_ATTACH_STORAGE_KEY_TEXT.to_string(),
        size: "4".to_string(),
        filename: filename_cipher("mock.txt"),
    });
    blob.attachments.push(Attachment {
        id: "2".to_string(),
        parent: "0001".to_string(),
        mimetype: "application/octet-stream".to_string(),
        storagekey: MOCK_ATTACH_STORAGE_KEY_BIN.to_string(),
        size: "3".to_string(),
        filename: filename_cipher("mock.bin"),
    });

    let updated = serde_json::to_vec_pretty(&blob).expect("serialize mock blob");
    fs::write(&blob_path, updated).expect("write mock blob");
}

#[test]
fn show_accepts_password_short_option_after_name() {
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");

    let output = run(&test_home, &["show", "test-account", "-p", "password"], &[]);

    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "test-account-password\n"
    );

    let _ = fs::remove_dir_all(&test_home);
}

#[test]
fn show_password_short_option_works_with_shared_style_fullname() {
    let exe = env!("CARGO_BIN_EXE_lpass");
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");

    let fullname = "Shared-Team/Infrastructure/Service API Token";
    let password = "service-api-token";

    let mut add = Command::new(exe)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_HOME", &test_home)
        .args(["add", "--sync=no", "--non-interactive", fullname])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lpass add");
    {
        let stdin = add.stdin.as_mut().expect("stdin available");
        writeln!(stdin, "Password: {password}").expect("write add stdin");
    }
    let add_output = add.wait_with_output().expect("wait add output");
    assert_eq!(
        add_output.status.code().unwrap_or(-1),
        0,
        "add stderr: {}",
        String::from_utf8_lossy(&add_output.stderr)
    );

    let show_output = Command::new(exe)
        .env("LPASS_HTTP_MOCK", "1")
        .env("LPASS_HOME", &test_home)
        .args(["show", fullname, "-p", "password"])
        .output()
        .expect("run lpass show");

    assert_eq!(
        show_output.status.code().unwrap_or(-1),
        0,
        "show stderr: {}",
        String::from_utf8_lossy(&show_output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&show_output.stdout),
        format!("{password}\n")
    );

    let _ = fs::remove_dir_all(&test_home);
}

#[test]
fn show_search_modes_and_expand_multi_follow_c_behavior() {
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");

    let regex = run(
        &test_home,
        &[
            "show",
            "--sync=no",
            "--basic-regexp",
            "--id",
            "^TEST-GROUP/TEST-ACCOUNT$",
        ],
        &[],
    );
    assert_eq!(
        regex.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&regex.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&regex.stdout), "0001\n");

    let invalid_regex = run(
        &test_home,
        &["show", "--sync=no", "--basic-regexp", "["],
        &[],
    );
    assert_eq!(invalid_regex.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&invalid_regex.stderr).contains("Invalid regex '['"),
        "stderr: {}",
        String::from_utf8_lossy(&invalid_regex.stderr)
    );

    let multi = run(
        &test_home,
        &["show", "--sync=no", "--fixed-strings", "test-group/test-"],
        &[],
    );
    assert_eq!(multi.status.code().unwrap_or(-1), 0);
    let multi_stdout = String::from_utf8_lossy(&multi.stdout);
    assert!(
        multi_stdout.contains("Multiple matches found."),
        "{multi_stdout}"
    );
    assert!(multi_stdout.contains("[id: 0001]"), "{multi_stdout}");

    let expanded = run(
        &test_home,
        &[
            "show",
            "--sync=no",
            "--id",
            "--expand-multi",
            "test-group/test-account",
            "test-group/test-note",
        ],
        &[],
    );
    assert_eq!(expanded.status.code().unwrap_or(-1), 0);
    let expanded_stdout = String::from_utf8_lossy(&expanded.stdout);
    assert!(expanded_stdout.contains("0001"), "{expanded_stdout}");
    assert!(expanded_stdout.contains("0002"), "{expanded_stdout}");

    let _ = fs::remove_dir_all(&test_home);
}

#[test]
fn show_clip_uses_clipboard_command_and_suppresses_stdout() {
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");
    let clip_file = test_home.join("clip.out");
    let clip_command = format!("cat > {}", clip_file.display());

    let output = run(
        &test_home,
        &[
            "show",
            "--sync=no",
            "--password",
            "--clip",
            "test-group/test-account",
        ],
        &[("LPASS_CLIPBOARD_COMMAND", clip_command.as_str())],
    );
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let copied = fs::read_to_string(&clip_file).expect("read clipboard file");
    assert_eq!(copied, "test-account-password");

    let _ = fs::remove_dir_all(&test_home);
}

#[test]
fn show_json_clip_copies_json_and_suppresses_stdout() {
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");
    let clip_file = test_home.join("clip-json.out");
    let clip_command = format!("cat > {}", clip_file.display());

    let output = run(
        &test_home,
        &[
            "show",
            "--sync=no",
            "--json",
            "--clip",
            "test-group/test-account",
        ],
        &[("LPASS_CLIPBOARD_COMMAND", clip_command.as_str())],
    );
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let copied = fs::read_to_string(&clip_file).expect("read clipboard file");
    assert!(copied.contains("\"name\": \"test-account\""), "{copied}");

    let _ = fs::remove_dir_all(&test_home);
}

#[cfg(unix)]
#[test]
fn show_attach_downloads_mock_attachment_after_login() {
    let test_home = unique_test_home();
    fs::create_dir_all(&test_home).expect("create test home");
    let askpass = write_askpass(&test_home, "#!/bin/sh\necho 123456\n");

    let login = run(
        &test_home,
        &[
            "login",
            "--trust",
            "--plaintext-key",
            "--force",
            "user@example.com",
        ],
        &[("LPASS_ASKPASS", askpass.to_str().expect("path"))],
    );
    assert_eq!(
        login.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&login.stderr)
    );
    inject_mock_attachments(&test_home);

    let show_attach = run(
        &test_home,
        &[
            "show",
            "--sync=no",
            "--attach=att-1",
            "test-group/test-account",
        ],
        &[],
    );
    assert_eq!(
        show_attach.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&show_attach.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&show_attach.stdout), "demo");

    let show_attach_missing = run(
        &test_home,
        &["show", "--sync=no", "--attach=9", "test-group/test-account"],
        &[],
    );
    assert_eq!(show_attach_missing.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&show_attach_missing.stderr)
            .contains("Could not find specified attachment '9'"),
        "stderr: {}",
        String::from_utf8_lossy(&show_attach_missing.stderr)
    );

    let show_attach_binary = run(
        &test_home,
        &["show", "--sync=no", "--attach=2", "test-group/test-account"],
        &[],
    );
    assert_eq!(show_attach_binary.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&show_attach_binary.stderr).contains("aborted response."),
        "stderr: {}",
        String::from_utf8_lossy(&show_attach_binary.stderr)
    );

    let show_attach_binary_print = run_with_input(
        &test_home,
        &["show", "--sync=no", "--attach=2", "test-group/test-account"],
        &[],
        "y\n",
    );
    assert_eq!(show_attach_binary_print.status.code().unwrap_or(-1), 0);
    assert_eq!(show_attach_binary_print.stdout, vec![0, 1, 2]);

    let show_attach_binary_skip = run_with_input(
        &test_home,
        &["show", "--sync=no", "--attach=2", "test-group/test-account"],
        &[],
        "n\n",
    );
    assert_eq!(show_attach_binary_skip.status.code().unwrap_or(-1), 0);
    assert!(show_attach_binary_skip.stdout.is_empty());

    let show_attach_binary_save = run_with_input(
        &test_home,
        &["show", "--sync=no", "--attach=2", "test-group/test-account"],
        &[],
        "\n",
    );
    assert_eq!(show_attach_binary_save.status.code().unwrap_or(-1), 0);
    assert!(show_attach_binary_save.stdout.is_empty());
    assert_eq!(
        fs::read(test_home.join("mock.bin")).expect("read saved attachment"),
        vec![0, 1, 2]
    );
    assert!(
        String::from_utf8_lossy(&show_attach_binary_save.stderr).contains("Wrote 3 bytes"),
        "stderr: {}",
        String::from_utf8_lossy(&show_attach_binary_save.stderr)
    );

    let show_attach_binary_retry = run_with_input(
        &test_home,
        &["show", "--sync=no", "--attach=2", "test-group/test-account"],
        &[],
        "bad\ny\n",
    );
    assert_eq!(show_attach_binary_retry.status.code().unwrap_or(-1), 0);
    assert_eq!(show_attach_binary_retry.stdout, vec![0, 1, 2]);
    assert!(
        String::from_utf8_lossy(&show_attach_binary_retry.stderr)
            .contains("Response not understood."),
        "stderr: {}",
        String::from_utf8_lossy(&show_attach_binary_retry.stderr)
    );

    let show_attach_binary_quiet = run(
        &test_home,
        &[
            "show",
            "--sync=no",
            "--quiet",
            "--attach=2",
            "test-group/test-account",
        ],
        &[],
    );
    assert_eq!(show_attach_binary_quiet.status.code().unwrap_or(-1), 0);
    assert_eq!(show_attach_binary_quiet.stdout, vec![0, 1, 2]);

    let show_pwprotect_ok = run(
        &test_home,
        &[
            "show",
            "--sync=no",
            "--password",
            "test-group/test-reprompt-account",
        ],
        &[("LPASS_ASKPASS", askpass.to_str().expect("path"))],
    );
    assert_eq!(
        show_pwprotect_ok.status.code().unwrap_or(-1),
        0,
        "stderr: {}",
        String::from_utf8_lossy(&show_pwprotect_ok.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&show_pwprotect_ok.stdout),
        "test-account-password\n"
    );

    let askpass_bad = write_askpass(
        &test_home,
        "#!/bin/sh\nif [ -e \"$LPASS_HOME/.askpass.lock\" ]; then exit 1; fi\ntouch \"$LPASS_HOME/.askpass.lock\"\necho wrong\n",
    );
    let show_pwprotect_fail = run(
        &test_home,
        &[
            "show",
            "--sync=no",
            "--password",
            "test-group/test-reprompt-account",
        ],
        &[("LPASS_ASKPASS", askpass_bad.to_str().expect("path"))],
    );
    assert_eq!(show_pwprotect_fail.status.code().unwrap_or(-1), 1);
    assert!(
        String::from_utf8_lossy(&show_pwprotect_fail.stderr)
            .contains("Could not authenticate for protected entry."),
        "stderr: {}",
        String::from_utf8_lossy(&show_pwprotect_fail.stderr)
    );

    let show_all = run(
        &test_home,
        &["show", "--sync=no", "test-group/test-account"],
        &[],
    );
    assert_eq!(show_all.status.code().unwrap_or(-1), 0);
    assert!(
        String::from_utf8_lossy(&show_all.stdout).contains("att-1: mock.txt"),
        "stdout: {}",
        String::from_utf8_lossy(&show_all.stdout)
    );
    assert!(
        String::from_utf8_lossy(&show_all.stdout).contains("att-2: mock.bin"),
        "stdout: {}",
        String::from_utf8_lossy(&show_all.stdout)
    );

    let _ = fs::remove_dir_all(&test_home);
}
