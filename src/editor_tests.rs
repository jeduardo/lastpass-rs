use super::*;
use tempfile::TempDir;

#[test]
fn shell_quote_escapes_single_quotes() {
    assert_eq!(shell_quote("a'b"), "'a'\\''b'");
}

#[test]
fn resolve_editor_prefers_visual_then_editor_then_vi() {
    assert_eq!(resolve_editor_from(None, None), "vi");
    assert_eq!(resolve_editor_from(None, Some("nano".to_string())), "nano");
    assert_eq!(
        resolve_editor_from(Some("vim".to_string()), Some("nano".to_string())),
        "vim"
    );
    assert_eq!(
        resolve_editor_from(Some("   ".to_string()), Some("nano".to_string())),
        "nano"
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn secure_temp_base_dir_matches_c_linux_behavior() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("SECURE_TMPDIR", "/tmp/ignored");
    assert_eq!(secure_temp_base_dir(), std::path::PathBuf::from("/dev/shm"));
}

#[cfg(target_os = "macos")]
#[test]
fn secure_temp_base_dir_prefers_secure_tmpdir_on_macos() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("SECURE_TMPDIR", "/tmp/secure");
    assert_eq!(
        secure_temp_base_dir(),
        std::path::PathBuf::from("/tmp/secure")
    );
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
#[test]
fn secure_temp_base_dir_prefers_secure_tmpdir_else_tmpdir() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("SECURE_TMPDIR", "/tmp/secure");
    assert_eq!(
        secure_temp_base_dir(),
        std::path::PathBuf::from("/tmp/secure")
    );

    crate::lpenv::clear_overrides_for_tests();
    crate::lpenv::set_override_for_tests("TMPDIR", "/tmp/fallback");
    assert_eq!(
        secure_temp_base_dir(),
        std::path::PathBuf::from("/tmp/fallback")
    );
}

#[cfg(unix)]
#[test]
fn edit_with_editor_runs_selected_editor_and_reads_back_contents() {
    use std::os::unix::fs::PermissionsExt;

    let _guard = crate::lpenv::begin_test_overrides();
    let temp = TempDir::new().expect("tempdir");
    let capture = temp.path().join("edited.txt");
    let script = temp.path().join("editor.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nset -eu\nprintf '%s' \"$1\" > '{}'\nprintf 'updated' > \"$1\"\n",
            capture.display()
        ),
    )
    .expect("write editor");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
        .expect("chmod editor");
    crate::lpenv::set_override_for_tests("EDITOR", &script.display().to_string());

    let value = edit_with_editor("initial").expect("edit");

    assert_eq!(value, "updated");
    let edited_path = std::fs::read_to_string(capture).expect("read capture");
    assert!(edited_path.contains("/lpass."));
}
