#![forbid(unsafe_code)]

use std::path::PathBuf;

pub fn create_secure_temp_file() -> Result<tempfile::NamedTempFile, String> {
    create_secure_temp_file_in(&secure_temp_dir())
}

pub fn editor_program() -> String {
    crate::lpenv::var("VISUAL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            crate::lpenv::var("EDITOR")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "vi".to_string())
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn create_secure_temp_file_in(dir: &std::path::Path) -> Result<tempfile::NamedTempFile, String> {
    tempfile::Builder::new()
        .prefix("lpass.")
        .tempfile_in(dir)
        .map_err(|err| format!("mkstemp: {err}"))
}

#[cfg(target_os = "linux")]
fn secure_temp_dir() -> PathBuf {
    PathBuf::from("/dev/shm")
}

#[cfg(not(target_os = "linux"))]
fn secure_temp_dir() -> PathBuf {
    secure_temp_dir_from_env(
        crate::lpenv::var_os("SECURE_TMPDIR").map(PathBuf::from),
        crate::lpenv::var_os("TMPDIR").map(PathBuf::from),
    )
}

#[cfg(not(target_os = "linux"))]
fn secure_temp_dir_from_env(secure_tmpdir: Option<PathBuf>, tmpdir: Option<PathBuf>) -> PathBuf {
    secure_tmpdir
        .or(tmpdir)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_program_prefers_visual_then_editor_then_vi() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("VISUAL", "");
        crate::lpenv::set_override_for_tests("EDITOR", "");

        assert_eq!(editor_program(), "vi");

        crate::lpenv::set_override_for_tests("EDITOR", "nano");
        assert_eq!(editor_program(), "nano");

        crate::lpenv::set_override_for_tests("VISUAL", "vim");
        assert_eq!(editor_program(), "vim");
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn create_secure_temp_file_uses_expected_base_dir() {
        let file = create_secure_temp_file().expect("temp file");
        #[cfg(target_os = "linux")]
        assert!(file.path().starts_with("/dev/shm"));
        #[cfg(not(target_os = "linux"))]
        assert!(file.path().starts_with(secure_temp_dir()));
    }

    #[test]
    fn create_secure_temp_file_in_reports_errors() {
        let err =
            create_secure_temp_file_in(std::path::Path::new("/path/that/does/not/exist"))
                .expect_err("temp file must fail");
        assert!(err.contains("mkstemp"));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn secure_temp_dir_prefers_secure_tmpdir_then_tmpdir() {
        let _guard = crate::lpenv::begin_test_overrides();
        assert_eq!(secure_temp_dir_from_env(None, None), PathBuf::from("/tmp"));
        crate::lpenv::set_override_for_tests("TMPDIR", "/tmp/one");
        assert_eq!(secure_temp_dir(), PathBuf::from("/tmp/one"));
        crate::lpenv::set_override_for_tests("SECURE_TMPDIR", "/tmp/two");
        assert_eq!(secure_temp_dir(), PathBuf::from("/tmp/two"));
    }
}
