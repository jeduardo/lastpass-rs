#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn log(level: i32, message: &str) {
    if !enabled(level) {
        return;
    }

    let Ok(path) = crate::config::config_path("lpass.log") else {
        return;
    };
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let _ = writeln!(
        file,
        "<{level}> [{}.{:06}] {message}",
        timestamp.as_secs(),
        timestamp.subsec_micros()
    );
}

pub fn enabled(level: i32) -> bool {
    configured_level().is_some_and(|configured| configured >= level)
}

fn configured_level() -> Option<i32> {
    crate::lpenv::var("LPASS_LOG_LEVEL")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;
    use crate::config::{ConfigEnv, ConfigStore, set_test_env};

    #[test]
    fn enabled_respects_configured_level() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "4");
        assert!(enabled(3));
        assert!(enabled(4));
        assert!(!enabled(5));
    }

    #[test]
    fn enabled_ignores_invalid_level() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "nope");
        assert!(!enabled(1));
    }

    #[test]
    fn log_writes_expected_file() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "7");
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        log(5, "Making request to login.php");

        let content = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        })
        .read_string("lpass.log")
        .expect("read log")
        .expect("log file");
        assert!(content.contains("Making request to login.php"));
        assert!(content.starts_with("<5> ["));
    }

    #[test]
    fn log_is_noop_when_below_threshold() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "3");
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        log(5, "ignored");

        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        assert_eq!(store.read_string("lpass.log").expect("read"), None);
    }

    #[test]
    #[cfg(unix)]
    fn log_ignores_config_path_failures() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "7");
        let temp = TempDir::new().expect("tempdir");
        let loop_path = temp.path().join("loop");
        symlink(&loop_path, &loop_path).expect("symlink loop");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(loop_path),
            ..ConfigEnv::default()
        });

        log(5, "ignored");
    }

    #[test]
    fn log_ignores_open_failures() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "7");
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        std::fs::create_dir_all(temp.path().join("lpass.log")).expect("directory at log path");
        log(5, "ignored");
    }
}
