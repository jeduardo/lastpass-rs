use super::*;
use crate::config::{ConfigEnv, config_path, set_test_env};
use tempfile::TempDir;

#[test]
fn log_level_defaults_to_none_and_parses_env_values() {
    let _guard = crate::lpenv::begin_test_overrides();
    assert_eq!(log_level(), LOG_NONE);

    crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "7");
    assert_eq!(log_level(), LOG_DEBUG);

    crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "bogus");
    assert_eq!(log_level(), 0);
}

#[test]
fn enabled_requires_requested_level() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "6");
    assert!(enabled(LOG_INFO));
    assert!(!enabled(LOG_DEBUG));
}

#[test]
fn log_writes_formatted_messages_to_lpass_log() {
    let _guard = crate::lpenv::begin_test_overrides();
    let home = TempDir::new().expect("tempdir");
    let _config_guard = set_test_env(ConfigEnv {
        lpass_home: Some(home.path().to_path_buf()),
        ..ConfigEnv::default()
    });
    crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "7");

    log(LOG_DEBUG, "Making request to https://example.com/\n");

    let path = config_path("lpass.log").expect("log path");
    let text = std::fs::read_to_string(path).expect("read log");
    assert!(text.contains("<7> ["));
    assert!(text.contains("Making request to https://example.com/"));
}

#[test]
fn log_ignores_messages_below_threshold() {
    let _guard = crate::lpenv::begin_test_overrides();
    let home = TempDir::new().expect("tempdir");
    let _config_guard = set_test_env(ConfigEnv {
        lpass_home: Some(home.path().to_path_buf()),
        ..ConfigEnv::default()
    });
    crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "3");

    log(LOG_DEBUG, "debug line\n");

    let path = config_path("lpass.log").expect("log path");
    assert!(
        !path.exists() || std::fs::read_to_string(path).expect("read log").is_empty(),
        "debug log should not be written at error level"
    );
}

#[test]
fn log_returns_when_config_path_cannot_be_created() {
    let _guard = crate::lpenv::begin_test_overrides();
    let _config_guard = set_test_env(ConfigEnv::default());
    crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "7");

    log(LOG_DEBUG, "this should be ignored\n");
}

#[test]
fn log_returns_when_log_path_is_a_directory() {
    let _guard = crate::lpenv::begin_test_overrides();
    let home = TempDir::new().expect("tempdir");
    let _config_guard = set_test_env(ConfigEnv {
        lpass_home: Some(home.path().to_path_buf()),
        ..ConfigEnv::default()
    });
    crate::lpenv::set_override_for_tests("LPASS_LOG_LEVEL", "7");

    let path = config_path("lpass.log").expect("log path");
    std::fs::create_dir_all(&path).expect("mkdir log path");

    log(LOG_DEBUG, "this should also be ignored\n");
}
