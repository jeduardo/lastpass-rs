#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env::VarError;
use std::ffi::{OsStr, OsString};
use std::sync::{OnceLock, RwLock};

use crate::config::config_read_string;

static OVERRIDES: OnceLock<RwLock<HashMap<OsString, OsString>>> = OnceLock::new();
#[cfg(test)]
static TEST_OVERRIDE_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

fn overrides() -> &'static RwLock<HashMap<OsString, OsString>> {
    OVERRIDES.get_or_init(|| RwLock::new(HashMap::new()))
}

fn with_read_overrides<T>(f: impl FnOnce(&HashMap<OsString, OsString>) -> T) -> T {
    match overrides().read() {
        Ok(guard) => f(&guard),
        Err(poisoned) => {
            let guard = poisoned.into_inner();
            f(&guard)
        }
    }
}

fn with_write_overrides(f: impl FnOnce(&mut HashMap<OsString, OsString>)) {
    match overrides().write() {
        Ok(mut guard) => f(&mut guard),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            f(&mut guard);
        }
    }
}

pub fn var_os<K: AsRef<OsStr>>(name: K) -> Option<OsString> {
    let key = name.as_ref().to_os_string();
    if let Some(value) = with_read_overrides(|map| map.get(&key).cloned()) {
        return Some(value);
    }
    std::env::var_os(key)
}

pub fn var(name: &str) -> Result<String, VarError> {
    match var_os(name) {
        Some(value) => value.into_string().map_err(VarError::NotUnicode),
        None => Err(VarError::NotPresent),
    }
}

pub fn reload_saved_environment() -> Result<(), String> {
    with_write_overrides(|map| map.clear());

    let env_value = match config_read_string("env") {
        Ok(Some(value)) => value,
        Ok(None) => return Ok(()),
        Err(err) => return Err(format!("{err}")),
    };

    let mut entries: Vec<(OsString, OsString)> = Vec::new();
    for line in env_value.split('\n') {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            warn_invalid_env_line(line);
            continue;
        };
        if name.is_empty() {
            warn_invalid_env_line(line);
            continue;
        }
        entries.push((OsString::from(name), OsString::from(value)));
    }

    with_write_overrides(|map| {
        for (name, value) in entries {
            map.insert(name, value);
        }
    });

    Ok(())
}

fn warn_invalid_env_line(line: &str) {
    eprintln!("warning: The environment line '{line}' is invalid.");
}

#[cfg(test)]
pub(crate) struct TestOverrideGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

#[cfg(test)]
pub(crate) fn begin_test_overrides() -> TestOverrideGuard {
    let lock = TEST_OVERRIDE_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    let guard = match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    with_write_overrides(|map| map.clear());
    TestOverrideGuard(guard)
}

#[cfg(test)]
impl Drop for TestOverrideGuard {
    fn drop(&mut self) {
        with_write_overrides(|map| map.clear());
    }
}

#[cfg(test)]
pub(crate) fn set_override_for_tests(name: &str, value: &str) {
    with_write_overrides(|map| {
        map.insert(OsString::from(name), OsString::from(value));
    });
}

#[cfg(test)]
pub(crate) fn clear_overrides_for_tests() {
    with_write_overrides(|map| map.clear());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigEnv, config_path, config_write_string, set_test_env};
    use std::ffi::OsString;
    use tempfile::TempDir;

    #[test]
    fn overlay_var_prefers_saved_values() {
        let _guard = begin_test_overrides();
        set_override_for_tests("LPASS_TEST_ENV", "saved");
        assert_eq!(var("LPASS_TEST_ENV").as_deref(), Ok("saved"));
    }

    #[test]
    fn var_returns_not_present_when_missing() {
        let _guard = begin_test_overrides();
        let err = var("LPASS_MISSING_ENV").expect_err("missing value");
        assert!(matches!(err, VarError::NotPresent));
    }

    #[test]
    fn var_os_returns_override_value() {
        let _guard = begin_test_overrides();
        set_override_for_tests("LPASS_OS_ENV", "value");
        assert_eq!(var_os("LPASS_OS_ENV"), Some(OsString::from("value")));
    }

    #[test]
    fn clear_overrides_removes_values() {
        let _guard = begin_test_overrides();
        set_override_for_tests("LPASS_CLEAR_ENV", "value");
        clear_overrides_for_tests();
        assert!(matches!(var("LPASS_CLEAR_ENV"), Err(VarError::NotPresent)));
    }

    #[test]
    fn reload_saved_environment_parses_valid_lines() {
        let _override_guard = begin_test_overrides();
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        config_write_string(
            "env",
            "LPASS_FIRST=one\ninvalid-line\n=missing-name\nLPASS_SECOND=two=parts\n",
        )
        .expect("write env");
        reload_saved_environment().expect("reload");

        assert_eq!(var("LPASS_FIRST").as_deref(), Ok("one"));
        assert_eq!(var("LPASS_SECOND").as_deref(), Ok("two=parts"));
        assert!(matches!(var("invalid-line"), Err(VarError::NotPresent)));
    }

    #[test]
    fn reload_saved_environment_surfaces_read_errors() {
        let _override_guard = begin_test_overrides();
        let temp = TempDir::new().expect("tempdir");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let env_path = config_path("env").expect("env path");
        std::fs::create_dir_all(&env_path).expect("make env dir");
        let err = reload_saved_environment().expect_err("must fail");
        assert!(err.contains("IO error while read"), "err: {err}");
    }

    #[test]
    #[cfg(unix)]
    fn var_reports_not_unicode_for_invalid_override() {
        use std::os::unix::ffi::OsStringExt;

        let _guard = begin_test_overrides();
        with_write_overrides(|map| {
            map.insert(
                OsString::from("LPASS_BAD_UTF8"),
                OsString::from_vec(vec![0x66, 0x6f, 0x80]),
            );
        });
        let err = var("LPASS_BAD_UTF8").expect_err("expected utf8 error");
        assert!(matches!(err, VarError::NotUnicode(_)));
    }
}
