#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::env::VarError;
use std::ffi::{OsStr, OsString};
use std::sync::{OnceLock, RwLock};

use crate::config::config_read_string;

static OVERRIDES: OnceLock<RwLock<HashMap<OsString, OsString>>> = OnceLock::new();

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
    use std::ffi::OsString;

    #[test]
    fn overlay_var_prefers_saved_values() {
        clear_overrides_for_tests();
        set_override_for_tests("LPASS_TEST_ENV", "saved");
        assert_eq!(var("LPASS_TEST_ENV").as_deref(), Ok("saved"));
        clear_overrides_for_tests();
    }

    #[test]
    fn var_returns_not_present_when_missing() {
        clear_overrides_for_tests();
        let err = var("LPASS_MISSING_ENV").expect_err("missing value");
        assert!(matches!(err, VarError::NotPresent));
    }

    #[test]
    fn var_os_returns_override_value() {
        clear_overrides_for_tests();
        set_override_for_tests("LPASS_OS_ENV", "value");
        assert_eq!(var_os("LPASS_OS_ENV"), Some(OsString::from("value")));
        clear_overrides_for_tests();
    }
}
