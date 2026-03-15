#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const LOG_NONE: i32 = -1;
pub const LOG_ERROR: i32 = 3;
pub const LOG_WARNING: i32 = 4;
pub const LOG_INFO: i32 = 6;
pub const LOG_DEBUG: i32 = 7;
pub const LOG_VERBOSE: i32 = 8;

#[inline(never)]
pub fn log_level() -> i32 {
    match crate::lpenv::var("LPASS_LOG_LEVEL") {
        Ok(value) => value.parse::<i32>().unwrap_or(0),
        Err(_) => LOG_NONE,
    }
}

#[inline(never)]
pub fn enabled(level: i32) -> bool {
    log_level() >= level
}

#[inline(never)]
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
        .unwrap_or(Duration::ZERO);
    let _ = write!(
        file,
        "<{level}> [{}.{:06}] {message}",
        timestamp.as_secs(),
        timestamp.subsec_micros()
    );
    let _ = file.flush();
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod tests;
