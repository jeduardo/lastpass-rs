#![forbid(unsafe_code)]

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LpassError {
    #[error("IO error while {context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("crypto error: {0}")]
    Crypto(&'static str),
    #[error("invalid iteration count: {0}")]
    InvalidIterations(u32),
    #[error("HOME is not set")]
    MissingHome,
    #[error("invalid utf-8 data")]
    InvalidUtf8,
    #[error("{0}")]
    User(&'static str),
}

pub type Result<T> = std::result::Result<T, LpassError>;

impl LpassError {
    pub fn io(context: &'static str, source: io::Error) -> Self {
        Self::Io { context, source }
    }
}
