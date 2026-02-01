#![forbid(unsafe_code)]

pub fn version_string() -> String {
    format!("LastPass CLI v{}", env!("CARGO_PKG_VERSION"))
}
