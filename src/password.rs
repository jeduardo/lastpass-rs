#![forbid(unsafe_code)]

use std::env;
use std::process::Command;

use crate::error::{LpassError, Result};

pub fn prompt_password(_username: &str) -> Result<String> {
    if let Ok(askpass) = env::var("LPASS_ASKPASS") {
        let output = Command::new(askpass)
            .output()
            .map_err(|err| LpassError::io("askpass", err))?;
        if !output.status.success() {
            return Err(LpassError::Crypto("askpass failed"));
        }
        let mut bytes = output.stdout;
        while matches!(bytes.last(), Some(b'\n') | Some(b'\r')) {
            bytes.pop();
        }
        let password = String::from_utf8_lossy(&bytes).to_string();
        return Ok(password);
    }
    Err(LpassError::Crypto("no askpass"))
}
