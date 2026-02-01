#![forbid(unsafe_code)]

use std::env;
use std::process::Command;

use crate::error::{LpassError, Result};

pub fn prompt_password(username: &str) -> Result<String> {
    let prompt = "Master Password";
    if let Ok(askpass) = env::var("LPASS_ASKPASS") {
        let output = Command::new(askpass)
            .arg(prompt)
            .output()
            .map_err(|err| LpassError::io("askpass", err))?;
        if !output.status.success() {
            return Err(LpassError::Crypto("askpass failed"));
        }
        return Ok(decode_password_output(output.stdout));
    }

    eprintln!(
        "Please enter the LastPass master password for <{}>.",
        username
    );
    rpassword::prompt_password(format!("{prompt}: "))
        .map_err(|err| LpassError::io("password prompt", err))
}

fn decode_password_output(mut bytes: Vec<u8>) -> String {
    while matches!(bytes.last(), Some(b'\n') | Some(b'\r')) {
        bytes.pop();
    }
    String::from_utf8_lossy(&bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::decode_password_output;

    #[test]
    fn decode_password_output_trims_trailing_newlines() {
        let raw = b"passphrase with spaces\r\n".to_vec();
        assert_eq!(decode_password_output(raw), "passphrase with spaces");
    }
}
