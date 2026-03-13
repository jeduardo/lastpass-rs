#![forbid(unsafe_code)]

use std::io::Write;
use std::process::Command;

use crate::error::{LpassError, Result};

pub fn prompt_password(username: &str) -> Result<String> {
    prompt_password_with_description(
        "Master Password",
        None,
        &format!(
            "Please enter the LastPass master password for <{}>.",
            username
        ),
    )
}

pub fn prompt_password_with_description(
    prompt: &str,
    error: Option<&str>,
    description: &str,
) -> Result<String> {
    if let Some(askpass) = askpass_program_from_env() {
        return prompt_password_with_askpass(&askpass, prompt);
    }
    prompt_password_from_tty_with(prompt, error, description, rpassword::prompt_password)
}

fn prompt_password_with_askpass(askpass: &str, prompt: &str) -> Result<String> {
    let output = Command::new(askpass)
        .arg(prompt)
        .output()
        .map_err(|err| LpassError::io("askpass", err))?;
    if !output.status.success() {
        return Err(LpassError::Crypto("askpass failed"));
    }
    Ok(decode_password_output(output.stdout))
}

fn prompt_password_from_tty_with<F>(
    prompt: &str,
    error: Option<&str>,
    description: &str,
    prompt_fn: F,
) -> Result<String>
where
    F: FnOnce(String) -> std::io::Result<String>,
{
    write_prompt_description(&mut std::io::stderr().lock(), description, error)
        .map_err(|err| LpassError::io("password prompt", err))?;
    prompt_fn(format!("{prompt}: ")).map_err(|err| LpassError::io("password prompt", err))
}

fn askpass_program_from_env() -> Option<String> {
    askpass_program_from_value(crate::lpenv::var("LPASS_ASKPASS").ok())
}

fn askpass_program_from_value(value: Option<String>) -> Option<String> {
    value.filter(|item| !item.trim().is_empty())
}

fn decode_password_output(mut bytes: Vec<u8>) -> String {
    while matches!(bytes.last(), Some(b'\n') | Some(b'\r')) {
        bytes.pop();
    }
    String::from_utf8_lossy(&bytes).to_string()
}

fn write_prompt_description<W: Write>(
    writer: &mut W,
    description: &str,
    error: Option<&str>,
) -> std::io::Result<()> {
    writeln!(writer, "{description}")?;
    writeln!(writer)?;
    if let Some(error) = error {
        writeln!(writer, "{error}")?;
    }
    writer.flush()
}

#[cfg(test)]
#[path = "password_tests.rs"]
mod tests;
