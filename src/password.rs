#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

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

#[inline(never)]
pub fn prompt_password_with_description(
    prompt: &str,
    error: Option<&str>,
    description: &str,
) -> Result<String> {
    prompt_password_with_description_and_tty(prompt, error, description, rpassword::prompt_password)
}

fn prompt_password_with_askpass(askpass: &str, prompt: &str) -> Result<String> {
    let output = Command::new(askpass).arg(prompt).output().map_err(|err| {
        if matches!(
            err.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::InvalidInput
                | std::io::ErrorKind::PermissionDenied
        ) {
            LpassError::Crypto("Unable to execute askpass")
        } else {
            LpassError::io("askpass", err)
        }
    })?;
    if !output.status.success() {
        return Err(LpassError::Crypto("askpass failed"));
    }
    Ok(decode_password_output(output.stdout))
}

fn prompt_password_with_description_and_tty<F>(
    prompt: &str,
    error: Option<&str>,
    description: &str,
    prompt_fn: F,
) -> Result<String>
where
    F: FnOnce(String) -> std::io::Result<String>,
{
    if let Some(askpass) = askpass_program_from_env() {
        return prompt_password_with_askpass(&askpass, prompt);
    }
    if pinentry_is_disabled() {
        return prompt_password_from_tty_with(prompt, error, description, prompt_fn);
    }

    match prompt_password_with_pinentry(&pinentry_program_from_env(), prompt, error, description)? {
        PinentryOutcome::Password(password) => Ok(password),
        PinentryOutcome::Fallback => {
            prompt_password_from_tty_with(prompt, error, description, prompt_fn)
        }
    }
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
    askpass_program_from_value(crate::lpenv::var_os("LPASS_ASKPASS"))
}

fn askpass_program_from_value(value: Option<std::ffi::OsString>) -> Option<String> {
    value.map(|item| item.to_string_lossy().into_owned())
}

fn pinentry_is_disabled() -> bool {
    crate::lpenv::var("LPASS_DISABLE_PINENTRY").as_deref() == Ok("1")
}

fn pinentry_program_from_env() -> String {
    crate::lpenv::var_os("LPASS_PINENTRY")
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pinentry".to_string())
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum PinentryOutcome {
    Password(String),
    Fallback,
}

fn prompt_password_with_pinentry(
    pinentry: &str,
    prompt: &str,
    error: Option<&str>,
    description: &str,
) -> Result<PinentryOutcome> {
    let mut child = match Command::new(pinentry)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if pinentry_spawn_should_fallback(&err) => return Ok(PinentryOutcome::Fallback),
        Err(err) => return Err(LpassError::io("pinentry", err)),
    };

    let mut stdin = child
        .stdin
        .take()
        .ok_or(LpassError::Crypto("pinentry failed"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or(LpassError::Crypto("pinentry failed"))?;
    let mut output = BufReader::new(stdout);

    if !pinentry_io(expect_ok(&mut output))? {
        return resolve_pinentry_failure(child);
    }
    if let Some(outcome) =
        send_command_with_recovery(&mut child, &mut stdin, "SETTITLE", Some("LastPass CLI"))?
    {
        return Ok(outcome);
    }
    if !pinentry_io(expect_ok(&mut output))? {
        return resolve_pinentry_failure(child);
    }

    let prompt_value = if prompt.is_empty() {
        None
    } else {
        Some(format!("{prompt}:"))
    };
    if let Some(outcome) =
        send_command_with_recovery(&mut child, &mut stdin, "SETPROMPT", prompt_value.as_deref())?
    {
        return Ok(outcome);
    }
    if !pinentry_io(expect_ok(&mut output))? {
        return resolve_pinentry_failure(child);
    }

    if let Some(error) = error {
        if let Some(outcome) =
            send_command_with_recovery(&mut child, &mut stdin, "SETERROR", Some(error))?
        {
            return Ok(outcome);
        }
        if !pinentry_io(expect_ok(&mut output))? {
            return resolve_pinentry_failure(child);
        }
    }

    if let Some(outcome) =
        send_command_with_recovery(&mut child, &mut stdin, "SETDESC", Some(description))?
    {
        return Ok(outcome);
    }
    if !pinentry_io(expect_ok(&mut output))? {
        return resolve_pinentry_failure(child);
    }

    for (name, value) in pinentry_options() {
        let option = format!("{name}={value}");
        if let Some(outcome) =
            send_command_with_recovery(&mut child, &mut stdin, "OPTION", Some(&option))?
        {
            return Ok(outcome);
        }
        if !pinentry_io(expect_ok(&mut output))? {
            return resolve_pinentry_failure(child);
        }
    }

    if let Some(outcome) = send_command_with_recovery(&mut child, &mut stdin, "GETPIN", None)? {
        return Ok(outcome);
    }
    let mut encoded = String::new();
    loop {
        let Some(line) = pinentry_io(read_protocol_line(&mut output))? else {
            return resolve_pinentry_failure(child);
        };
        if let Some(value) = line.strip_prefix("D ") {
            encoded.push_str(value);
            continue;
        }
        if line.starts_with("OK") {
            break;
        }
        return resolve_pinentry_failure(child);
    }

    let _ = send_command(&mut stdin, "BYE", None);
    let _ = child.wait();
    Ok(PinentryOutcome::Password(pinentry_unescape(&encoded)))
}

fn pinentry_spawn_should_fallback(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::InvalidInput
    )
}

fn pinentry_io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|err| LpassError::io("pinentry", err))
}

fn send_command_with_recovery(
    child: &mut Child,
    stdin: &mut impl Write,
    command: &str,
    argument: Option<&str>,
) -> Result<Option<PinentryOutcome>> {
    match send_command(stdin, command, argument) {
        Ok(()) => Ok(None),
        Err(err) if pinentry_pipe_closed(&err) => {
            resolve_pinentry_failure_in_place(child).map(Some)
        }
        Err(err) => Err(LpassError::io("pinentry", err)),
    }
}

fn pinentry_pipe_closed(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
    )
}

fn resolve_pinentry_failure(mut child: Child) -> Result<PinentryOutcome> {
    resolve_pinentry_failure_in_place(&mut child)
}

fn resolve_pinentry_failure_in_place(child: &mut Child) -> Result<PinentryOutcome> {
    let status = child
        .wait()
        .map_err(|err| LpassError::io("pinentry", err))?;
    match status.code() {
        Some(76) => Ok(PinentryOutcome::Fallback),
        Some(0) => Err(LpassError::Crypto("pinentry failed")),
        Some(_) => Err(LpassError::Crypto("pinentry failed")),
        None => Err(LpassError::Crypto("pinentry failed")),
    }
}

fn send_command(
    stdin: &mut impl Write,
    command: &str,
    argument: Option<&str>,
) -> std::io::Result<()> {
    match argument {
        Some(argument) => writeln!(stdin, "{command} {}", pinentry_escape(argument)),
        None => writeln!(stdin, "{command}"),
    }?;
    stdin.flush()
}

fn expect_ok(output: &mut BufReader<ChildStdout>) -> std::io::Result<bool> {
    Ok(read_protocol_line(output)?
        .map(|line| line.starts_with("OK"))
        .unwrap_or(false))
}

fn read_protocol_line(output: &mut BufReader<ChildStdout>) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    let read = output.read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }
    while matches!(line.chars().last(), Some('\n') | Some('\r')) {
        line.pop();
    }
    Ok(Some(line))
}

fn pinentry_options() -> Vec<(&'static str, String)> {
    let mut options = Vec::new();
    if let Ok(term) = crate::lpenv::var("TERM") {
        options.push(("ttytype", term));
    }
    if let Some(ttyname) = tty_name_for_stdin() {
        options.push(("ttyname", ttyname));
    }
    if let Ok(display) = crate::lpenv::var("DISPLAY") {
        options.push(("display", display));
    }
    options
}

fn tty_name_for_stdin() -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    for path in ["/proc/self/fd/0", "/dev/fd/0"] {
        if let Ok(target) = std::fs::read_link(path) {
            return Some(target.to_string_lossy().into_owned());
        }
    }
    None
}

fn pinentry_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '\r' => out.push_str("%0d"),
            '\n' => out.push_str("%0a"),
            _ => out.push(ch),
        }
    }
    out
}

fn pinentry_unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'%' && idx + 2 < bytes.len() {
            let hex = &value[idx + 1..idx + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(char::from(byte));
                idx += 3;
                continue;
            }
        }
        out.push(char::from(bytes[idx]));
        idx += 1;
    }
    out
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
