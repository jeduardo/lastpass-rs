#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
#[cfg(target_os = "linux")]
use std::io::IsTerminal;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::error::{LpassError, Result};

type PromptFn<'a> = dyn FnMut(String) -> std::io::Result<String> + 'a;

#[inline(never)]
pub fn prompt_password(username: &str) -> Result<String> {
    prompt_password_with_description(
        "Master Password",
        None,
        &format!("Please enter the LastPass master password for <{}>.", username),
    )
}

#[inline(never)]
pub fn prompt_password_with_description(
    prompt: &str,
    error: Option<&str>,
    description: &str,
) -> Result<String> {
    let mut prompt_fn = rpassword::prompt_password;
    prompt_password_with_description_and_tty(prompt, error, description, &mut prompt_fn)
}

fn prompt_password_with_description_and_tty(
    prompt: &str,
    error: Option<&str>,
    description: &str,
    prompt_fn: &mut PromptFn<'_>,
) -> Result<String> {
    if let Some(askpass) = askpass_program_from_env() {
        return prompt_password_with_askpass(&askpass, prompt);
    }
    if pinentry_disabled() {
        return prompt_password_from_tty_with(prompt, error, description, prompt_fn);
    }
    match prompt_password_with_pinentry(
        pinentry_program_from_env().as_deref().unwrap_or("pinentry"),
        prompt,
        error,
        description,
    ) {
        Ok(password) => Ok(password),
        Err(PinentryError::Unavailable) => {
            prompt_password_from_tty_with(prompt, error, description, prompt_fn)
        }
        Err(PinentryError::Failed) => Err(LpassError::Crypto("pinentry failed")),
    }
}

fn prompt_password_with_askpass(askpass: &OsString, prompt: &str) -> Result<String> {
    let output = Command::new(askpass)
        .arg(prompt)
        .output()
        .map_err(|err| LpassError::io("askpass", err))?;
    if !output.status.success() {
        return Err(LpassError::Crypto("askpass failed"));
    }
    Ok(decode_password_output(output.stdout))
}

fn prompt_password_from_tty_with(
    prompt: &str,
    error: Option<&str>,
    description: &str,
    prompt_fn: &mut dyn FnMut(String) -> std::io::Result<String>,
) -> Result<String> {
    write_prompt_description(&mut std::io::stderr().lock(), description, error)
        .map_err(|err| LpassError::io("password prompt", err))?;
    prompt_fn(format!("{prompt}: ")).map_err(|err| LpassError::io("password prompt", err))
}

fn prompt_password_with_pinentry(
    pinentry: &str,
    prompt: &str,
    error: Option<&str>,
    description: &str,
) -> std::result::Result<String, PinentryError> {
    let mut child = spawn_pinentry(pinentry)?;
    let (stdin, stdout) = match take_pinentry_stdio(&mut child) {
        Ok(stdio) => stdio,
        Err(err) => {
            let _ = child.wait();
            return Err(err);
        }
    };
    let mut input = stdin;
    let mut output = BufReader::new(stdout);

    let result = (|| {
        expect_pinentry_ok(&mut output)?;
        send_pinentry_command(&mut input, "SETTITLE", Some("LastPass CLI"))?;
        expect_pinentry_ok(&mut output)?;
        send_pinentry_command(&mut input, "SETPROMPT", Some(&format!("{prompt}:")))?;
        expect_pinentry_ok(&mut output)?;
        if let Some(error) = error {
            send_pinentry_command(&mut input, "SETERROR", Some(error))?;
            expect_pinentry_ok(&mut output)?;
        }
        send_pinentry_command(&mut input, "SETDESC", Some(description))?;
        expect_pinentry_ok(&mut output)?;
        send_pinentry_option(&mut input, &mut output, "ttytype", crate::lpenv::var("TERM").ok())?;
        send_pinentry_option(&mut input, &mut output, "ttyname", tty_name_for_stdin())?;
        send_pinentry_option(&mut input, &mut output, "display", crate::lpenv::var("DISPLAY").ok())?;
        send_pinentry_command(&mut input, "GETPIN", None)?;
        let password = read_pinentry_data(&mut output)?;
        Ok(pinentry_unescape(&password))
    })();
    let _ = send_pinentry_command(&mut input, "BYE", None);
    let _ = child.wait();
    result
}

fn spawn_pinentry(pinentry: &str) -> std::result::Result<Child, PinentryError> {
    Command::new(pinentry)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| PinentryError::Unavailable)
}

fn take_pinentry_stdio(
    child: &mut Child,
) -> std::result::Result<(ChildStdin, ChildStdout), PinentryError> {
    let Some(stdin) = child.stdin.take() else {
        return Err(PinentryError::Failed);
    };
    let Some(stdout) = child.stdout.take() else {
        return Err(PinentryError::Failed);
    };
    Ok((stdin, stdout))
}

fn send_pinentry_option(
    input: &mut ChildStdin,
    output: &mut BufReader<ChildStdout>,
    name: &str,
    value: Option<String>,
) -> std::result::Result<(), PinentryError> {
    if let Some(value) = value {
        send_pinentry_command(input, "OPTION", Some(&format!("{name}={value}")))?;
        expect_pinentry_ok(output)?;
    }
    Ok(())
}

fn send_pinentry_command(
    input: &mut ChildStdin,
    command: &str,
    argument: Option<&str>,
) -> std::result::Result<(), PinentryError> {
    match argument {
        Some(argument) => writeln!(input, "{command} {}", pinentry_escape(argument)),
        None => writeln!(input, "{command}"),
    }
    .and_then(|_| input.flush())
    .map_err(|_| PinentryError::Failed)
}

fn expect_pinentry_ok(
    output: &mut BufReader<ChildStdout>,
) -> std::result::Result<(), PinentryError> {
    let line = read_pinentry_line(output)?;
    if line.starts_with("OK") {
        Ok(())
    } else {
        Err(PinentryError::Failed)
    }
}

fn read_pinentry_data(
    output: &mut BufReader<ChildStdout>,
) -> std::result::Result<String, PinentryError> {
    let mut password = String::new();
    loop {
        let line = read_pinentry_line(output)?;
        if let Some(data) = line.strip_prefix("D ") {
            password.push_str(data);
            continue;
        }
        if line.starts_with("OK") {
            return Ok(password);
        }
        return Err(PinentryError::Failed);
    }
}

fn read_pinentry_line(
    output: &mut BufReader<ChildStdout>,
) -> std::result::Result<String, PinentryError> {
    let mut line = String::new();
    let read = output.read_line(&mut line).map_err(|_| PinentryError::Failed)?;
    if read == 0 {
        return Err(PinentryError::Failed);
    }
    while matches!(line.as_bytes().last(), Some(b'\n') | Some(b'\r')) {
        line.pop();
    }
    Ok(line)
}

fn pinentry_disabled() -> bool {
    matches!(crate::lpenv::var("LPASS_DISABLE_PINENTRY").as_deref(), Ok("1"))
}

fn askpass_program_from_env() -> Option<OsString> {
    crate::lpenv::var_os("LPASS_ASKPASS")
}

#[cfg(test)]
fn askpass_program_from_value(value: Option<OsString>) -> Option<OsString> {
    value
}

fn pinentry_program_from_env() -> Option<String> {
    crate::lpenv::var("LPASS_PINENTRY").ok()
}

fn decode_password_output(mut bytes: Vec<u8>) -> String {
    while matches!(bytes.last(), Some(b'\n') | Some(b'\r')) {
        bytes.pop();
    }
    String::from_utf8_lossy(&bytes).to_string()
}

fn pinentry_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => escaped.push_str("%25"),
            '\r' => escaped.push_str("%0d"),
            '\n' => escaped.push_str("%0a"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn pinentry_unescape(value: &str) -> String {
    let mut unescaped = Vec::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hi = chars.next();
            let lo = chars.next();
            if let (Some(hi), Some(lo)) = (hi, lo)
                && let Ok(byte) = u8::from_str_radix(&format!("{hi}{lo}"), 16)
            {
                unescaped.push(byte);
                continue;
            }
            break;
        }
        let mut encoded = [0_u8; 4];
        unescaped.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
    }
    String::from_utf8_lossy(&unescaped).to_string()
}

fn tty_name_for_stdin() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        if !std::io::stdin().is_terminal() {
            return None;
        }
        std::fs::read_link("/proc/self/fd/0")
            .ok()
            .map(|path| path.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PinentryError {
    Unavailable,
    Failed,
}

#[cfg(test)]
#[path = "../password_tests.rs"]
mod tests;
