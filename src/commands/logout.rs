#![forbid(unsafe_code)]

use std::io::{self, Write};

use crate::agent::{agent_get_decryption_key, agent_is_available};
use crate::http::HttpClient;
use crate::session::{session_kill, session_load};
use crate::terminal::{self, BOLD, FG_RED, FG_YELLOW, RESET};
use zeroize::Zeroize;

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<i32, String> {
    let usage = "usage: logout [--force, -f] [--color=auto|never|always]";
    let mut force = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--force" || arg == "-f" {
            force = true;
            continue;
        }
        if arg == "--color" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        return Err(usage.to_string());
    }

    if !force && !ask_yes_no(true, "Are you sure you would like to log out?")? {
        let message = format!("{FG_YELLOW}{BOLD}Log out{RESET}: aborted.");
        println!("{}", terminal::render_stdout(&message));
        return Ok(1);
    }

    if agent_is_available() {
        let mut key = agent_get_decryption_key().map_err(|err| format!("{err}"))?;
        let session = session_load(&key)
            .map_err(|err| format!("{err}"))?
            .ok_or_else(|| "Could not find session. Perhaps you need to login with `lpass login`.".to_string())?;
        lastpass_logout(&session.token, Some(&session)).map_err(|err| format!("{err}"))?;
        key.zeroize();
    }

    session_kill().map_err(|err| format!("{err}"))?;

    let message = format!("{FG_YELLOW}{BOLD}Log out{RESET}: complete.");
    println!("{}", terminal::render_stdout(&message));
    Ok(0)
}

fn lastpass_logout(
    token: &str,
    session: Option<&crate::session::Session>,
) -> crate::error::Result<()> {
    let client = HttpClient::from_env()?;
    let _ = client.post_lastpass(
        None,
        "logout.php",
        session,
        &[("method", "cli"), ("noredirect", "1"), ("token", token)],
    )?;
    Ok(())
}

fn ask_yes_no(default_yes: bool, prompt: &str) -> Result<bool, String> {
    let options = if default_yes { "Y/n" } else { "y/N" };
    loop {
        eprint!(
            "{}",
            terminal::render_stderr(&format!("{prompt} [{options}] "))
        );
        io::stderr()
            .flush()
            .map_err(|err| format!("flush: {err}"))?;

        let mut response = String::new();
        let read = io::stdin()
            .read_line(&mut response)
            .map_err(|err| format!("read: {err}"))?;
        if read == 0 {
            return Err("aborted response.".to_string());
        }

        if let Some(value) = parse_yes_no_response(response.trim(), default_yes) {
            return Ok(value);
        }

        let msg = format!("{FG_RED}{BOLD}Error{RESET}: Response not understood.");
        eprintln!("{}", terminal::render_stderr(&msg));
    }
}

fn parse_yes_no_response(input: &str, default_yes: bool) -> Option<bool> {
    if input.is_empty() {
        return Some(default_yes);
    }
    let first = input.chars().next()?;
    if first.eq_ignore_ascii_case(&'y') {
        Some(true)
    } else if first.eq_ignore_ascii_case(&'n') {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_yes_no_response, run_inner};

    #[test]
    fn parse_yes_no_accepts_yes_variants() {
        assert_eq!(parse_yes_no_response("y", true), Some(true));
        assert_eq!(parse_yes_no_response("yes", false), Some(true));
        assert_eq!(parse_yes_no_response("yellow", false), Some(true));
    }

    #[test]
    fn parse_yes_no_accepts_no_variants() {
        assert_eq!(parse_yes_no_response("n", true), Some(false));
        assert_eq!(parse_yes_no_response("no", true), Some(false));
        assert_eq!(parse_yes_no_response("never", true), Some(false));
    }

    #[test]
    fn parse_yes_no_uses_default_on_empty_response() {
        assert_eq!(parse_yes_no_response("", true), Some(true));
        assert_eq!(parse_yes_no_response("", false), Some(false));
    }

    #[test]
    fn parse_yes_no_rejects_unknown_response() {
        assert_eq!(parse_yes_no_response("maybe", true), None);
    }

    #[test]
    fn run_inner_rejects_unknown_options() {
        let err = run_inner(&["--bogus".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: logout"));
    }

    #[test]
    fn run_inner_rejects_missing_color_value() {
        let err = run_inner(&["--color".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: logout"));
    }

    #[test]
    fn run_inner_rejects_invalid_color_value() {
        let err = run_inner(&["--color=rainbow".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: logout"));
    }
}
