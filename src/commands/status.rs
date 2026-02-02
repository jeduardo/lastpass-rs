#![forbid(unsafe_code)]

use crate::agent::agent_is_available;
use crate::config::config_read_string;
use crate::terminal::{self, BOLD, FG_GREEN, FG_RED, RESET, UNDERLINE};

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
    let mut quiet = false;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            return Err("usage: status [--quiet, -q] [--color=auto|never|always]".to_string());
        }
        if arg == "--quiet" || arg == "-q" {
            quiet = true;
            continue;
        }
        if arg == "--color" {
            let value = iter
                .next()
                .ok_or_else(|| "... --color=auto|never|always".to_string())?;
            let mode = terminal::parse_color_mode(value)
                .ok_or_else(|| "... --color=auto|never|always".to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value)
                .ok_or_else(|| "... --color=auto|never|always".to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        return Err("usage: status [--quiet, -q] [--color=auto|never|always]".to_string());
    }

    if !agent_is_available() {
        if !quiet {
            let message = format!("{FG_RED}{BOLD}Not logged in{RESET}.");
            println!("{}", terminal::render_stdout(&message));
        }
        return Ok(1);
    }

    if !quiet {
        let username = config_read_string("username")
            .ok()
            .flatten()
            .unwrap_or_else(|| "unknown".to_string());
        let message = format!("{FG_GREEN}{BOLD}Logged in{RESET} as {UNDERLINE}{username}{RESET}.");
        println!("{}", terminal::render_stdout(&message));
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_inner_rejects_positional_args() {
        let err = run_inner(&["unexpected".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: status"));
    }

    #[test]
    fn run_inner_rejects_invalid_color_mode() {
        let err = run_inner(&["--color=rainbow".to_string()]).expect_err("must fail");
        assert!(err.contains("--color=auto|never|always"));
    }
}
