#![forbid(unsafe_code)]

use crate::commands::data::load_blob;
use crate::format::format_account;
use crate::terminal::{self, BOLD, FG_GREEN, NO_BOLD, RESET};

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
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg.starts_with('-') {
            if arg.starts_with("--sync=") {
                continue;
            }
            if arg == "--sync" {
                let _ = iter.next();
                continue;
            }
            if arg == "--long" || arg == "-l" || arg == "-m" || arg == "-u" {
                continue;
            }
            if arg == "--color" || arg == "-C" {
                let value = iter.next().ok_or_else(|| {
                    "... --color=auto|never|always".to_string()
                })?;
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
        }
    }

    let blob = load_blob().map_err(|err| format!("{err}"))?;
    for account in &blob.accounts {
        let line = format_ls_line(account);
        println!("{}", terminal::render_stdout(&line));
    }
    Ok(0)
}

fn format_ls_line(account: &crate::blob::Account) -> String {
    format!(
        "{FG_GREEN}{BOLD}{}{NO_BOLD} [id: {}]{RESET}",
        format_account("%aN", account),
        account.id,
    )
}
