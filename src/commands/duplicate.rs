#![forbid(unsafe_code)]

use crate::blob::Blob;
use crate::commands::data::{load_blob, save_blob};
use crate::terminal;

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
    let usage =
        "usage: duplicate [--sync=auto|now|no] [--color=auto|never|always] {UNIQUENAME|UNIQUEID}";
    let mut name: Option<String> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            name = Some(arg.clone());
            continue;
        }
        if arg.starts_with("--sync=") {
            continue;
        }
        if arg == "--sync" {
            let _ = iter.next();
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

    let name = name.ok_or_else(|| usage.to_string())?;

    let mut blob = load_blob().map_err(|err| format!("{err}"))?;
    let idx = find_account_index(&blob, &name)
        .ok_or_else(|| "Could not find specified account(s).".to_string())?;
    let mut account = blob.accounts[idx].clone();
    account.id = next_id(&blob);
    blob.accounts.push(account);
    save_blob(&blob).map_err(|err| format!("{err}"))?;

    Ok(0)
}

fn find_account_index(blob: &Blob, name: &str) -> Option<usize> {
    if name != "0" {
        if let Some((idx, _)) = blob
            .accounts
            .iter()
            .enumerate()
            .find(|(_, acct)| acct.id.eq_ignore_ascii_case(name))
        {
            return Some(idx);
        }
    }

    blob.accounts
        .iter()
        .enumerate()
        .find(|(_, acct)| acct.fullname == name || acct.name == name)
        .map(|(idx, _)| idx)
}

fn next_id(blob: &Blob) -> String {
    let mut max_id = 0u32;
    for account in &blob.accounts {
        if let Ok(value) = account.id.parse::<u32>() {
            if value > max_id {
                max_id = value;
            }
        }
    }
    format!("{:04}", max_id.saturating_add(1))
}
