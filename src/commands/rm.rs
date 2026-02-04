#![forbid(unsafe_code)]

use crate::blob::Account;
use crate::commands::data::{SyncMode, load_blob, maybe_push_account_remove, save_blob};
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
    let usage = "usage: rm [--sync=auto|now|no] [--color=auto|never|always] {UNIQUENAME|UNIQUEID}";
    let mut name: Option<String> = None;
    let mut sync_mode = SyncMode::Auto;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            if name.is_some() {
                return Err(usage.to_string());
            }
            name = Some(arg.clone());
            continue;
        }

        if let Some(value) = arg.strip_prefix("--sync=") {
            let Some(mode) = SyncMode::parse(value) else {
                return Err(usage.to_string());
            };
            sync_mode = mode;
            continue;
        }
        if arg == "--sync" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            let Some(mode) = SyncMode::parse(value) else {
                return Err(usage.to_string());
            };
            sync_mode = mode;
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
    let idx = match find_unique_account_index(&blob.accounts, &name) {
        Ok(idx) => idx,
        Err(FindAccountError::Missing) => {
            return Err(format!("Could not find specified account '{name}'."));
        }
        Err(FindAccountError::Ambiguous) => {
            return Err(format!(
                "Multiple matches found for '{name}'. You must specify an ID instead of a name."
            ));
        }
    };
    let removed = blob.accounts.remove(idx);
    save_blob(&blob).map_err(|err| format!("{err}"))?;
    maybe_push_account_remove(&removed, sync_mode).map_err(|err| format!("{err}"))?;
    Ok(0)
}

#[derive(Debug)]
enum FindAccountError {
    Missing,
    Ambiguous,
}

fn find_unique_account_index(accounts: &[Account], name: &str) -> Result<usize, FindAccountError> {
    if name != "0" {
        if let Some((idx, _)) = accounts
            .iter()
            .enumerate()
            .find(|(_, account)| account.id.eq_ignore_ascii_case(name))
        {
            return Ok(idx);
        }
    }

    let mut match_idx: Option<usize> = None;
    for (idx, account) in accounts.iter().enumerate() {
        if account.fullname == name || account.name == name {
            if match_idx.is_some() {
                return Err(FindAccountError::Ambiguous);
            }
            match_idx = Some(idx);
        }
    }
    match_idx.ok_or(FindAccountError::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: &str, name: &str, fullname: &str) -> Account {
        Account {
            id: id.to_string(),
            share_name: None,
            name: name.to_string(),
            name_encrypted: None,
            group: String::new(),
            group_encrypted: None,
            fullname: fullname.to_string(),
            url: String::new(),
            url_encrypted: None,
            username: String::new(),
            username_encrypted: None,
            password: String::new(),
            password_encrypted: None,
            note: String::new(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        }
    }

    #[test]
    fn find_unique_account_matches_id_and_name() {
        let accounts = vec![
            account("1", "alpha", "group/alpha"),
            account("2", "beta", "group/beta"),
        ];
        assert_eq!(find_unique_account_index(&accounts, "2").expect("id"), 1);
        assert_eq!(
            find_unique_account_index(&accounts, "group/alpha").expect("fullname"),
            0
        );
    }

    #[test]
    fn find_unique_account_returns_none_for_missing_or_ambiguous() {
        let accounts = vec![
            account("1", "dup", "one/dup"),
            account("2", "dup", "two/dup"),
        ];
        assert!(matches!(
            find_unique_account_index(&accounts, "missing"),
            Err(FindAccountError::Missing)
        ));
        assert!(matches!(
            find_unique_account_index(&accounts, "dup"),
            Err(FindAccountError::Ambiguous)
        ));
    }

    #[test]
    fn run_inner_rejects_invalid_invocations() {
        let err = run_inner(&[]).expect_err("missing arg");
        assert!(err.contains("usage: rm"));

        let err = run_inner(&["--color".to_string()]).expect_err("missing color value");
        assert!(err.contains("usage: rm"));

        let err = run_inner(&["alpha".to_string(), "beta".to_string()]).expect_err("too many args");
        assert!(err.contains("usage: rm"));

        let err = run_inner(&["--sync".to_string()]).expect_err("missing sync value");
        assert!(err.contains("usage: rm"));

        let err = run_inner(&["--sync=bad".to_string(), "alpha".to_string()])
            .expect_err("bad sync value");
        assert!(err.contains("usage: rm"));

        let err = run_inner(&["--bogus".to_string()]).expect_err("unknown option");
        assert!(err.contains("usage: rm"));
    }
}
