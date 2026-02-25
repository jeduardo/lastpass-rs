#![forbid(unsafe_code)]

use crate::blob::Blob;
use crate::commands::argparse::parse_sync_option;
use crate::commands::data::{SyncMode, load_blob, save_blob};
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
    let mut sync_mode = SyncMode::Auto;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            name = Some(arg.clone());
            continue;
        }
        if let Some(mode) = parse_sync_option(arg, &mut iter, usage)? {
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

    let mut blob = load_blob(sync_mode).map_err(|err| format!("{err}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::Account;

    fn account(id: &str, name: &str, group: &str) -> Account {
        let fullname = if group.is_empty() {
            name.to_string()
        } else {
            format!("{group}/{name}")
        };
        Account {
            id: id.to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: name.to_string(),
            name_encrypted: None,
            group: group.to_string(),
            group_encrypted: None,
            fullname,
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

    fn blob_with_accounts() -> Blob {
        Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![
                account("0001", "alpha", "team"),
                account("0002", "beta", ""),
                account("0007", "gamma", "team"),
            ],
            attachments: Vec::new(),
        }
    }

    #[test]
    fn find_account_index_matches_id_first() {
        let blob = blob_with_accounts();
        assert_eq!(find_account_index(&blob, "0002"), Some(1));
    }

    #[test]
    fn find_account_index_matches_fullname_and_name() {
        let blob = blob_with_accounts();
        assert_eq!(find_account_index(&blob, "team/alpha"), Some(0));
        assert_eq!(find_account_index(&blob, "beta"), Some(1));
    }

    #[test]
    fn find_account_index_allows_name_zero_without_id_match() {
        let mut blob = blob_with_accounts();
        blob.accounts.push(account("0000", "0", ""));
        assert_eq!(find_account_index(&blob, "0"), Some(3));
    }

    #[test]
    fn next_id_uses_highest_numeric_value() {
        let blob = blob_with_accounts();
        assert_eq!(next_id(&blob), "0008");
    }

    #[test]
    fn next_id_ignores_lower_numeric_values() {
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![account("0005", "alpha", ""), account("0001", "beta", "")],
            attachments: Vec::new(),
        };
        assert_eq!(next_id(&blob), "0006");
    }

    #[test]
    fn run_inner_requires_target_argument() {
        let err = run_inner(&[]).expect_err("missing argument must fail");
        assert!(err.contains("usage: duplicate"));
    }

    #[test]
    fn run_inner_rejects_invalid_color_mode() {
        let err = run_inner(&["--color=rainbow".to_string()]).expect_err("bad color");
        assert!(err.contains("usage: duplicate"));

        let err = run_inner(&["--sync".to_string()]).expect_err("missing sync value");
        assert!(err.contains("usage: duplicate"));

        let err = run_inner(&["--sync=bad".to_string(), "x".to_string()]).expect_err("bad sync");
        assert!(err.contains("usage: duplicate"));
    }
}
