#![forbid(unsafe_code)]

use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};

use crate::blob::{Account, Blob};
use crate::commands::argparse::parse_sync_option;
use crate::commands::data::{SyncMode, load_blob, save_blob};
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
    let usage = "usage: generate [--sync=auto|now|no] [--clip, -c] [--username=USERNAME] [--url=URL] [--no-symbols] {NAME|UNIQUEID} LENGTH";
    let mut username: Option<String> = None;
    let mut url: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut sync_mode = SyncMode::Auto;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            positional.push(arg.clone());
            continue;
        }
        if let Some(mode) = parse_sync_option(arg, &mut iter, usage)? {
            sync_mode = mode;
            continue;
        }
        if arg == "--clip" || arg == "-c" {
            continue;
        }
        if arg == "--no-symbols" {
            continue;
        }
        if arg == "--username" {
            if let Some(next) = iter.next() {
                username = Some(next.clone());
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("--username=") {
            username = Some(value.to_string());
            continue;
        }
        if arg == "--url" {
            if let Some(next) = iter.next() {
                url = Some(next.clone());
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("--url=") {
            url = Some(value.to_string());
            continue;
        }
        return Err(usage.to_string());
    }

    if positional.len() != 2 {
        return Err(usage.to_string());
    }

    let name = positional.remove(0);
    let length: usize = positional
        .remove(0)
        .parse()
        .map_err(|_| "length must be a number".to_string())?;

    let password = generate_password(length);

    let mut blob = load_blob(sync_mode).map_err(|err| format!("{err}"))?;
    if let Some(idx) = find_account_index(&blob, &name) {
        let account = &mut blob.accounts[idx];
        if let Some(value) = username {
            account.username = value;
        }
        if let Some(value) = url {
            account.url = value;
        }
        account.password = password;
    } else {
        let mut account = build_account(&name, &blob);
        account.username = username.unwrap_or_default();
        account.url = url.unwrap_or_default();
        account.password = password;
        blob.accounts.push(account);
    }

    save_blob(&blob).map_err(|err| format!("{err}"))?;
    Ok(0)
}

fn generate_password(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn find_account_index(blob: &Blob, name: &str) -> Option<usize> {
    if name != "0"
        && let Some((idx, _)) = blob
            .accounts
            .iter()
            .enumerate()
            .find(|(_, acct)| acct.id.eq_ignore_ascii_case(name))
    {
        return Some(idx);
    }

    blob.accounts
        .iter()
        .enumerate()
        .find(|(_, acct)| acct.fullname == name || acct.name == name)
        .map(|(idx, _)| idx)
}

fn build_account(fullname: &str, blob: &Blob) -> Account {
    let (group, name) = split_group(fullname);
    let fullname = if group.is_empty() {
        name.clone()
    } else {
        format!("{}/{}", group, name)
    };

    Account {
        id: next_id(blob),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name,
        name_encrypted: None,
        group,
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
        last_touch: "skipped".to_string(),
        last_modified_gmt: "skipped".to_string(),
        fav: false,
        pwprotect: false,
        attachkey: String::new(),
        attachkey_encrypted: None,
        attachpresent: false,
        fields: Vec::new(),
    }
}

fn split_group(full: &str) -> (String, String) {
    if let Some(pos) = full.rfind('/') {
        let group = full[..pos].to_string();
        let name = full[pos + 1..].to_string();
        return (group, name);
    }
    (String::new(), full.to_string())
}

fn next_id(blob: &Blob) -> String {
    let mut max_id = 0u32;
    for account in &blob.accounts {
        if let Ok(value) = account.id.parse::<u32>()
            && value > max_id
        {
            max_id = value;
        }
    }
    format!("{:04}", max_id.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn run_inner_rejects_invalid_sync_values() {
        let err = run_inner(&["--sync".to_string()]).expect_err("missing sync value");
        assert!(err.contains("usage: generate"));

        let err = run_inner(&["--sync=bad".to_string()]).expect_err("bad sync value");
        assert!(err.contains("usage: generate"));
    }

    #[test]
    fn split_group_and_next_id_cover_helpers() {
        assert_eq!(
            split_group("team/alpha"),
            ("team".to_string(), "alpha".to_string())
        );
        assert_eq!(split_group("alpha"), (String::new(), "alpha".to_string()));

        let blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![account("0002", "a", ""), account("0010", "b", "")],
            attachments: Vec::new(),
        };
        assert_eq!(next_id(&blob), "0011");
    }
}
