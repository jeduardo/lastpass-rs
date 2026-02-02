#![forbid(unsafe_code)]

use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};

use crate::blob::{Account, Blob};
use crate::commands::data::{load_blob, save_blob};
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
    let mut username: Option<String> = None;
    let mut url: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            positional.push(arg.clone());
            continue;
        }
        if arg.starts_with("--sync=") {
            continue;
        }
        if arg == "--sync" {
            let _ = iter.next();
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
        return Err("usage: generate [--sync=auto|now|no] [--clip, -c] [--username=USERNAME] [--url=URL] [--no-symbols] {NAME|UNIQUEID} LENGTH".to_string());
    }

    if positional.len() != 2 {
        return Err("usage: generate [--sync=auto|now|no] [--clip, -c] [--username=USERNAME] [--url=URL] [--no-symbols] {NAME|UNIQUEID} LENGTH".to_string());
    }

    let name = positional.remove(0);
    let length: usize = positional
        .remove(0)
        .parse()
        .map_err(|_| "length must be a number".to_string())?;

    let password = generate_password(length);

    let mut blob = load_blob().map_err(|err| format!("{err}"))?;
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
        if let Ok(value) = account.id.parse::<u32>() {
            if value > max_id {
                max_id = value;
            }
        }
    }
    format!("{:04}", max_id.saturating_add(1))
}
