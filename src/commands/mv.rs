#![forbid(unsafe_code)]

use crate::blob::Account;
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
    let usage = "usage: mv [--color=auto|never|always] {UNIQUENAME|UNIQUEID} GROUP";
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

    if positional.len() != 2 {
        return Err(usage.to_string());
    }
    let name = &positional[0];
    let folder = &positional[1];

    let mut blob = load_blob().map_err(|err| format!("{err}"))?;
    let idx = find_unique_account_index(&blob.accounts, name)?;
    let share_names = collect_share_names(&blob.accounts);
    update_location(&mut blob.accounts[idx], folder, &share_names);
    save_blob(&blob).map_err(|err| format!("{err}"))?;
    Ok(0)
}

fn find_unique_account_index(accounts: &[Account], name: &str) -> Result<usize, String> {
    if name != "0" {
        if let Some((idx, _)) = accounts
            .iter()
            .enumerate()
            .find(|(_, account)| account.id.eq_ignore_ascii_case(name))
        {
            return Ok(idx);
        }
    }

    let matches: Vec<usize> = accounts
        .iter()
        .enumerate()
        .filter(|(_, account)| account.fullname == name || account.name == name)
        .map(|(idx, _)| idx)
        .collect();

    match matches.len() {
        0 => Err(format!("Unable to find account {name}")),
        1 => Ok(matches[0]),
        _ => Err(format!(
            "Multiple matches found for '{name}'. You must specify an ID instead of a name."
        )),
    }
}

fn collect_share_names(accounts: &[Account]) -> Vec<String> {
    let mut names: Vec<String> = accounts
        .iter()
        .filter_map(|account| account.share_name.as_ref())
        .cloned()
        .collect();
    names.sort();
    names.dedup();
    names.sort_by_key(|name| usize::MAX - name.len());
    names
}

fn update_location(account: &mut Account, folder: &str, share_names: &[String]) {
    let folder = folder.trim_end_matches('/').to_string();
    let share_name = infer_share_name(&folder, share_names);
    if let Some(share_name) = share_name {
        let group = if folder == share_name {
            String::new()
        } else if folder.starts_with(&(share_name.clone() + "/")) {
            folder[share_name.len() + 1..].to_string()
        } else {
            folder.clone()
        };
        account.share_name = Some(share_name.clone());
        account.group = group.clone();
        account.fullname = if group.is_empty() {
            format!("{share_name}/{}", account.name)
        } else {
            format!("{share_name}/{group}/{}", account.name)
        };
        return;
    }

    account.share_name = None;
    account.group = folder.clone();
    account.fullname = if folder.is_empty() {
        account.name.clone()
    } else {
        format!("{folder}/{}", account.name)
    };
}

fn infer_share_name(folder: &str, share_names: &[String]) -> Option<String> {
    for share_name in share_names {
        if folder == share_name {
            return Some(share_name.clone());
        }
        if folder.starts_with(&(share_name.clone() + "/")) {
            return Some(share_name.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(id: &str, name: &str, fullname: &str, share_name: Option<&str>) -> Account {
        Account {
            id: id.to_string(),
            share_name: share_name.map(|value| value.to_string()),
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
    fn find_unique_account_prefers_id_and_detects_ambiguity() {
        let accounts = vec![
            account("100", "shared", "team/shared", None),
            account("200", "shared", "other/shared", None),
        ];
        assert_eq!(
            find_unique_account_index(&accounts, "200").expect("id match"),
            1
        );
        let err = find_unique_account_index(&accounts, "shared").expect_err("ambiguous");
        assert!(err.contains("Multiple matches found"));
    }

    #[test]
    fn update_location_sets_group_and_fullname() {
        let mut account = account("1", "entry", "team/entry", None);
        update_location(&mut account, "ops", &[]);
        assert_eq!(account.share_name, None);
        assert_eq!(account.group, "ops");
        assert_eq!(account.fullname, "ops/entry");
    }

    #[test]
    fn update_location_infers_share_from_folder_prefix() {
        let mut account = account("1", "entry", "team/entry", Some("Team"));
        update_location(&mut account, "Team/dev", &[String::from("Team")]);
        assert_eq!(account.share_name.as_deref(), Some("Team"));
        assert_eq!(account.group, "dev");
        assert_eq!(account.fullname, "Team/dev/entry");
    }

    #[test]
    fn update_location_handles_share_root_and_plain_root() {
        let mut shared = account("1", "entry", "Team/dev/entry", Some("Team"));
        update_location(&mut shared, "Team/", &[String::from("Team")]);
        assert_eq!(shared.share_name.as_deref(), Some("Team"));
        assert_eq!(shared.group, "");
        assert_eq!(shared.fullname, "Team/entry");

        let mut plain = account("2", "entry", "ops/entry", None);
        update_location(&mut plain, "", &[String::from("Team")]);
        assert_eq!(plain.share_name, None);
        assert_eq!(plain.group, "");
        assert_eq!(plain.fullname, "entry");
    }

    #[test]
    fn collect_share_names_deduplicates_and_prefers_longest_prefix() {
        let accounts = vec![
            account("1", "one", "Team/one", Some("Team")),
            account("2", "two", "Team/Platform/two", Some("Team/Platform")),
            account("3", "three", "Team/three", Some("Team")),
        ];
        let share_names = collect_share_names(&accounts);
        assert_eq!(
            share_names,
            vec!["Team/Platform".to_string(), "Team".to_string()]
        );
        assert_eq!(
            infer_share_name("Team/Platform/dev", &share_names).as_deref(),
            Some("Team/Platform")
        );
        assert_eq!(infer_share_name("Elsewhere/dev", &share_names), None);
    }

    #[test]
    fn find_unique_account_reports_missing() {
        let accounts = vec![account("100", "alpha", "team/alpha", None)];
        let err = find_unique_account_index(&accounts, "missing").expect_err("missing");
        assert!(err.contains("Unable to find account"));
    }

    #[test]
    fn run_inner_rejects_invalid_arguments() {
        let err = run_inner(&[]).expect_err("missing args");
        assert!(err.contains("usage: mv"));

        let err = run_inner(&["--color".to_string()]).expect_err("missing color value");
        assert!(err.contains("usage: mv"));

        let err = run_inner(&["--color=rainbow".to_string()]).expect_err("bad color");
        assert!(err.contains("usage: mv"));

        let err = run_inner(&["--sync".to_string(), "auto".to_string(), "a".to_string()])
            .expect_err("missing destination");
        assert!(err.contains("usage: mv"));
    }
}
