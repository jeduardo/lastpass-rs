#![forbid(unsafe_code)]

use crate::blob::{Account, Share};
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
        "usage: mv [--sync=auto|now|no] [--color=auto|never|always] {UNIQUENAME|UNIQUEID} GROUP";
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

    let mut blob = load_blob(sync_mode).map_err(|err| format!("{err}"))?;
    let idx = find_unique_account_index(&blob.accounts, name)?;
    let shares = collect_shares(&blob.accounts, &blob.shares);
    update_location(&mut blob.accounts[idx], folder, &shares);
    if let Some(err) = readonly_move_error(&blob.accounts[idx]) {
        return Err(err);
    }
    save_blob(&blob).map_err(|err| format!("{err}"))?;
    Ok(0)
}

fn find_unique_account_index(accounts: &[Account], name: &str) -> Result<usize, String> {
    if name != "0"
        && let Some((idx, _)) = accounts
            .iter()
            .enumerate()
            .find(|(_, account)| account.id.eq_ignore_ascii_case(name))
    {
        return Ok(idx);
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

#[derive(Debug, Clone, Eq, PartialEq)]
struct ShareRef {
    id: Option<String>,
    name: String,
    readonly: bool,
}

fn collect_shares(accounts: &[Account], shares: &[Share]) -> Vec<ShareRef> {
    let mut out: Vec<ShareRef> = shares
        .iter()
        .map(|share| ShareRef {
            id: Some(share.id.clone()),
            name: share.name.clone(),
            readonly: share.readonly,
        })
        .collect();

    for account in accounts {
        let Some(name) = account.share_name.as_ref() else {
            continue;
        };
        if out.iter().any(|share| share.name == *name) {
            continue;
        }
        out.push(ShareRef {
            id: account.share_id.clone(),
            name: name.clone(),
            readonly: account.share_readonly,
        });
    }

    out.sort_by_key(|share| usize::MAX - share.name.len());
    out
}

fn update_location(account: &mut Account, folder: &str, shares: &[ShareRef]) {
    let folder = folder.trim_end_matches('/').to_string();
    if let Some(share) = infer_share(&folder, shares) {
        let share_name = &share.name;
        let group = if folder == *share_name {
            String::new()
        } else {
            folder[share_name.len() + 1..].to_string()
        };
        account.share_name = Some(share_name.clone());
        account.share_id = share.id.clone();
        account.share_readonly = share.readonly;
        account.group = group.clone();
        account.fullname = if group.is_empty() {
            format!("{share_name}/{}", account.name)
        } else {
            format!("{share_name}/{group}/{}", account.name)
        };
        return;
    }

    account.share_name = None;
    account.share_id = None;
    account.share_readonly = false;
    account.group = folder.clone();
    account.fullname = if folder.is_empty() {
        account.name.clone()
    } else {
        format!("{folder}/{}", account.name)
    };
}

fn infer_share<'a>(folder: &str, shares: &'a [ShareRef]) -> Option<&'a ShareRef> {
    for share in shares {
        if folder == share.name {
            return Some(share);
        }
        if folder.starts_with(&(share.name.to_string() + "/")) {
            return Some(share);
        }
    }
    None
}

fn readonly_move_error(account: &Account) -> Option<String> {
    if !account.share_readonly {
        return None;
    }
    let share_name = account.share_name.as_deref().unwrap_or("(unknown)");
    Some(format!(
        "You do not have access to move {} into {}",
        account.name, share_name
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn account(id: &str, name: &str, fullname: &str, share_name: Option<&str>) -> Account {
        Account {
            id: id.to_string(),
            share_name: share_name.map(|value| value.to_string()),
            share_id: None,
            share_readonly: false,
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
        update_location(
            &mut account,
            "Team/dev",
            &[ShareRef {
                id: Some("42".to_string()),
                name: "Team".to_string(),
                readonly: false,
            }],
        );
        assert_eq!(account.share_name.as_deref(), Some("Team"));
        assert_eq!(account.share_id.as_deref(), Some("42"));
        assert_eq!(account.group, "dev");
        assert_eq!(account.fullname, "Team/dev/entry");
    }

    #[test]
    fn update_location_handles_share_root_and_plain_root() {
        let mut shared = account("1", "entry", "Team/dev/entry", Some("Team"));
        update_location(
            &mut shared,
            "Team/",
            &[ShareRef {
                id: Some("42".to_string()),
                name: "Team".to_string(),
                readonly: false,
            }],
        );
        assert_eq!(shared.share_name.as_deref(), Some("Team"));
        assert_eq!(shared.share_id.as_deref(), Some("42"));
        assert_eq!(shared.group, "");
        assert_eq!(shared.fullname, "Team/entry");

        let mut plain = account("2", "entry", "ops/entry", None);
        update_location(
            &mut plain,
            "",
            &[ShareRef {
                id: Some("42".to_string()),
                name: "Team".to_string(),
                readonly: false,
            }],
        );
        assert_eq!(plain.share_name, None);
        assert_eq!(plain.share_id, None);
        assert_eq!(plain.group, "");
        assert_eq!(plain.fullname, "entry");
    }

    #[test]
    fn collect_shares_deduplicates_and_prefers_longest_prefix() {
        let accounts = vec![
            account("1", "one", "Team/one", Some("Team")),
            account("2", "two", "Team/Platform/two", Some("Team/Platform")),
            account("3", "three", "Team/three", Some("Team")),
        ];
        let share_names = collect_shares(&accounts, &[]);
        assert_eq!(
            share_names
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Team/Platform", "Team"]
        );
        assert_eq!(
            infer_share("Team/Platform/dev", &share_names).map(|s| s.name.as_str()),
            Some("Team/Platform")
        );
        assert_eq!(infer_share("Elsewhere/dev", &share_names), None);
    }

    #[test]
    fn collect_shares_prefers_explicit_share_metadata() {
        let shares = vec![Share {
            id: "abc".to_string(),
            name: "Shared".to_string(),
            readonly: true,
        }];
        let out = collect_shares(&[], &shares);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id.as_deref(), Some("abc"));
        assert_eq!(out[0].name, "Shared");
        assert!(out[0].readonly);
    }

    #[test]
    fn readonly_move_error_reports_share_name() {
        let mut acct = account("1", "entry", "Team/entry", Some("Team"));
        acct.share_readonly = true;
        let err = readonly_move_error(&acct).expect("readonly error");
        assert!(err.contains("move entry into Team"));
        assert_eq!(
            readonly_move_error(&account("2", "entry", "entry", None)),
            None
        );
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

        let err = run_inner(&["--sync".to_string()]).expect_err("missing sync");
        assert!(err.contains("usage: mv"));

        let err = run_inner(&["--sync=bad".to_string(), "a".to_string(), "b".to_string()])
            .expect_err("bad sync");
        assert!(err.contains("usage: mv"));

        let err = run_inner(&["--sync".to_string(), "auto".to_string(), "a".to_string()])
            .expect_err("missing destination");
        assert!(err.contains("usage: mv"));
    }

    #[test]
    fn run_and_parse_color_paths() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");

        assert_eq!(run(&["--color".to_string()]), 1);

        let err = run_inner(&[
            "--color".to_string(),
            "never".to_string(),
            "entry".to_string(),
            "group".to_string(),
        ])
        .expect_err("runtime error after parse");
        assert!(err.contains("Unable to find account"));

        let err = run_inner(&[
            "--color=always".to_string(),
            "entry".to_string(),
            "group".to_string(),
        ])
        .expect_err("runtime error after parse");
        assert!(err.contains("Unable to find account"));
    }

    #[test]
    fn run_inner_reports_readonly_move_error_in_mock_mode() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");

        let mut blob = load_blob(SyncMode::No).expect("mock blob");
        let account = blob
            .accounts
            .iter_mut()
            .find(|item| item.fullname == "test-group/test-account")
            .expect("account");
        account.share_readonly = true;
        account.share_name = Some("Shared Team".to_string());
        save_blob(&blob).expect("save blob");

        let err = run_inner(&[
            "--sync=no".to_string(),
            "test-group/test-account".to_string(),
            "Shared Team/target".to_string(),
        ])
        .expect_err("readonly move should fail");
        assert!(err.contains("You do not have access to move"));
    }

    #[test]
    fn find_unique_account_allows_name_zero_without_id_match() {
        let accounts = vec![account("10", "0", "0", None)];
        let idx = find_unique_account_index(&accounts, "0").expect("match by name");
        assert_eq!(idx, 0);
    }
}
