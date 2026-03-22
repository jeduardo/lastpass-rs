#![forbid(unsafe_code)]

use crate::blob::{Account, Share};
use crate::commands::argparse::parse_sync_option;
use crate::commands::data::{
    SyncMode, load_blob, maybe_push_account_share_move, maybe_push_account_update, save_blob,
};
use crate::terminal;

fn lpass_error_to_string(err: crate::error::LpassError) -> String {
    err.to_string()
}

fn non_empty_share_id(value: Option<&str>) -> Option<&str> {
    match value {
        Some(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

pub(super) fn run_inner(args: &[String]) -> Result<i32, String> {
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
            let Some(mode) = terminal::parse_color_mode(value) else {
                return Err(usage.to_string());
            };
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let Some(mode) = terminal::parse_color_mode(value) else {
                return Err(usage.to_string());
            };
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

    let mut blob = load_blob(sync_mode).map_err(lpass_error_to_string)?;
    let idx = find_unique_account_index(&blob.accounts, name)?;
    let original = blob.accounts[idx].clone();
    let shares = collect_shares(&blob.accounts, &blob.shares);
    update_location(&mut blob.accounts[idx], folder, &shares);
    if let Some(err) = readonly_move_error(&blob.accounts[idx]) {
        return Err(err);
    }

    if share_changed(&original, &blob.accounts[idx]) {
        if !share_transition_has_api_ids(&original, &blob.accounts[idx]) {
            return Err("Move to/from shared folder failed (-22)".to_string());
        }
        maybe_push_account_share_move(&blob.accounts[idx], &blob, original.share_id.as_deref())
            .map_err(lpass_error_to_string)?;
        blob.accounts.remove(idx);
        save_blob(&blob).map_err(lpass_error_to_string)?;
        return Ok(0);
    }

    maybe_push_account_update(&blob.accounts[idx], &blob, sync_mode).map_err(lpass_error_to_string)?;
    save_blob(&blob).map_err(lpass_error_to_string)?;
    Ok(0)
}

pub(super) fn find_unique_account_index(accounts: &[Account], name: &str) -> Result<usize, String> {
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
pub(super) struct ShareRef {
    pub(super) id: Option<String>,
    pub(super) name: String,
    pub(super) readonly: bool,
}

pub(super) fn collect_shares(accounts: &[Account], shares: &[Share]) -> Vec<ShareRef> {
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

pub(super) fn update_location(account: &mut Account, folder: &str, shares: &[ShareRef]) {
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

pub(super) fn infer_share<'a>(folder: &str, shares: &'a [ShareRef]) -> Option<&'a ShareRef> {
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

pub(super) fn readonly_move_error(account: &Account) -> Option<String> {
    if !account.share_readonly {
        return None;
    }
    let share_name = account.share_name.as_deref().unwrap_or("(unknown)");
    Some(format!(
        "You do not have access to move {} into {}",
        account.name, share_name
    ))
}

pub(super) fn share_changed(original: &Account, updated: &Account) -> bool {
    match (
        non_empty_share_id(original.share_id.as_deref()),
        non_empty_share_id(updated.share_id.as_deref()),
    ) {
        (Some(left), Some(right)) => left != right,
        (Some(_), None) | (None, Some(_)) => true,
        (None, None) => !share_name_eq_ignore_ascii_case(
            original.share_name.as_deref(),
            updated.share_name.as_deref(),
        ),
    }
}

pub(super) fn share_transition_has_api_ids(original: &Account, updated: &Account) -> bool {
    non_empty_share_id(original.share_id.as_deref()).is_some()
        || non_empty_share_id(updated.share_id.as_deref()).is_some()
}

pub(super) fn share_name_eq_ignore_ascii_case(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
