#![forbid(unsafe_code)]

use rand::{Rng, thread_rng};

use crate::blob::{Account, Blob, Share};
use crate::commands::argparse::parse_sync_option;
use crate::commands::clipboard::copy_to_clipboard;
use crate::commands::data::{SyncMode, load_blob, maybe_push_account_update, save_blob};
use crate::notes::{collapse_notes, expand_notes};

const USAGE: &str = "usage: generate [--sync=auto|now|no] [--clip, -c] [--username=USERNAME] [--url=URL] [--no-symbols] {NAME|UNIQUEID} LENGTH";
const ALL_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";
const NICE_CHARS_LEN: usize = 62;

#[derive(Debug, Clone, Eq, PartialEq)]
struct GenerateArgs {
    name: String,
    length: usize,
    username: Option<String>,
    url: Option<String>,
    no_symbols: bool,
    clip: bool,
    sync_mode: SyncMode,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ShareRef {
    id: Option<String>,
    name: String,
    readonly: bool,
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

fn run_inner(args: &[String]) -> Result<i32, String> {
    let parsed = parse_generate_args(args)?;
    let password = generate_password(parsed.length, parsed.no_symbols);

    let mut blob = load_blob(parsed.sync_mode).map_err(|err| format!("{err}"))?;
    let idx = find_unique_account_index(&blob.accounts, &parsed.name)?;

    let updated_account = if let Some(idx) = idx {
        update_existing_account(&mut blob.accounts[idx], &parsed, &password)?
    } else {
        let account = build_account(&parsed.name, &blob)?;
        let account = populate_new_account(account, &parsed, &password);
        blob.accounts.push(account.clone());
        account
    };

    save_blob(&blob).map_err(|err| format!("{err}"))?;
    maybe_push_account_update(&updated_account, parsed.sync_mode)
        .map_err(|err| format!("{err}"))?;

    if parsed.clip {
        let mut clipboard_data = password.into_bytes();
        clipboard_data.push(b'\n');
        copy_to_clipboard(&clipboard_data)?;
    } else {
        println!("{password}");
    }

    Ok(0)
}

fn parse_generate_args(args: &[String]) -> Result<GenerateArgs, String> {
    let mut username: Option<String> = None;
    let mut url: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut sync_mode = SyncMode::Auto;
    let mut no_symbols = false;
    let mut clip = false;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            positional.push(arg.clone());
            continue;
        }
        if let Some(mode) = parse_sync_option(arg, &mut iter, USAGE)? {
            sync_mode = mode;
            continue;
        }
        match arg.as_str() {
            "--clip" | "-c" => clip = true,
            "--no-symbols" => no_symbols = true,
            "--username" => {
                let next = iter.next().ok_or_else(|| USAGE.to_string())?;
                username = Some(next.clone());
            }
            "--url" => {
                let next = iter.next().ok_or_else(|| USAGE.to_string())?;
                url = Some(next.clone());
            }
            _ => {
                if let Some(value) = arg.strip_prefix("--username=") {
                    username = Some(value.to_string());
                } else if let Some(value) = arg.strip_prefix("--url=") {
                    url = Some(value.to_string());
                } else {
                    return Err(USAGE.to_string());
                }
            }
        }
    }

    if positional.len() != 2 {
        return Err(USAGE.to_string());
    }

    let name = positional.remove(0);
    let length = parse_length_like_c(&positional.remove(0))?;

    Ok(GenerateArgs {
        name,
        length,
        username,
        url,
        no_symbols,
        clip,
        sync_mode,
    })
}

fn parse_length_like_c(value: &str) -> Result<usize, String> {
    let digits: String = value.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Err(USAGE.to_string());
    }
    let length = digits.parse::<usize>().map_err(|_| USAGE.to_string())?;
    if length == 0 {
        return Err(USAGE.to_string());
    }
    Ok(length)
}

fn update_existing_account(
    account: &mut Account,
    parsed: &GenerateArgs,
    password: &str,
) -> Result<Account, String> {
    if account.share_readonly {
        let share_name = account.share_name.as_deref().unwrap_or("(unknown)");
        return Err(format!(
            "{} is a readonly shared entry from {}. It cannot be edited.",
            account.fullname, share_name
        ));
    }

    let original = account.clone();
    let expanded = expand_notes(&original);
    let mut working = expanded.clone().unwrap_or(original);

    if let Some(value) = parsed.username.as_ref() {
        working.username = value.clone();
    }
    if let Some(value) = parsed.url.as_ref() {
        working.url = value.clone();
    }
    working.password = password.to_string();

    let updated = if expanded.is_some() {
        collapse_notes(&working)
    } else {
        working
    };

    *account = updated.clone();
    Ok(updated)
}

fn generate_password(len: usize, no_symbols: bool) -> String {
    let chars = password_charset(no_symbols).as_bytes();
    let mut rng = thread_rng();
    let mut password = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.gen_range(0..chars.len());
        password.push(chars[idx] as char);
    }
    password
}

fn password_charset(no_symbols: bool) -> &'static str {
    if no_symbols {
        &ALL_CHARS[..NICE_CHARS_LEN]
    } else {
        ALL_CHARS
    }
}

fn find_unique_account_index(accounts: &[Account], name: &str) -> Result<Option<usize>, String> {
    if name != "0"
        && let Some((idx, _)) = accounts
            .iter()
            .enumerate()
            .find(|(_, account)| account.id.eq_ignore_ascii_case(name))
    {
        return Ok(Some(idx));
    }

    let matches: Vec<usize> = accounts
        .iter()
        .enumerate()
        .filter(|(_, account)| account.fullname == name || account.name == name)
        .map(|(idx, _)| idx)
        .collect();

    if matches.is_empty() {
        return Ok(None);
    }
    if matches.len() > 1 {
        return Err(format!(
            "Multiple matches found for '{name}'. You must specify an ID instead of a name."
        ));
    }
    Ok(matches.into_iter().next())
}

fn build_account(fullname: &str, blob: &Blob) -> Result<Account, String> {
    let (group, name) = split_group(fullname);
    let mut account = Account {
        id: "0".to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name,
        name_encrypted: None,
        group,
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
        last_touch: "skipped".to_string(),
        last_modified_gmt: "skipped".to_string(),
        fav: false,
        pwprotect: false,
        attachkey: String::new(),
        attachkey_encrypted: None,
        attachpresent: false,
        fields: Vec::new(),
    };

    assign_share(&mut account, blob)?;
    Ok(account)
}

fn populate_new_account(mut account: Account, parsed: &GenerateArgs, password: &str) -> Account {
    account.username = parsed.username.clone().unwrap_or_default();
    account.url = parsed.url.clone().unwrap_or_default();
    account.password = password.to_string();
    account
}

fn assign_share(account: &mut Account, blob: &Blob) -> Result<(), String> {
    let shares = collect_shares(&blob.accounts, &blob.shares);
    let Some(share) = infer_share(&account.fullname, &shares) else {
        if is_shared_folder_name(&account.fullname) {
            return Err(format!(
                "Unable to find shared folder for {} in blob",
                account.fullname
            ));
        }
        return Ok(());
    };

    let path = &account.fullname[share.name.len() + 1..];
    let (group, name) = split_group(path);
    account.share_name = Some(share.name.clone());
    account.share_id = share.id.clone();
    account.share_readonly = share.readonly;
    account.group = group;
    account.name = name;
    Ok(())
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

fn infer_share<'a>(fullname: &str, shares: &'a [ShareRef]) -> Option<&'a ShareRef> {
    shares
        .iter()
        .find(|share| fullname.starts_with(&(share.name.to_string() + "/")))
}

fn is_shared_folder_name(fullname: &str) -> bool {
    fullname.starts_with("Shared-") && fullname.contains('/')
}

fn split_group(full: &str) -> (String, String) {
    if let Some(pos) = full.rfind('/') {
        let group = full[..pos].to_string();
        let name = full[pos + 1..].to_string();
        return (group, name);
    }
    (String::new(), full.to_string())
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
    fn parse_generate_args_supports_core_options() {
        let parsed = parse_generate_args(&[
            "--sync=no".to_string(),
            "--clip".to_string(),
            "--username=alice".to_string(),
            "--url".to_string(),
            "https://example.com".to_string(),
            "--no-symbols".to_string(),
            "team/entry".to_string(),
            "20".to_string(),
        ])
        .expect("parse args");

        assert_eq!(
            parsed,
            GenerateArgs {
                name: "team/entry".to_string(),
                length: 20,
                username: Some("alice".to_string()),
                url: Some("https://example.com".to_string()),
                no_symbols: true,
                clip: true,
                sync_mode: SyncMode::No,
            }
        );
    }

    #[test]
    fn parse_generate_args_rejects_usage_errors() {
        let err = parse_generate_args(&["--sync".to_string()]).expect_err("missing sync value");
        assert!(err.contains("usage: generate"));

        let err = parse_generate_args(&["--sync=bad".to_string()]).expect_err("bad sync value");
        assert!(err.contains("usage: generate"));

        let err = parse_generate_args(&["name".to_string(), "0".to_string()]).expect_err("zero");
        assert!(err.contains("usage: generate"));

        let err =
            parse_generate_args(&["name".to_string(), "abc".to_string()]).expect_err("not number");
        assert!(err.contains("usage: generate"));
    }

    #[test]
    fn parse_generate_args_rejects_missing_values_unknown_flags_and_wrong_arity() {
        let err =
            parse_generate_args(&["--username".to_string()]).expect_err("missing username value");
        assert!(err.contains("usage: generate"));

        let err =
            parse_generate_args(&["--bogus".to_string(), "entry".to_string(), "16".to_string()])
                .expect_err("unknown flag");
        assert!(err.contains("usage: generate"));

        let err = parse_generate_args(&["entry".to_string()]).expect_err("wrong arity");
        assert!(err.contains("usage: generate"));
    }

    #[test]
    fn parse_length_like_c_accepts_numeric_prefixes() {
        assert_eq!(parse_length_like_c("16xyz").expect("numeric prefix"), 16);
    }

    #[test]
    fn password_charset_matches_upstream_ranges() {
        assert_eq!(password_charset(true), &ALL_CHARS[..NICE_CHARS_LEN]);
        assert!(password_charset(false).contains('`'));
        assert!(password_charset(false).contains('?'));
    }

    #[test]
    fn generate_password_respects_requested_charset() {
        let generated = generate_password(64, true);
        assert_eq!(generated.len(), 64);
        assert!(
            generated
                .chars()
                .all(|ch| password_charset(true).contains(ch))
        );
    }

    #[test]
    fn find_unique_account_matches_id_name_and_detects_ambiguity() {
        let accounts = vec![
            account("0001", "same", "g1"),
            account("0002", "same", "g2"),
            account("0003", "unique", ""),
        ];

        assert_eq!(
            find_unique_account_index(&accounts, "0002").expect("id"),
            Some(1)
        );
        assert_eq!(
            find_unique_account_index(&accounts, "unique").expect("name"),
            Some(2)
        );
        assert_eq!(
            find_unique_account_index(&accounts, "missing").expect("missing"),
            None
        );
        let err = find_unique_account_index(&accounts, "same").expect_err("ambiguous");
        assert!(err.contains("Multiple matches found"));
    }

    #[test]
    fn find_unique_account_allows_name_zero_without_id_match() {
        let accounts = vec![account("7", "0", "")];
        assert_eq!(
            find_unique_account_index(&accounts, "0").expect("name"),
            Some(0)
        );
    }

    #[test]
    fn build_account_assigns_share_metadata_and_strips_share_from_group() {
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: vec![Share {
                id: "77".to_string(),
                name: "Team".to_string(),
                readonly: false,
                key: None,
            }],
            accounts: Vec::new(),
            attachments: Vec::new(),
        };

        let account = build_account("Team/apps/entry", &blob).expect("build shared");
        assert_eq!(account.id, "0");
        assert_eq!(account.share_name.as_deref(), Some("Team"));
        assert_eq!(account.share_id.as_deref(), Some("77"));
        assert_eq!(account.group, "apps");
        assert_eq!(account.name, "entry");
        assert_eq!(account.fullname, "Team/apps/entry");
    }

    #[test]
    fn build_account_rejects_missing_shared_folder_prefix() {
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: Vec::new(),
            attachments: Vec::new(),
        };

        let err = build_account("Shared-Example/entry", &blob).expect_err("missing share");
        assert!(err.contains("Unable to find shared folder"));
    }

    #[test]
    fn collect_shares_includes_account_metadata_and_skips_duplicates() {
        let mut duplicate = account("0001", "entry", "group");
        duplicate.share_name = Some("Team".to_string());
        duplicate.share_id = Some("77".to_string());

        let mut inferred = account("0002", "entry2", "group2");
        inferred.share_name = Some("Extra".to_string());
        inferred.share_id = Some("88".to_string());
        inferred.share_readonly = true;

        let shares = collect_shares(
            &[duplicate, inferred],
            &[Share {
                id: "77".to_string(),
                name: "Team".to_string(),
                readonly: false,
                key: None,
            }],
        );

        assert_eq!(shares.len(), 2);
        assert!(
            shares
                .iter()
                .any(|share| share.name == "Team" && share.id.as_deref() == Some("77"))
        );
        assert!(shares.iter().any(|share| share.name == "Extra"
            && share.id.as_deref() == Some("88")
            && share.readonly));
    }

    #[test]
    fn update_existing_account_rejects_readonly_shared_entries() {
        let mut account = account("0001", "entry", "Team");
        account.fullname = "Team/entry".to_string();
        account.share_name = Some("Team".to_string());
        account.share_readonly = true;

        let err = update_existing_account(
            &mut account,
            &GenerateArgs {
                name: "Team/entry".to_string(),
                length: 16,
                username: None,
                url: None,
                no_symbols: false,
                clip: false,
                sync_mode: SyncMode::No,
            },
            "secret",
        )
        .expect_err("readonly");
        assert!(err.contains("readonly shared entry"));
    }

    #[test]
    fn update_existing_account_round_trips_secure_notes() {
        let mut account = account("0001", "note", "team");
        account.url = "http://sn".to_string();
        account.note =
            "NoteType: Server\nHostname: srv\nUsername: old-user\nPassword: old-pass".to_string();

        let updated = update_existing_account(
            &mut account,
            &GenerateArgs {
                name: "team/note".to_string(),
                length: 16,
                username: Some("new-user".to_string()),
                url: Some("https://example.com".to_string()),
                no_symbols: false,
                clip: false,
                sync_mode: SyncMode::No,
            },
            "new-pass",
        )
        .expect("update secure note");

        assert_eq!(updated.url, "http://sn");
        assert!(updated.note.contains("Username:new-user"));
        assert!(updated.note.contains("Password:new-pass"));
        assert!(updated.note.contains("URL:https://example.com"));
        assert_eq!(account.note, updated.note);
        assert_eq!(account.url, updated.url);
    }

    #[test]
    fn split_group_covers_root_and_nested_paths() {
        assert_eq!(
            split_group("team/alpha"),
            ("team".to_string(), "alpha".to_string())
        );
        assert_eq!(split_group("alpha"), (String::new(), "alpha".to_string()));
    }
}
