#![forbid(unsafe_code)]

use std::io::IsTerminal;

use crate::blob::Account;
use crate::commands::argparse::parse_sync_option;
use crate::commands::data::{SyncMode, load_blob};
use crate::format::format_account;
use crate::format::get_display_fullname;
use crate::terminal::{self, BOLD, FG_BLUE, FG_CYAN, FG_GREEN, NO_BOLD, RESET};
use zeroize::Zeroizing;

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", terminal::cli_failure_text(&err));
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<i32, String> {
    let usage =
        "usage: ls [--sync=auto|now|no] [--long, -l] [-m] [-u] [--color=auto|never|always] [GROUP]";
    let mut iter = args.iter().peekable();
    let mut long_listing = false;
    let mut show_mtime = true;
    let mut group: Option<String> = None;
    let mut color_mode = terminal::ColorMode::Auto;
    let mut output_format: Option<String> = None;
    let mut sync_mode = SyncMode::Auto;

    while let Some(arg) = iter.next() {
        if let Some(mode) = parse_sync_option(arg, &mut iter, usage)? {
            sync_mode = mode;
            continue;
        }
        if arg == "--long" || arg == "-l" {
            long_listing = true;
            continue;
        }
        if arg == "-m" {
            show_mtime = true;
            continue;
        }
        if arg == "-u" {
            show_mtime = false;
            continue;
        }
        if arg == "--format" || arg == "-f" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            output_format = Some(value.to_string());
            continue;
        }
        if let Some(value) = arg.strip_prefix("--format=") {
            output_format = Some(value.to_string());
            continue;
        }
        if arg == "--color" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            color_mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            color_mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            continue;
        }
        if arg.starts_with('-') {
            return Err(usage.to_string());
        }
        if group.is_some() {
            return Err(usage.to_string());
        }
        group = Some(arg.to_string());
    }
    terminal::set_color_mode(color_mode);

    let blob = load_blob(sync_mode).map_err(|err| format!("{err}"))?;

    let print_tree = color_mode == terminal::ColorMode::Always
        || (color_mode == terminal::ColorMode::Auto && std::io::stdout().is_terminal());

    let mut listing_accounts = blob.accounts.clone();
    for share in &blob.shares {
        if listing_accounts.iter().any(|account| {
            account.url == "http://group" && account.share_id.as_deref() == Some(share.id.as_str())
        }) {
            continue;
        }
        listing_accounts.push(synthetic_share_account(share));
    }

    let mut accounts: Vec<&Account> = listing_accounts.iter().collect();
    accounts.sort_by_key(|a| get_display_fullname(a));

    let group_filter = match group.as_deref() {
        Some("(none)") => Some(""),
        Some(value) => Some(value),
        None => None,
    };

    let mtime = if long_listing {
        if show_mtime { "%am " } else { "%aU " }
    } else {
        ""
    };
    let fullname = if print_tree { 'n' } else { 'N' };
    let username = if long_listing { " [username: %au]" } else { "" };
    let format = output_format.unwrap_or_else(|| {
        format!("{FG_CYAN}{mtime}{FG_GREEN}{BOLD}%a{fullname}{NO_BOLD} [id: %ai]{username}{RESET}")
    });

    if print_tree {
        let mut root = LsNode::default();
        for account in accounts {
            if !matches_group(account, group_filter) {
                continue;
            }
            insert_account(&mut root, account);
        }
        for line in render_tree_lines(&root, &format) {
            println!("{}", terminal::render_stdout(&line));
        }
    } else {
        for account in accounts {
            if !matches_group(account, group_filter) {
                continue;
            }
            let line = format_account(&format, account);
            println!("{}", terminal::render_stdout(&line));
        }
    }
    Ok(0)
}

#[derive(Debug, Default)]
struct LsNode {
    name: Option<String>,
    account: Option<Account>,
    shared: bool,
    children: Vec<LsNode>,
}

fn matches_group(account: &Account, group_filter: Option<&str>) -> bool {
    let Some(group) = group_filter else {
        return true;
    };

    if group.is_empty() {
        return account.share_name.is_none() && account.group.is_empty();
    }

    let fullname = &account.fullname;
    if !fullname.starts_with(group) {
        return false;
    }
    if group.ends_with('/') || fullname.len() == group.len() {
        return true;
    }
    fullname.as_bytes().get(group.len()) == Some(&b'/')
}

fn insert_account(root: &mut LsNode, account: &Account) {
    let mut dirname = get_display_fullname(account);
    if dirname.ends_with(&account.name) {
        dirname.truncate(dirname.len().saturating_sub(account.name.len()));
    }
    if dirname.ends_with('/') {
        let _ = dirname.pop();
    }

    let mut components: Vec<&str> = Vec::new();
    let mut remainder = dirname.as_str();
    if let Some(share_name) = account.share_name.as_deref()
        && remainder.starts_with(share_name)
    {
        components.extend(parse_path_components(share_name));
        remainder = if remainder.len() > share_name.len() {
            &remainder[share_name.len() + 1..]
        } else {
            ""
        };
    }
    components.extend(parse_path_components(remainder));

    let mut node = root;
    for component in components {
        node = get_or_insert_child(node, component, account.share_name.is_some());
    }

    if account.url == "http://group" {
        return;
    }

    node.children.push(LsNode {
        name: Some(account.name.clone()),
        account: Some(account.clone()),
        shared: account.share_name.is_some(),
        children: Vec::new(),
    });
}

fn synthetic_share_account(share: &crate::blob::Share) -> Account {
    Account {
        id: share.id.clone(),
        share_name: Some(share.name.clone()),
        share_id: Some(share.id.clone()),
        share_readonly: share.readonly,
        name: String::new(),
        name_encrypted: None,
        group: String::new(),
        group_encrypted: None,
        fullname: format!("{}/", share.name),
        url: "http://group".to_string(),
        url_encrypted: None,
        username: Zeroizing::new(String::new()),
        username_encrypted: None,
        password: Zeroizing::new(String::new()),
        password_encrypted: None,
        note: Zeroizing::new(String::new()),
        note_encrypted: None,
        last_touch: String::new(),
        last_modified_gmt: String::new(),
        fav: false,
        pwprotect: false,
        attachkey: Zeroizing::new(String::new()),
        attachkey_encrypted: None,
        attachpresent: false,
        fields: Vec::new(),
    }
}

fn parse_path_components(path: &str) -> impl Iterator<Item = &str> {
    path.split('\\').filter(|component| !component.is_empty())
}

fn get_or_insert_child<'a>(node: &'a mut LsNode, name: &str, shared: bool) -> &'a mut LsNode {
    if let Some(index) = node
        .children
        .iter()
        .position(|child| child.account.is_none() && child.name.as_deref() == Some(name))
    {
        return &mut node.children[index];
    }
    node.children.push(LsNode {
        name: Some(name.to_string()),
        account: None,
        shared,
        children: Vec::new(),
    });
    let idx = node.children.len() - 1;
    &mut node.children[idx]
}

fn render_tree_lines(root: &LsNode, format: &str) -> Vec<String> {
    let mut out = Vec::new();
    render_tree_lines_inner(root, format, 0, &mut out);
    out
}

fn render_tree_lines_inner(node: &LsNode, format: &str, level: usize, out: &mut Vec<String>) {
    for child in &node.children {
        let Some(name) = child.name.as_deref() else {
            continue;
        };
        let indent = "    ".repeat(level);
        if let Some(account) = child.account.as_ref() {
            let line = format_account(format, account);
            out.push(format!("{indent}{line}"));
        } else if child.shared {
            out.push(format!("{indent}{FG_CYAN}{BOLD}{name}{RESET}"));
        } else {
            out.push(format!("{indent}{FG_BLUE}{BOLD}{name}{RESET}"));
        }
        render_tree_lines_inner(child, format, level + 1, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{Blob, Share};
    use crate::config::{config_write_buffer, config_write_encrypted_string};
    use crate::kdf::KDF_HASH_LEN;
    use crate::session::{Session, session_save};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    fn account(
        id: &str,
        share_name: Option<&str>,
        group: &str,
        name: &str,
        fullname: &str,
        url: &str,
    ) -> Account {
        Account {
            id: id.to_string(),
            share_name: share_name.map(|value| value.to_string()),
            share_id: None,
            share_readonly: false,
            name: name.to_string(),
            name_encrypted: None,
            group: group.to_string(),
            group_encrypted: None,
            fullname: fullname.to_string(),
            url: url.to_string(),
            url_encrypted: None,
            username: Zeroizing::new(String::new()),
            username_encrypted: None,
            password: Zeroizing::new(String::new()),
            password_encrypted: None,
            note: Zeroizing::new(String::new()),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: Zeroizing::new(String::new()),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        }
    }

    #[test]
    fn tree_renders_indented_groups_and_accounts() {
        let mut root = LsNode::default();
        let account = account(
            "1",
            None,
            "personal\\infra",
            "vault",
            "personal\\infra/vault",
            "https://x",
        );
        insert_account(&mut root, &account);

        let lines = render_tree_lines(&root, "%an [id: %ai]");
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], format!("{FG_BLUE}{BOLD}personal{RESET}"));
        assert_eq!(lines[1], format!("    {FG_BLUE}{BOLD}infra{RESET}"));
        assert_eq!(lines[2], "        vault [id: 1]");
    }

    #[test]
    fn tree_uses_cyan_for_shared_folders() {
        let mut root = LsNode::default();
        let account = account(
            "2",
            Some("Team"),
            "ops",
            "pagerduty",
            "Team/ops/pagerduty",
            "https://x",
        );
        insert_account(&mut root, &account);

        let lines = render_tree_lines(&root, "%an [id: %ai]");
        assert_eq!(lines[0], format!("{FG_CYAN}{BOLD}Team{RESET}"));
    }

    #[test]
    fn matches_none_group_filters_empty_group_only() {
        let plain = account("1", None, "", "plain", "plain", "https://x");
        let grouped = account("2", None, "group", "named", "group/named", "https://x");
        assert!(matches_group(&plain, Some("")));
        assert!(!matches_group(&grouped, Some("")));
    }

    #[test]
    fn matches_group_handles_prefix_and_separator_rules() {
        let account = account(
            "1",
            None,
            "team/sub",
            "entry",
            "team/sub/entry",
            "https://x",
        );
        assert!(matches_group(&account, Some("team")));
        assert!(matches_group(&account, Some("team/sub")));
        assert!(matches_group(&account, Some("team/sub/")));
        assert!(!matches_group(&account, Some("tea")));
        assert!(!matches_group(&account, Some("other")));
        assert!(matches_group(&account, None));
    }

    #[test]
    fn insert_account_skips_group_markers() {
        let mut root = LsNode::default();
        let group_marker = account("9", None, "team", "folder", "team/folder", "http://group");
        insert_account(&mut root, &group_marker);
        let lines = render_tree_lines(&root, "%an [id: %ai]");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], format!("{FG_BLUE}{BOLD}team{RESET}"));
    }

    #[test]
    fn parse_path_components_ignores_empty_segments() {
        let parts: Vec<&str> = parse_path_components("\\a\\\\b\\").collect();
        assert_eq!(parts, vec!["a", "b"]);
    }

    #[test]
    fn get_or_insert_child_reuses_existing_node() {
        let mut root = LsNode::default();
        let first_ptr = {
            let child = get_or_insert_child(&mut root, "team", false);
            child as *mut LsNode
        };
        let second_ptr = {
            let child = get_or_insert_child(&mut root, "team", false);
            child as *mut LsNode
        };
        assert_eq!(first_ptr, second_ptr);
        assert_eq!(root.children.len(), 1);
    }

    #[test]
    fn insert_account_with_share_name_matching_full_dirname() {
        let mut root = LsNode::default();
        let acct = account("1", Some("Team"), "", "entry", "Team/entry", "https://x");
        insert_account(&mut root, &acct);

        let lines = render_tree_lines(&root, "%an [id: %ai]");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], format!("{FG_CYAN}{BOLD}Team{RESET}"));
        assert_eq!(lines[1], "    entry [id: 1]");
    }

    #[test]
    fn render_tree_lines_skips_nameless_nodes() {
        let root = LsNode {
            name: None,
            account: None,
            shared: false,
            children: vec![
                LsNode {
                    name: None,
                    account: None,
                    shared: false,
                    children: Vec::new(),
                },
                LsNode {
                    name: Some("visible".to_string()),
                    account: None,
                    shared: false,
                    children: Vec::new(),
                },
            ],
        };
        let lines = render_tree_lines(&root, "%an");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("visible"));
    }

    #[test]
    fn run_inner_rejects_invalid_option_combinations() {
        let err = run_inner(&["--color".to_string()]).expect_err("missing color value");
        assert!(err.contains("usage: ls"));

        let err = run_inner(&["--sync".to_string()]).expect_err("missing sync value");
        assert!(err.contains("usage: ls"));

        let err = run_inner(&["--sync=bad".to_string()]).expect_err("bad sync value");
        assert!(err.contains("usage: ls"));

        let err = run_inner(&["--format".to_string()]).expect_err("missing format value");
        assert!(err.contains("usage: ls"));

        let err = run_inner(&["--bogus".to_string()]).expect_err("unknown flag");
        assert!(err.contains("usage: ls"));

        let err = run_inner(&["a".to_string(), "b".to_string()]).expect_err("two groups");
        assert!(err.contains("usage: ls"));
    }

    fn write_mock_state(_home: &TempDir, blob: &Blob) {
        let key = [7u8; KDF_HASH_LEN];
        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        crate::config::config_write_string("username", "tester").expect("username");
        session_save(
            &Session {
                uid: "u1".to_string(),
                session_id: "s1".to_string(),
                token: "t1".to_string(),
                url_encryption_enabled: false,
                url_logging_enabled: false,
                server: None,
                private_key: None,
                private_key_enc: None,
            },
            &key,
        )
        .expect("session save");
        crate::commands::data::save_blob(blob).expect("write blob");
    }

    fn make_test_blob() -> Blob {
        Blob {
            version: 1,
            local_version: false,
            shares: vec![Share {
                id: "share1".to_string(),
                name: "Shared".to_string(),
                readonly: false,
                key: None,
            }],
            accounts: vec![
                account(
                    "0001",
                    None,
                    "team",
                    "server",
                    "team/server",
                    "https://example.com",
                ),
                account("0002", None, "", "plain-entry", "plain-entry", "https://x"),
                {
                    let mut acct = account(
                        "0003",
                        Some("Shared"),
                        "ops",
                        "shared-entry",
                        "Shared/ops/shared-entry",
                        "https://y",
                    );
                    acct.share_id = Some("share1".to_string());
                    acct
                },
                {
                    // Group marker for the share — dedup should skip synthetic account
                    let mut marker =
                        account("0004", Some("Shared"), "", "", "Shared/", "http://group");
                    marker.share_id = Some("share1".to_string());
                    marker
                },
            ],
            attachments: Vec::new(),
        }
    }

    #[test]
    fn run_inner_mock_m_flag_and_format_equals_syntax() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        write_mock_state(&home, &make_test_blob());

        // Covers lines 44-45 (-m flag) and 57-58 (--format= equals syntax)
        assert_eq!(
            run_inner(&[
                "--sync=no".to_string(),
                "-m".to_string(),
                "--format=%aN".to_string(),
            ])
            .expect("-m and --format="),
            0
        );
    }

    #[test]
    fn run_inner_mock_color_space_separated() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        write_mock_state(&home, &make_test_blob());

        // Covers lines 62-63 (--color space-separated)
        assert_eq!(
            run_inner(&[
                "--sync=no".to_string(),
                "--color".to_string(),
                "never".to_string(),
            ])
            .expect("--color never"),
            0
        );
    }

    #[test]
    fn run_inner_mock_share_dedup_and_none_group() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        write_mock_state(&home, &make_test_blob());

        // Covers lines 87-89 (share dedup — the blob has a share and a group marker)
        // and lines 98-99 ((none) group filter)
        assert_eq!(
            run_inner(&[
                "--sync=no".to_string(),
                "--color=never".to_string(),
                "(none)".to_string(),
            ])
            .expect("(none) group"),
            0
        );
    }

    #[test]
    fn run_inner_mock_tree_rendering_always_color() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        write_mock_state(&home, &make_test_blob());

        // Covers lines 115-124 (tree rendering path when color_mode is Always)
        assert_eq!(
            run_inner(&["--sync=no".to_string(), "--color=always".to_string(),])
                .expect("tree always"),
            0
        );
    }

    #[test]
    fn run_inner_mock_non_tree_group_filter_skip() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        write_mock_state(&home, &make_test_blob());

        // Covers line 128 (continue in non-tree rendering with group filter)
        assert_eq!(
            run_inner(&[
                "--sync=no".to_string(),
                "--color=never".to_string(),
                "team".to_string(),
            ])
            .expect("non-tree group filter"),
            0
        );
    }
}
