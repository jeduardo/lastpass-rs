#![forbid(unsafe_code)]

use crate::agent::{agent_get_decryption_key, agent_load_on_disk_key};
use crate::blob::Account;
use crate::commands::argparse::parse_sync_option;
use crate::commands::data::{SyncMode, load_blob, maybe_log_access};
use crate::kdf::KDF_HASH_LEN;
use crate::terminal;

const DEFAULT_FIELDS: &[&str] = &[
    "url", "username", "password", "extra", "name", "grouping", "fav",
];

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
        "usage: export [--sync=auto|now|no] [--color=auto|never|always] [--fields=FIELDLIST]";
    let mut fields: Vec<String> = Vec::new();
    let mut sync_mode = SyncMode::Auto;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            return Err(usage.to_string());
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
        if arg == "--fields" {
            let next = iter.next().ok_or_else(|| usage.to_string())?;
            fields.extend(parse_fields(next));
            continue;
        }
        if let Some(value) = arg.strip_prefix("--fields=") {
            fields.extend(parse_fields(value));
            continue;
        }
        return Err(usage.to_string());
    }

    if fields.is_empty() {
        fields = DEFAULT_FIELDS.iter().map(|item| item.to_string()).collect();
    }

    let blob = load_blob(sync_mode).map_err(|err| format!("{err}"))?;
    authenticate_protected_entries(&blob.accounts)?;
    let mut out = String::new();

    write_row(&fields, &mut out);

    for account in blob.accounts.iter().rev() {
        if account.url == "http://group" {
            continue;
        }
        let row: Vec<String> = fields
            .iter()
            .map(|field| export_value(account, field))
            .collect();
        write_row(&row, &mut out);
        maybe_log_access(account, sync_mode).map_err(|err| format!("{err}"))?;
    }

    print!("{out}");
    Ok(0)
}

fn parse_fields(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
        .collect()
}

fn export_value(account: &Account, field: &str) -> String {
    match field {
        "url" => account.url.clone(),
        "username" => account.username.clone(),
        "password" => account.password.clone(),
        "extra" => account.note.clone(),
        "name" => account.name.clone(),
        "grouping" => grouping_value(account),
        "fav" => bool_str(account.fav),
        "id" => account.id.clone(),
        "group" => account.group.clone(),
        "fullname" => account.fullname.clone(),
        "last_touch" => account.last_touch.clone(),
        "last_modified_gmt" => account.last_modified_gmt.clone(),
        "attachpresent" => bool_str(account.attachpresent),
        _ => String::new(),
    }
}

fn grouping_value(account: &Account) -> String {
    match account.share_name.as_deref() {
        Some(share_name) if account.group.is_empty() => share_name.to_string(),
        Some(share_name) => format!(r"{share_name}\{}", account.group),
        None => account.group.clone(),
    }
}

fn bool_str(value: bool) -> String {
    if value {
        "1".to_string()
    } else {
        "0".to_string()
    }
}

fn write_row(fields: &[String], out: &mut String) {
    for (idx, field) in fields.iter().enumerate() {
        let cell = csv_cell(field);
        out.push_str(&cell);
        if idx + 1 == fields.len() {
            out.push_str("\r\n");
        } else {
            out.push(',');
        }
    }
}

fn csv_cell(value: &str) -> String {
    let needs_quote = value
        .chars()
        .any(|ch| ch == '"' || ch == ',' || ch == '\n' || ch == '\r');
    if !needs_quote {
        return value.to_string();
    }

    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        out.push(ch);
        if ch == '"' {
            out.push('"');
        }
    }
    out.push('"');
    out
}

fn authenticate_protected_entries(accounts: &[Account]) -> Result<(), String> {
    if !accounts.iter().any(|account| account.pwprotect) {
        return Ok(());
    }

    let prompted_key = agent_load_on_disk_key()
        .map_err(|_| "Could not authenticate for protected entry.".to_string())?;
    let current_key = agent_get_decryption_key()
        .map_err(|_| "Could not authenticate for protected entry.".to_string())?;
    ensure_current_key_matches(prompted_key, current_key)
}

fn ensure_current_key_matches(
    prompted_key: [u8; KDF_HASH_LEN],
    current_key: [u8; KDF_HASH_LEN],
) -> Result<(), String> {
    if prompted_key == current_key {
        Ok(())
    } else {
        Err("Current key is not on-disk key.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::Account;
    use crate::config::{
        ConfigEnv, config_write_buffer, config_write_encrypted_string, config_write_string,
        set_test_env,
    };
    use crate::kdf::kdf_decryption_key;
    use tempfile::TempDir;

    fn account() -> Account {
        Account {
            id: "42".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: "entry".to_string(),
            name_encrypted: None,
            group: "team".to_string(),
            group_encrypted: None,
            fullname: "team/entry".to_string(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: "alice".to_string(),
            username_encrypted: None,
            password: "secret".to_string(),
            password_encrypted: None,
            note: "line1\nline2".to_string(),
            note_encrypted: None,
            last_touch: "yesterday".to_string(),
            last_modified_gmt: "now".to_string(),
            fav: true,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: true,
            fields: Vec::new(),
        }
    }

    #[test]
    fn parse_fields_ignores_empty_segments() {
        let fields = parse_fields("url,,username,password,");
        assert_eq!(fields, vec!["url", "username", "password"]);
    }

    #[test]
    fn export_value_maps_known_fields() {
        let account = account();
        assert_eq!(export_value(&account, "url"), "https://example.com");
        assert_eq!(export_value(&account, "username"), "alice");
        assert_eq!(export_value(&account, "password"), "secret");
        assert_eq!(export_value(&account, "extra"), "line1\nline2");
        assert_eq!(export_value(&account, "name"), "entry");
        assert_eq!(export_value(&account, "grouping"), "team");
        assert_eq!(export_value(&account, "fav"), "1");
        assert_eq!(export_value(&account, "attachpresent"), "1");
        assert_eq!(export_value(&account, "id"), "42");
        assert_eq!(export_value(&account, "group"), "team");
        assert_eq!(export_value(&account, "fullname"), "team/entry");
        assert_eq!(export_value(&account, "last_touch"), "yesterday");
        assert_eq!(export_value(&account, "last_modified_gmt"), "now");
        assert_eq!(export_value(&account, "unknown"), "");
    }

    #[test]
    fn write_row_quotes_special_cells() {
        let mut out = String::new();
        write_row(
            &[
                "plain".to_string(),
                "a,b".to_string(),
                "quote\"inside".to_string(),
            ],
            &mut out,
        );
        assert_eq!(out, "plain,\"a,b\",\"quote\"\"inside\"\r\n");
    }

    #[test]
    fn csv_cell_quotes_newlines_and_crlf() {
        assert_eq!(csv_cell("hello"), "hello");
        assert_eq!(csv_cell("a\nb"), "\"a\nb\"");
        assert_eq!(csv_cell("a\rb"), "\"a\rb\"");
    }

    #[test]
    fn run_inner_rejects_positional_arguments() {
        let err = run_inner(&["unexpected".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: export"));
    }

    #[test]
    fn run_inner_rejects_invalid_color_mode() {
        let err = run_inner(&["--color=rainbow".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: export"));

        let err = run_inner(&["--sync".to_string()]).expect_err("missing sync value");
        assert!(err.contains("usage: export"));

        let err = run_inner(&["--sync=bad".to_string()]).expect_err("bad sync value");
        assert!(err.contains("usage: export"));

        let err = run_inner(&["--fields".to_string()]).expect_err("missing fields value");
        assert!(err.contains("usage: export"));

        let err = run_inner(&["--bogus".to_string()]).expect_err("unknown flag");
        assert!(err.contains("usage: export"));
    }

    #[test]
    fn run_inner_accepts_color_and_exports_in_mock_mode() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        let blob = crate::blob::Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![account()],
            attachments: Vec::new(),
        };
        let store = crate::config::ConfigStore::with_env(crate::config::ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..crate::config::ConfigEnv::default()
        });
        let blob_json = serde_json::to_vec(&blob).expect("blob json");
        store.write_buffer("blob", &blob_json).expect("write blob");

        let status = run_inner(&[
            "--sync=no".to_string(),
            "--color".to_string(),
            "never".to_string(),
        ])
        .expect("default export");
        assert_eq!(status, 0);

        let status = run_inner(&[
            "--sync=no".to_string(),
            "--color=always".to_string(),
            "--fields".to_string(),
            "name,grouping,fav,attachpresent".to_string(),
        ])
        .expect("custom fields export");
        assert_eq!(status, 0);
    }

    #[test]
    fn bool_str_returns_zero_for_false() {
        assert_eq!(bool_str(false), "0");
    }

    #[test]
    fn grouping_value_includes_share_name_with_backslash() {
        let mut account = account();
        account.share_name = Some("Shared".to_string());
        assert_eq!(grouping_value(&account), r"Shared\team");

        account.group.clear();
        assert_eq!(grouping_value(&account), "Shared");
    }

    #[test]
    fn ensure_current_key_matches_rejects_mismatch() {
        assert!(ensure_current_key_matches([1u8; KDF_HASH_LEN], [1u8; KDF_HASH_LEN]).is_ok());
        let err = ensure_current_key_matches([1u8; KDF_HASH_LEN], [2u8; KDF_HASH_LEN])
            .expect_err("mismatch");
        assert!(err.contains("Current key is not on-disk key."));
    }

    #[test]
    fn authenticate_protected_entries_skips_unprotected_accounts() {
        assert!(authenticate_protected_entries(&[account()]).is_ok());
    }

    #[test]
    fn authenticate_protected_entries_reports_auth_failure() {
        let protected = Account {
            pwprotect: true,
            ..account()
        };
        let err = authenticate_protected_entries(&[protected]).expect_err("auth should fail");
        assert!(err.contains("Could not authenticate for protected entry."));
    }

    #[test]
    #[cfg(unix)]
    fn authenticate_protected_entries_accepts_matching_prompted_and_current_keys() {
        use std::os::unix::fs::PermissionsExt;

        let _override_guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let askpass = home.path().join("askpass.sh");
        std::fs::write(&askpass, "#!/bin/sh\necho hunter2\n").expect("write askpass");
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700))
            .expect("chmod askpass");

        let username = "user@example.com";
        let iterations = 2u32;
        let key = kdf_decryption_key(username, "hunter2", iterations).expect("derive key");
        config_write_string("iterations", &iterations.to_string()).expect("write iterations");
        config_write_string("username", username).expect("write username");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        config_write_buffer("plaintext_key", &key).expect("write key");

        crate::lpenv::set_override_for_tests("LPASS_ASKPASS", &askpass.display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_AGENT_DISABLE", "1");

        let protected = Account {
            pwprotect: true,
            ..account()
        };
        authenticate_protected_entries(&[protected]).expect("auth succeeds");
    }

    #[test]
    #[cfg(unix)]
    fn authenticate_protected_entries_reports_current_key_failure_after_prompt() {
        use std::os::unix::fs::PermissionsExt;

        let _override_guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let marker = home.path().join("askpass-used");
        let askpass = home.path().join("askpass-once.sh");
        let script = format!(
            "#!/bin/sh\nif [ -f \"{}\" ]; then\n  exit 1\nfi\ntouch \"{}\"\necho hunter2\n",
            marker.display(),
            marker.display()
        );
        std::fs::write(&askpass, script).expect("write askpass");
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700))
            .expect("chmod askpass");

        let username = "user@example.com";
        let iterations = 2u32;
        let key = kdf_decryption_key(username, "hunter2", iterations).expect("derive key");
        config_write_string("iterations", &iterations.to_string()).expect("write iterations");
        config_write_string("username", username).expect("write username");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        config_write_buffer("plaintext_key", b"bad").expect("write bad key");

        crate::lpenv::set_override_for_tests("LPASS_ASKPASS", &askpass.display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_AGENT_DISABLE", "1");

        let protected = Account {
            pwprotect: true,
            ..account()
        };
        let err = authenticate_protected_entries(&[protected]).expect_err("current key fails");
        assert!(err.contains("Could not authenticate for protected entry."));
    }
}
