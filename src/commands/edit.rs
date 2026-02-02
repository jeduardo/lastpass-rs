#![forbid(unsafe_code)]

use std::io::{self, Read};

use crate::blob::{Account, Field};
use crate::commands::data::{load_blob, save_blob};
use crate::notes::{NoteType, collapse_notes, expand_notes, note_type_by_name};
use crate::terminal;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum EditChoice {
    Any,
    Username,
    Password,
    Url,
    Notes,
    Field,
    Name,
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
    let usage = "usage: edit [--sync=auto|now|no] [--non-interactive] [--color=auto|never|always] {--name|--username|--password|--url|--notes|--field=FIELD} {NAME|UNIQUEID}";
    let mut choice = EditChoice::Any;
    let mut field_name: Option<String> = None;
    let mut non_interactive = false;
    let mut name: Option<String> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            name = Some(arg.clone());
            continue;
        }

        if arg == "--non-interactive" {
            non_interactive = true;
        } else if arg == "--username" {
            set_choice(&mut choice, EditChoice::Username)?;
        } else if arg == "--password" {
            set_choice(&mut choice, EditChoice::Password)?;
        } else if arg == "--url" {
            set_choice(&mut choice, EditChoice::Url)?;
        } else if arg == "--notes" {
            set_choice(&mut choice, EditChoice::Notes)?;
        } else if arg == "--name" {
            set_choice(&mut choice, EditChoice::Name)?;
        } else if arg == "--field" {
            set_choice(&mut choice, EditChoice::Field)?;
            if let Some(next) = iter.next() {
                field_name = Some(next.clone());
            }
        } else if let Some(value) = arg.strip_prefix("--field=") {
            set_choice(&mut choice, EditChoice::Field)?;
            field_name = Some(value.to_string());
        } else if arg.starts_with("--sync=") {
            // ignored
        } else if arg == "--sync" {
            let _ = iter.next();
        } else if arg == "--color" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
        } else if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
        } else {
            return Err(usage.to_string());
        }
    }

    let name = name.ok_or_else(|| usage.to_string())?;

    if !non_interactive {
        return Err("interactive edit not implemented; use --non-interactive".to_string());
    }

    if choice == EditChoice::Field && field_name.is_none() {
        return Err("missing --field name".to_string());
    }

    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("stdin: {err}"))?;
    trim_trailing_newlines(&mut input);

    let mut blob = load_blob().map_err(|err| format!("{err}"))?;
    let idx = find_account_index(&blob.accounts, &name)
        .ok_or_else(|| "Could not find specified account(s).".to_string())?;

    let original = blob.accounts[idx].clone();
    let (mut working, secure_note) = match expand_notes(&original) {
        Some(expanded) => (expanded, true),
        None => (original.clone(), false),
    };

    match choice {
        EditChoice::Username => working.username = input,
        EditChoice::Password => working.password = input,
        EditChoice::Url => working.url = input,
        EditChoice::Notes => working.note = input,
        EditChoice::Name => apply_fullname(&mut working, &input),
        EditChoice::Field => {
            let field_name = field_name.unwrap_or_default();
            if !secure_note {
                return Err(
                    "Editing fields of entries that are not secure notes is currently not supported."
                        .to_string(),
                );
            }
            apply_field(&mut working, &field_name, &input);
        }
        EditChoice::Any => {
            let update = parse_update_input(&input);
            apply_update(&mut working, &update, secure_note);
        }
    }

    let updated = if secure_note {
        collapse_notes(&working)
    } else {
        working
    };
    blob.accounts[idx] = updated;

    save_blob(&blob).map_err(|err| format!("{err}"))?;
    Ok(0)
}

fn set_choice(choice: &mut EditChoice, next: EditChoice) -> Result<(), String> {
    if *choice != EditChoice::Any {
        return Err("usage: edit [--sync=auto|now|no] [--non-interactive] [--color=auto|never|always] {--name|--username|--password|--url|--notes|--field=FIELD} {NAME|UNIQUEID}".to_string());
    }
    *choice = next;
    Ok(())
}

fn trim_trailing_newlines(value: &mut String) {
    while matches!(value.chars().last(), Some('\n') | Some('\r')) {
        value.pop();
    }
}

fn find_account_index(accounts: &[Account], name: &str) -> Option<usize> {
    if name != "0" {
        if let Some((idx, _)) = accounts
            .iter()
            .enumerate()
            .find(|(_, acct)| acct.id.eq_ignore_ascii_case(name))
        {
            return Some(idx);
        }
    }

    accounts
        .iter()
        .enumerate()
        .find(|(_, acct)| acct.fullname == name || acct.name == name)
        .map(|(idx, _)| idx)
}

fn apply_fullname(account: &mut Account, fullname: &str) {
    let trimmed = fullname.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Some(pos) = trimmed.rfind('/') {
        account.group = trimmed[..pos].to_string();
        account.name = trimmed[pos + 1..].to_string();
        account.fullname = trimmed.to_string();
    } else {
        account.group = String::new();
        account.name = trimmed.to_string();
        account.fullname = trimmed.to_string();
    }
}

fn apply_field(account: &mut Account, name: &str, value: &str) {
    if name == "Username" {
        account.username = value.to_string();
        return;
    }
    if name == "Password" {
        account.password = value.to_string();
        return;
    }
    if name == "URL" {
        account.url = value.to_string();
        return;
    }

    if let Some(field) = account.fields.iter_mut().find(|field| field.name == name) {
        field.value = value.to_string();
    } else {
        account.fields.push(Field {
            name: name.to_string(),
            field_type: "text".to_string(),
            value: value.to_string(),
            value_encrypted: None,
            checked: false,
        });
    }
}

#[derive(Debug, Default)]
struct ParsedUpdate {
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    note: Option<String>,
    fullname: Option<String>,
    reprompt: Option<bool>,
    fields: Vec<(String, String)>,
    note_type_name: Option<String>,
}

fn parse_update_input(raw: &str) -> ParsedUpdate {
    let mut update = ParsedUpdate::default();
    let lines: Vec<&str> = raw.split('\n').collect();
    let mut idx = 0usize;

    while idx < lines.len() {
        let line = lines[idx];
        let Some((key, value)) = split_key_value(line) else {
            idx += 1;
            continue;
        };
        let value = value.trim_start().to_string();

        if key == "Notes" {
            let mut note_value = value;
            if idx + 1 < lines.len() {
                let rest = lines[idx + 1..].join("\n");
                if !rest.is_empty() {
                    if !note_value.is_empty() {
                        note_value.push('\n');
                    }
                    note_value.push_str(&rest);
                }
            }
            update.note = Some(note_value);
            break;
        }

        match key {
            "Username" => update.username = Some(value),
            "Password" => update.password = Some(value),
            "URL" => update.url = Some(value),
            "Name" => update.fullname = Some(value),
            "Reprompt" => update.reprompt = parse_yes_no(&value),
            "NoteType" => update.note_type_name = Some(value),
            _ => update.fields.push((key.to_string(), value)),
        }

        idx += 1;
    }

    update
}

fn apply_update(account: &mut Account, update: &ParsedUpdate, secure_note: bool) {
    if let Some(value) = &update.username {
        account.username = value.clone();
    }
    if let Some(value) = &update.password {
        account.password = value.clone();
    }
    if let Some(value) = &update.url {
        account.url = value.clone();
    }
    if let Some(value) = &update.note {
        account.note = value.clone();
    }
    if let Some(value) = &update.fullname {
        apply_fullname(account, value);
    }
    if let Some(value) = update.reprompt {
        account.pwprotect = value;
    }

    if secure_note {
        for (name, value) in &update.fields {
            apply_field(account, name, value);
        }
        if let Some(note_type_name) = &update.note_type_name {
            let note_type = note_type_by_name(note_type_name);
            if note_type != NoteType::None {
                apply_field(account, "NoteType", note_type_name);
            }
        }
    }
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let mut iter = line.splitn(2, ':');
    let key = iter.next()?.trim();
    let value = iter.next()?;
    Some((key, value))
}

fn parse_yes_no(value: &str) -> Option<bool> {
    if value.eq_ignore_ascii_case("yes") {
        Some(true)
    } else if value.eq_ignore_ascii_case("no") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Account {
        Account {
            id: "100".to_string(),
            share_name: None,
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
            note: "note".to_string(),
            note_encrypted: None,
            last_touch: String::new(),
            last_modified_gmt: String::new(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: vec![Field {
                name: "Hostname".to_string(),
                field_type: "text".to_string(),
                value: "old-host".to_string(),
                value_encrypted: None,
                checked: false,
            }],
        }
    }

    #[test]
    fn set_choice_rejects_multiple_choice_flags() {
        let mut choice = EditChoice::Any;
        set_choice(&mut choice, EditChoice::Username).expect("first choice");
        let err = set_choice(&mut choice, EditChoice::Password).expect_err("conflict");
        assert!(err.contains("usage: edit"));
    }

    #[test]
    fn trim_trailing_newlines_removes_crlf_suffix() {
        let mut value = "line\r\n\r\n".to_string();
        trim_trailing_newlines(&mut value);
        assert_eq!(value, "line");
    }

    #[test]
    fn find_account_index_matches_by_id_and_name() {
        let accounts = vec![account()];
        assert_eq!(find_account_index(&accounts, "100"), Some(0));
        assert_eq!(find_account_index(&accounts, "entry"), Some(0));
        assert_eq!(find_account_index(&accounts, "team/entry"), Some(0));
        assert_eq!(find_account_index(&accounts, "missing"), None);
    }

    #[test]
    fn apply_fullname_updates_group_and_name() {
        let mut acct = account();
        apply_fullname(&mut acct, "new-group/new-name");
        assert_eq!(acct.group, "new-group");
        assert_eq!(acct.name, "new-name");
        assert_eq!(acct.fullname, "new-group/new-name");

        apply_fullname(&mut acct, "single");
        assert_eq!(acct.group, "");
        assert_eq!(acct.name, "single");
        assert_eq!(acct.fullname, "single");
    }

    #[test]
    fn apply_field_updates_known_and_custom_fields() {
        let mut acct = account();
        apply_field(&mut acct, "Username", "bob");
        apply_field(&mut acct, "Password", "new-secret");
        apply_field(&mut acct, "URL", "https://new.example.com");
        apply_field(&mut acct, "Hostname", "new-host");
        apply_field(&mut acct, "Port", "443");

        assert_eq!(acct.username, "bob");
        assert_eq!(acct.password, "new-secret");
        assert_eq!(acct.url, "https://new.example.com");
        let hostname = acct
            .fields
            .iter()
            .find(|field| field.name == "Hostname")
            .expect("hostname field");
        assert_eq!(hostname.value, "new-host");
        assert!(acct.fields.iter().any(|field| field.name == "Port"));
    }

    #[test]
    fn parse_update_input_parses_standard_and_notes_payloads() {
        let parsed = parse_update_input(
            "Username: bob\nPassword: p\nURL: https://u\nName: grp/item\nReprompt: yes\nNoteType: Server\nHostname: srv\nNotes: line1\nline2",
        );
        assert_eq!(parsed.username.as_deref(), Some("bob"));
        assert_eq!(parsed.password.as_deref(), Some("p"));
        assert_eq!(parsed.url.as_deref(), Some("https://u"));
        assert_eq!(parsed.fullname.as_deref(), Some("grp/item"));
        assert_eq!(parsed.reprompt, Some(true));
        assert_eq!(parsed.note_type_name.as_deref(), Some("Server"));
        assert_eq!(parsed.note.as_deref(), Some("line1\nline2"));
        assert_eq!(parsed.fields, vec![("Hostname".to_string(), "srv".to_string())]);
    }

    #[test]
    fn apply_update_applies_fields_for_secure_notes_only() {
        let mut acct_secure = account();
        let mut update = ParsedUpdate {
            username: Some("bob".to_string()),
            password: Some("new-pass".to_string()),
            url: Some("https://new.example.com".to_string()),
            note: Some("updated".to_string()),
            fullname: Some("ops/db".to_string()),
            reprompt: Some(true),
            fields: vec![("Hostname".to_string(), "db.example.com".to_string())],
            note_type_name: Some("Server".to_string()),
        };

        apply_update(&mut acct_secure, &update, true);
        assert_eq!(acct_secure.username, "bob");
        assert_eq!(acct_secure.password, "new-pass");
        assert_eq!(acct_secure.url, "https://new.example.com");
        assert_eq!(acct_secure.note, "updated");
        assert_eq!(acct_secure.fullname, "ops/db");
        assert!(acct_secure.pwprotect);
        assert!(
            acct_secure
                .fields
                .iter()
                .any(|field| field.name == "NoteType" && field.value == "Server")
        );
        assert!(
            acct_secure
                .fields
                .iter()
                .any(|field| field.name == "Hostname" && field.value == "db.example.com")
        );

        let mut acct_non_secure = account();
        update.fields = vec![("Hostname".to_string(), "ignored".to_string())];
        apply_update(&mut acct_non_secure, &update, false);
        assert!(
            !acct_non_secure
                .fields
                .iter()
                .any(|field| field.value == "ignored")
        );
    }

    #[test]
    fn parse_yes_no_supports_yes_no_only() {
        assert_eq!(parse_yes_no("yes"), Some(true));
        assert_eq!(parse_yes_no("No"), Some(false));
        assert_eq!(parse_yes_no("maybe"), None);
    }

    #[test]
    fn run_inner_validates_arguments_before_blob_access() {
        let err = run_inner(&[]).expect_err("missing target");
        assert!(err.contains("usage: edit"));

        let err = run_inner(&["--username".to_string(), "--password".to_string(), "x".to_string()])
            .expect_err("conflicting selectors");
        assert!(err.contains("usage: edit"));

        let err = run_inner(&[
            "--non-interactive".to_string(),
            "x".to_string(),
            "--field".to_string(),
        ])
        .expect_err("missing field name");
        assert!(err.contains("missing --field name"));
    }
}
