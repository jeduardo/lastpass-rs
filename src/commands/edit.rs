#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::process::Command;

use crate::blob::{Account, Field};
use crate::commands::data::{SyncMode, load_blob, maybe_push_account_update, save_blob};
use crate::notes::{
    NoteType, collapse_notes, expand_notes, note_field_is_multiline, note_has_field,
    note_type_by_name, note_type_fields,
};
use crate::terminal;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum EditChoice {
    Any,
    Username,
    Password,
    Url,
    Field,
    Name,
    Notes,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct EditArgs {
    name: String,
    choice: EditChoice,
    field: Option<String>,
    non_interactive: bool,
    sync_mode: SyncMode,
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
    let parsed = parse_edit_args(args)?;
    let mut blob = load_blob(parsed.sync_mode).map_err(|err| format!("{err}"))?;

    let idx = find_unique_account_index(&blob.accounts, &parsed.name)?;
    let (mut working, secure_note_expanded, is_new) = if let Some(idx) = idx {
        let original = blob.accounts[idx].clone();
        if original.share_readonly {
            let share_name = original.share_name.as_deref().unwrap_or("(unknown)");
            return Err(format!(
                "{} is a readonly shared entry from {}. It cannot be edited.",
                original.fullname, share_name
            ));
        }
        if let Some(expanded) = expand_notes(&original) {
            (expanded, true, false)
        } else {
            (original, false, false)
        }
    } else {
        (
            new_account(&parsed.name, parsed.choice == EditChoice::Notes),
            false,
            true,
        )
    };

    if parsed.choice == EditChoice::Field && !secure_note_expanded {
        return Err(
            "Editing fields of entries that are not secure notes is currently not supported."
                .to_string(),
        );
    }

    let mut input = if parsed.non_interactive {
        read_stdin_to_string()?
    } else {
        let initial = make_editor_initial_text(&working, &parsed, secure_note_expanded);
        edit_with_editor(&initial)?
    };

    match parsed.choice {
        EditChoice::Any => {
            let note_type = account_note_type(&working);
            let update = parse_update_input(&input, note_type);
            apply_update(&mut working, &update);
        }
        _ => {
            trim_single_trailing_newline(&mut input);
            apply_choice_value(
                &mut working,
                parsed.choice,
                parsed.field.as_deref(),
                &input,
                secure_note_expanded,
            )?;
        }
    }

    let updated = if secure_note_expanded {
        collapse_notes(&working)
    } else {
        working
    };

    let updated_account = if let Some(idx) = idx {
        blob.accounts[idx] = updated;
        blob.accounts[idx].clone()
    } else {
        let mut account = updated;
        account.id = "0".to_string();
        if is_new {
            blob.accounts.push(account.clone());
        }
        account
    };

    save_blob(&blob).map_err(|err| format!("{err}"))?;
    maybe_push_account_update(&updated_account, parsed.sync_mode)
        .map_err(|err| format!("{err}"))?;
    Ok(0)
}

fn parse_edit_args(args: &[String]) -> Result<EditArgs, String> {
    let usage = "usage: edit [--sync=auto|now|no] [--non-interactive] [--color=auto|never|always] {--name|--username|--password|--url|--notes|--field=FIELD} {NAME|UNIQUEID}";
    let mut choice = EditChoice::Any;
    let mut field: Option<String> = None;
    let mut non_interactive = false;
    let mut sync_mode = SyncMode::Auto;
    let mut name: Option<String> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            if name.is_some() {
                return Err(usage.to_string());
            }
            name = Some(arg.clone());
            continue;
        }

        match arg.as_str() {
            "-u" | "--username" => set_choice(&mut choice, EditChoice::Username)?,
            "-p" | "--password" => set_choice(&mut choice, EditChoice::Password)?,
            "--url" => set_choice(&mut choice, EditChoice::Url)?,
            "--field" => {
                set_choice(&mut choice, EditChoice::Field)?;
                let Some(next) = iter.next() else {
                    return Err(usage.to_string());
                };
                field = Some(next.clone());
            }
            "--name" => set_choice(&mut choice, EditChoice::Name)?,
            "--notes" => set_choice(&mut choice, EditChoice::Notes)?,
            "--non-interactive" => non_interactive = true,
            "--sync" => {
                let Some(next) = iter.next() else {
                    return Err(usage.to_string());
                };
                let Some(mode) = SyncMode::parse(next) else {
                    return Err(usage.to_string());
                };
                sync_mode = mode;
            }
            "--color" => {
                let Some(next) = iter.next() else {
                    return Err(usage.to_string());
                };
                let Some(mode) = terminal::parse_color_mode(next) else {
                    return Err(usage.to_string());
                };
                terminal::set_color_mode(mode);
            }
            _ => {
                if let Some(value) = arg.strip_prefix("--field=") {
                    set_choice(&mut choice, EditChoice::Field)?;
                    field = Some(value.to_string());
                    continue;
                }
                if let Some(value) = arg.strip_prefix("--sync=") {
                    let Some(mode) = SyncMode::parse(value) else {
                        return Err(usage.to_string());
                    };
                    sync_mode = mode;
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
        }
    }

    let Some(name) = name else {
        return Err(usage.to_string());
    };

    Ok(EditArgs {
        name,
        choice,
        field,
        non_interactive,
        sync_mode,
    })
}

fn set_choice(choice: &mut EditChoice, next: EditChoice) -> Result<(), String> {
    if *choice != EditChoice::Any {
        return Err("usage: edit [--sync=auto|now|no] [--non-interactive] [--color=auto|never|always] {--name|--username|--password|--url|--notes|--field=FIELD} {NAME|UNIQUEID}".to_string());
    }
    *choice = next;
    Ok(())
}

fn find_unique_account_index(accounts: &[Account], name: &str) -> Result<Option<usize>, String> {
    if name != "0" {
        if let Some((idx, _)) = accounts
            .iter()
            .enumerate()
            .find(|(_, account)| account.id.eq_ignore_ascii_case(name))
        {
            return Ok(Some(idx));
        }
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

fn make_editor_initial_text(
    account: &Account,
    parsed: &EditArgs,
    secure_note_expanded: bool,
) -> String {
    match parsed.choice {
        EditChoice::Any => render_account_file(account),
        EditChoice::Username => format!("{}\n", account.username),
        EditChoice::Password => format!("{}\n", account.password),
        EditChoice::Url => format!("{}\n", account.url),
        EditChoice::Notes => format!("{}\n", account.note),
        EditChoice::Name => format!("{}\n", account.fullname),
        EditChoice::Field => {
            if !secure_note_expanded {
                return "\n".to_string();
            }
            let value = parsed
                .field
                .as_deref()
                .and_then(|field_name| account.fields.iter().find(|field| field.name == field_name))
                .map(|field| field.value.as_str())
                .unwrap_or("");
            format!("{value}\n")
        }
    }
}

fn render_account_file(account: &Account) -> String {
    let mut out = String::new();
    out.push_str("Name: ");
    out.push_str(&account.fullname);
    out.push('\n');

    let note_type = account_note_type(account);
    if note_type == NoteType::None {
        out.push_str("URL: ");
        out.push_str(&account.url);
        out.push('\n');
        out.push_str("Username: ");
        out.push_str(&account.username);
        out.push('\n');
        out.push_str("Password: ");
        out.push_str(&account.password);
        out.push('\n');
    }

    let mut fields = account.fields.clone();
    if note_type != NoteType::None {
        for field_name in note_type_fields(note_type) {
            if *field_name == "Username" || *field_name == "Password" {
                continue;
            }
            if fields.iter().any(|field| field.name == *field_name) {
                continue;
            }
            fields.push(Field {
                name: field_name.to_string(),
                field_type: "text".to_string(),
                value: String::new(),
                value_encrypted: None,
                checked: false,
            });
        }
    }

    for field in &fields {
        out.push_str(&field.name);
        out.push_str(": ");
        out.push_str(&field.value);
        out.push('\n');
    }

    if account.pwprotect {
        out.push_str("Reprompt: Yes\n");
    }

    out.push_str("Notes:    # Add notes below this line.\n");
    out.push_str(&account.note);
    out
}

fn edit_with_editor(initial: &str) -> Result<String, String> {
    let mut file = tempfile::NamedTempFile::new().map_err(|err| format!("mkstemp: {err}"))?;
    file.write_all(initial.as_bytes())
        .map_err(|err| format!("write: {err}"))?;
    file.flush().map_err(|err| format!("flush: {err}"))?;

    let editor = crate::lpenv::var("VISUAL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            crate::lpenv::var("EDITOR")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "vi".to_string());
    let path = file.path().to_string_lossy().to_string();
    let _status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} {}", shell_quote(&path)))
        .status()
        .map_err(|err| format!("system($VISUAL): {err}"))?;

    fs::read_to_string(&path).map_err(|err| format!("read: {err}"))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn read_stdin_to_string() -> Result<String, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("stdin: {err}"))?;
    Ok(input)
}

fn new_account(fullname: &str, secure_note: bool) -> Account {
    let (group, name) = split_group(fullname);
    let fullname = if group.is_empty() {
        name.clone()
    } else {
        format!("{group}/{name}")
    };

    Account {
        id: "0".to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name,
        name_encrypted: None,
        group,
        group_encrypted: None,
        fullname,
        url: if secure_note {
            "http://sn".to_string()
        } else {
            String::new()
        },
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

fn trim_single_trailing_newline(value: &mut String) {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
}

fn apply_choice_value(
    account: &mut Account,
    choice: EditChoice,
    field_name: Option<&str>,
    value: &str,
    secure_note_expanded: bool,
) -> Result<(), String> {
    match choice {
        EditChoice::Username => account.username = value.to_string(),
        EditChoice::Password => account.password = value.to_string(),
        EditChoice::Url => account.url = value.to_string(),
        EditChoice::Name => apply_fullname(account, value),
        EditChoice::Notes => account.note = value.to_string(),
        EditChoice::Field => {
            if !secure_note_expanded {
                return Err(
                    "Editing fields of entries that are not secure notes is currently not supported."
                        .to_string(),
                );
            }
            let field_name = field_name.unwrap_or_default();
            if value.is_empty() {
                account.fields.retain(|field| field.name != field_name);
            } else if let Some(field) = account
                .fields
                .iter_mut()
                .find(|field| field.name == field_name)
            {
                field.value = value.to_string();
            } else {
                account.fields.push(Field {
                    name: field_name.to_string(),
                    field_type: "text".to_string(),
                    value: value.to_string(),
                    value_encrypted: None,
                    checked: false,
                });
            }
        }
        EditChoice::Any => {}
    }
    Ok(())
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let mut iter = line.splitn(2, ':');
    let key = iter.next()?.trim();
    let value = iter.next()?;
    Some((key, value))
}

fn parse_update_input(raw: &str, note_type: NoteType) -> ParsedUpdate {
    let mut update = ParsedUpdate::default();
    let lines: Vec<&str> = raw.split('\n').collect();
    let mut current_multiline: Option<usize> = None;
    let mut idx = 0usize;

    while idx < lines.len() {
        let line = lines[idx];

        if let Some(field_idx) = current_multiline {
            if let Some((key, _)) = split_key_value(line) {
                if is_valid_field_name(note_type, key) {
                    current_multiline = None;
                } else {
                    update.fields[field_idx].1.push('\n');
                    update.fields[field_idx].1.push_str(line);
                    idx += 1;
                    continue;
                }
            } else {
                update.fields[field_idx].1.push('\n');
                update.fields[field_idx].1.push_str(line);
                idx += 1;
                continue;
            }
        }

        let Some((key, value)) = split_key_value(line) else {
            idx += 1;
            continue;
        };
        let value = value.trim_start().to_string();

        if key == "Notes" {
            let note_value = lines[idx + 1..].join("\n");
            update.note = Some(note_value);
            break;
        }

        match key {
            "Username" => update.username = Some(value),
            "Password" => update.password = Some(value),
            "URL" => update.url = Some(value),
            "Name" => update.fullname = Some(value),
            "Reprompt" => update.reprompt = parse_yes_no(&value),
            _ => {
                update.fields.push((key.to_string(), value));
                if note_field_is_multiline(note_type, key) {
                    current_multiline = Some(update.fields.len() - 1);
                }
            }
        }

        idx += 1;
    }

    update
}

fn is_valid_field_name(note_type: NoteType, name: &str) -> bool {
    if matches!(
        name,
        "Name" | "URL" | "Username" | "Password" | "Notes" | "NoteType" | "Reprompt"
    ) {
        return true;
    }
    if note_type == NoteType::None {
        return true;
    }
    note_has_field(note_type, name)
}

fn account_note_type(account: &Account) -> NoteType {
    account
        .fields
        .iter()
        .find(|field| field.name == "NoteType")
        .map(|field| note_type_by_name(&field.value))
        .unwrap_or(NoteType::None)
}

fn apply_update(account: &mut Account, update: &ParsedUpdate) {
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
    for (name, value) in &update.fields {
        if let Some(field) = account.fields.iter_mut().find(|field| field.name == *name) {
            field.value = value.clone();
        } else {
            account.fields.push(Field {
                name: name.clone(),
                field_type: "text".to_string(),
                value: value.clone(),
                value_encrypted: None,
                checked: false,
            });
        }
    }
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
    fn parse_edit_args_rejects_conflicting_selectors() {
        let err = parse_edit_args(&[
            "--username".to_string(),
            "--password".to_string(),
            "x".to_string(),
        ])
        .expect_err("must fail");
        assert!(err.contains("usage: edit"));
    }

    #[test]
    fn parse_edit_args_supports_short_options_and_sync_validation() {
        let parsed = parse_edit_args(&["-u".to_string(), "x".to_string()]).expect("args");
        assert_eq!(parsed.choice, EditChoice::Username);

        let parsed = parse_edit_args(&["-p".to_string(), "x".to_string()]).expect("args");
        assert_eq!(parsed.choice, EditChoice::Password);

        let err =
            parse_edit_args(&["--sync=bad".to_string(), "x".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: edit"));
    }

    #[test]
    fn find_unique_account_index_matches_id_name_and_detects_ambiguity() {
        let mut first = account();
        first.id = "0001".to_string();
        first.name = "same".to_string();
        first.fullname = "g1/same".to_string();

        let mut second = account();
        second.id = "0002".to_string();
        second.name = "same".to_string();
        second.fullname = "g2/same".to_string();

        let accounts = vec![first, second];
        assert_eq!(
            find_unique_account_index(&accounts, "0002").expect("id"),
            Some(1)
        );
        assert_eq!(
            find_unique_account_index(&accounts, "g1/same").expect("fullname"),
            Some(0)
        );
        let err = find_unique_account_index(&accounts, "same").expect_err("ambiguous");
        assert!(err.contains("Multiple matches found"));
    }

    #[test]
    fn trim_single_trailing_newline_removes_only_one_newline() {
        let mut value = "line\n\n".to_string();
        trim_single_trailing_newline(&mut value);
        assert_eq!(value, "line\n");
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
    fn apply_choice_value_field_path_adds_updates_and_removes() {
        let mut acct = account();
        apply_choice_value(
            &mut acct,
            EditChoice::Field,
            Some("Hostname"),
            "new-host",
            true,
        )
        .expect("update");
        assert_eq!(
            acct.fields
                .iter()
                .find(|field| field.name == "Hostname")
                .expect("field")
                .value,
            "new-host"
        );

        apply_choice_value(&mut acct, EditChoice::Field, Some("Port"), "443", true).expect("add");
        assert!(acct.fields.iter().any(|field| field.name == "Port"));

        apply_choice_value(&mut acct, EditChoice::Field, Some("Port"), "", true).expect("remove");
        assert!(!acct.fields.iter().any(|field| field.name == "Port"));

        let err = apply_choice_value(&mut acct, EditChoice::Field, Some("x"), "y", false)
            .expect_err("must fail");
        assert!(err.contains("not secure notes"));
    }

    #[test]
    fn parse_update_input_parses_standard_notes_and_multiline_fields() {
        let parsed = parse_update_input(
            "Username: bob\nPassword: p\nURL: https://u\nName: grp/item\nReprompt: yes\nPrivate Key: line1\nline2\nNotes: note1\nnote2",
            NoteType::SshKey,
        );
        assert_eq!(parsed.username.as_deref(), Some("bob"));
        assert_eq!(parsed.password.as_deref(), Some("p"));
        assert_eq!(parsed.url.as_deref(), Some("https://u"));
        assert_eq!(parsed.fullname.as_deref(), Some("grp/item"));
        assert_eq!(parsed.reprompt, Some(true));
        assert_eq!(parsed.note.as_deref(), Some("note2"));
        assert!(
            parsed
                .fields
                .iter()
                .any(|(name, value)| { name == "Private Key" && value == "line1\nline2" })
        );
    }

    #[test]
    fn parse_update_input_ignores_notes_inline_comment_value() {
        let parsed = parse_update_input(
            "Notes:    # Add notes below this line.\nupdated body",
            NoteType::None,
        );
        assert_eq!(parsed.note.as_deref(), Some("updated body"));
    }

    #[test]
    fn apply_update_applies_core_and_field_values() {
        let mut acct = account();
        let update = ParsedUpdate {
            username: Some("bob".to_string()),
            password: Some("new-pass".to_string()),
            url: Some("https://new.example.com".to_string()),
            note: Some("updated".to_string()),
            fullname: Some("ops/db".to_string()),
            reprompt: Some(true),
            fields: vec![
                ("Hostname".to_string(), "db.example.com".to_string()),
                ("Custom".to_string(), "x".to_string()),
            ],
        };

        apply_update(&mut acct, &update);
        assert_eq!(acct.username, "bob");
        assert_eq!(acct.password, "new-pass");
        assert_eq!(acct.url, "https://new.example.com");
        assert_eq!(acct.note, "updated");
        assert_eq!(acct.fullname, "ops/db");
        assert!(acct.pwprotect);
        assert!(
            acct.fields
                .iter()
                .any(|field| field.name == "Hostname" && field.value == "db.example.com")
        );
        assert!(
            acct.fields
                .iter()
                .any(|field| field.name == "Custom" && field.value == "x")
        );
    }

    #[test]
    fn parse_edit_args_supports_color_and_field_equals() {
        let parsed = parse_edit_args(&[
            "--field=Hostname".to_string(),
            "--sync=now".to_string(),
            "--color=always".to_string(),
            "entry".to_string(),
        ])
        .expect("args");
        assert_eq!(parsed.choice, EditChoice::Field);
        assert_eq!(parsed.field.as_deref(), Some("Hostname"));
        assert_eq!(parsed.sync_mode, SyncMode::Now);
    }

    #[test]
    fn make_editor_initial_text_handles_field_and_notes() {
        let acct = account();
        let args = EditArgs {
            name: acct.fullname.clone(),
            choice: EditChoice::Field,
            field: Some("Hostname".to_string()),
            non_interactive: false,
            sync_mode: SyncMode::Auto,
        };
        let text = make_editor_initial_text(&acct, &args, true);
        assert!(text.contains("old-host"));

        let no_field = make_editor_initial_text(&acct, &args, false);
        assert_eq!(no_field, "\n");

        let notes = make_editor_initial_text(
            &acct,
            &EditArgs {
                choice: EditChoice::Notes,
                ..args
            },
            false,
        );
        assert!(notes.ends_with('\n'));
    }

    #[test]
    fn render_account_file_includes_reprompt_and_note_fields() {
        let mut acct = account();
        acct.pwprotect = true;
        acct.url = "http://sn".to_string();
        acct.fields.push(Field {
            name: "NoteType".to_string(),
            field_type: "text".to_string(),
            value: "Server".to_string(),
            value_encrypted: None,
            checked: false,
        });
        let rendered = render_account_file(&acct);
        assert!(rendered.contains("Reprompt: Yes"));
        assert!(rendered.contains("NoteType: Server"));
        assert!(!rendered.contains("URL: https://"));
    }

    #[test]
    fn parse_update_input_tracks_unknown_fields_and_reprompt() {
        let parsed = parse_update_input("Custom: value\nReprompt: no", NoteType::None);
        assert_eq!(parsed.reprompt, Some(false));
        assert!(
            parsed
                .fields
                .iter()
                .any(|(name, value)| name == "Custom" && value == "value")
        );
    }

    #[test]
    fn account_note_type_detects_note_type_field() {
        let mut acct = account();
        acct.fields.push(Field {
            name: "NoteType".to_string(),
            field_type: "text".to_string(),
            value: "Server".to_string(),
            value_encrypted: None,
            checked: false,
        });
        assert_eq!(account_note_type(&acct), NoteType::Server);
    }

    #[test]
    fn render_account_file_and_shell_quote_cover_helper_paths() {
        let mut acct = account();
        acct.fields.push(Field {
            name: "NoteType".to_string(),
            field_type: "text".to_string(),
            value: "Server".to_string(),
            value_encrypted: None,
            checked: false,
        });
        let rendered = render_account_file(&acct);
        assert!(rendered.contains("Name: team/entry"));
        assert!(rendered.contains("Notes:    # Add notes below this line."));
        assert!(rendered.contains("Hostname: old-host"));

        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
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

        let err = run_inner(&[
            "--username".to_string(),
            "--password".to_string(),
            "x".to_string(),
        ])
        .expect_err("conflicting selectors");
        assert!(err.contains("usage: edit"));

        let err = run_inner(&["--field".to_string(), "x".to_string()]).expect_err("missing target");
        assert!(err.contains("usage: edit"));
    }
}
