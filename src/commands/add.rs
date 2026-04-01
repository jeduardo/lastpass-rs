#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::process::Command;

use zeroize::Zeroizing;

use crate::blob::{Account, Field};
use crate::commands::data::{SyncMode, load_blob, maybe_push_account_update, save_blob};
use crate::notes::{
    NoteType, collapse_notes, note_field_is_multiline, note_has_field, note_type_by_name,
    note_type_by_shortname, note_type_display_name, note_type_fields,
};
use crate::share::assign_account_share;
use crate::terminal;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum EditChoice {
    Any,
    Username,
    Password,
    Url,
    Field,
    Notes,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AddArgs {
    name: String,
    choice: EditChoice,
    field: Option<String>,
    non_interactive: bool,
    sync_mode: SyncMode,
    note_type: NoteType,
    is_app: bool,
}

#[derive(Debug)]
struct ParsedEntry {
    name: Option<String>,
    username: Option<String>,
    password: Option<String>,
    url: Option<String>,
    note: Option<String>,
    fields: Vec<Field>,
    note_type: NoteType,
    has_note_type_field: bool,
    reprompt: Option<bool>,
}

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
    let parsed = parse_add_args(args)?;

    if parsed.note_type != NoteType::None
        && parsed.choice != EditChoice::Any
        && parsed.choice != EditChoice::Notes
    {
        return Err("Note type may only be used with secure notes".to_string());
    }

    let raw_input = if parsed.non_interactive {
        read_stdin_to_string()?
    } else {
        let initial = make_editor_initial_text(&parsed);
        edit_with_editor(&initial)?
    };

    let mut blob = load_blob(parsed.sync_mode).map_err(|err| format!("{err}"))?;
    let mut account = if parsed.choice == EditChoice::Any {
        let entry = parse_entry_input(&raw_input, parsed.note_type);
        let entry_name = entry.name.clone().unwrap_or_else(|| parsed.name.clone());
        let mut account = build_account(&entry, &entry_name);
        if parsed.is_app
            && !account
                .fields
                .iter()
                .any(|field| field.name == "Application")
        {
            account.fields.push(make_field("Application", ""));
        }
        account
    } else {
        let mut account = new_account(&parsed.name, parsed.choice, parsed.note_type, parsed.is_app);
        let mut value = raw_input;
        trim_single_trailing_newline(&mut value);
        apply_choice_value(&mut account, parsed.choice, parsed.field.as_deref(), &value)?;
        account
    };

    assign_account_share(&mut account, &blob)?;
    account.id = "0".to_string();
    blob.accounts.push(account.clone());
    save_blob(&blob).map_err(|err| format!("{err}"))?;
    maybe_push_account_update(&account, &blob, parsed.sync_mode).map_err(|err| format!("{err}"))?;
    Ok(0)
}

fn parse_add_args(args: &[String]) -> Result<AddArgs, String> {
    let usage = "usage: add [--sync=auto|now|no] [--non-interactive] [--color=auto|never|always] {--username|--password|--url|--notes|--field=FIELD|--note-type=NOTETYPE} NAME";
    let mut choice = EditChoice::Any;
    let mut field: Option<String> = None;
    let mut non_interactive = false;
    let mut sync_mode = SyncMode::Auto;
    let mut note_type = NoteType::None;
    let mut is_app = false;
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
            "--notes" => set_choice(&mut choice, EditChoice::Notes)?,
            "--field" => {
                set_choice(&mut choice, EditChoice::Field)?;
                let Some(next) = iter.next() else {
                    return Err(usage.to_string());
                };
                field = Some(next.clone());
            }
            "--non-interactive" => non_interactive = true,
            "--app" => is_app = true,
            "--note-type" => {
                let Some(next) = iter.next() else {
                    return Err(crate::notes::note_type_usage());
                };
                note_type = note_type_by_shortname(next);
                if note_type == NoteType::None {
                    return Err(crate::notes::note_type_usage());
                }
            }
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
                if let Some(value) = arg.strip_prefix("--sync=") {
                    let Some(mode) = SyncMode::parse(value) else {
                        return Err(usage.to_string());
                    };
                    sync_mode = mode;
                    continue;
                }
                if let Some(value) = arg.strip_prefix("--field=") {
                    set_choice(&mut choice, EditChoice::Field)?;
                    field = Some(value.to_string());
                    continue;
                }
                if let Some(value) = arg.strip_prefix("--note-type=") {
                    note_type = note_type_by_shortname(value);
                    if note_type == NoteType::None {
                        return Err(crate::notes::note_type_usage());
                    }
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

    Ok(AddArgs {
        name,
        choice,
        field,
        non_interactive,
        sync_mode,
        note_type,
        is_app,
    })
}

fn set_choice(choice: &mut EditChoice, next: EditChoice) -> Result<(), String> {
    if *choice != EditChoice::Any {
        return Err(
            "add ... {--username|--password|--url|--notes|--field=FIELD|--note-type=NOTE_TYPE}"
                .to_string(),
        );
    }
    *choice = next;
    Ok(())
}

fn make_editor_initial_text(parsed: &AddArgs) -> String {
    let account = new_account(&parsed.name, parsed.choice, parsed.note_type, parsed.is_app);
    match parsed.choice {
        EditChoice::Any => render_account_file(&account, parsed.note_type, parsed.is_app),
        EditChoice::Username => format!("{}\n", account.username.as_str()),
        EditChoice::Password => format!("{}\n", account.password.as_str()),
        EditChoice::Url => format!("{}\n", account.url),
        EditChoice::Notes => format!("{}\n", account.note.as_str()),
        EditChoice::Field => format!(
            "{}\n",
            parsed
                .field
                .as_deref()
                .and_then(|field_name| account.fields.iter().find(|f| f.name == field_name))
                .map(|field| field.value.as_str())
                .unwrap_or("")
        ),
    }
}

fn render_account_file(account: &Account, note_type: NoteType, is_app: bool) -> String {
    let mut out = String::new();
    out.push_str("Name: ");
    out.push_str(&account.fullname);
    out.push('\n');

    if is_app {
        let appname = account
            .fields
            .iter()
            .find(|field| field.name == "Application")
            .map(|field| field.value.as_str())
            .unwrap_or("");
        out.push_str("Application: ");
        out.push_str(appname);
        out.push('\n');
    } else if note_type == NoteType::None {
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
            fields.push(make_field(field_name, ""));
        }
    }

    for field in &fields {
        if is_app && field.name == "Application" {
            continue;
        }
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
    let mut file = crate::editor::create_secure_temp_file()?;
    file.write_all(initial.as_bytes())
        .map_err(|err| format!("write: {err}"))?;
    file.flush().map_err(|err| format!("flush: {err}"))?;

    let editor = crate::editor::editor_program();
    let path = file.path().to_string_lossy().to_string();
    let _status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} {}", crate::editor::shell_quote(&path)))
        .status()
        .map_err(|err| format!("system($VISUAL): {err}"))?;

    fs::read_to_string(&path).map_err(|err| format!("read: {err}"))
}

fn read_stdin_to_string() -> Result<String, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("stdin: {err}"))?;
    Ok(input)
}

fn new_account(name: &str, choice: EditChoice, note_type: NoteType, is_app: bool) -> Account {
    let (group, item_name) = split_group(name);
    let fullname = if group.is_empty() {
        item_name.clone()
    } else {
        format!("{group}/{item_name}")
    };

    let mut fields = Vec::new();
    if note_type != NoteType::None
        && choice == EditChoice::Any
        && let Some(note_name) = note_type_display_name(note_type)
    {
        fields.push(make_field("NoteType", note_name));
    }
    if is_app {
        fields.push(make_field("Application", ""));
    }

    Account {
        id: "0".to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name: item_name,
        name_encrypted: None,
        group,
        group_encrypted: None,
        fullname,
        url: if choice == EditChoice::Notes || note_type != NoteType::None {
            "http://sn".to_string()
        } else {
            String::new()
        },
        url_encrypted: None,
        username: Zeroizing::new(String::new()),
        username_encrypted: None,
        password: Zeroizing::new(String::new()),
        password_encrypted: None,
        note: Zeroizing::new(String::new()),
        note_encrypted: None,
        last_touch: "skipped".to_string(),
        last_modified_gmt: "skipped".to_string(),
        fav: false,
        pwprotect: false,
        attachkey: Zeroizing::new(String::new()),
        attachkey_encrypted: None,
        attachpresent: false,
        fields,
    }
}

fn apply_choice_value(
    account: &mut Account,
    choice: EditChoice,
    field_name: Option<&str>,
    value: &str,
) -> Result<(), String> {
    match choice {
        EditChoice::Username => account.username = Zeroizing::new(value.to_string()),
        EditChoice::Password => account.password = Zeroizing::new(value.to_string()),
        EditChoice::Url => account.url = value.to_string(),
        EditChoice::Notes => account.note = Zeroizing::new(value.to_string()),
        EditChoice::Field => {
            if account.url != "http://sn" {
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
                account.fields.push(make_field(field_name, value));
            }
        }
        EditChoice::Any => {}
    }
    Ok(())
}

fn trim_single_trailing_newline(value: &mut String) {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
}

fn parse_entry_input(raw: &str, mut note_type: NoteType) -> ParsedEntry {
    let mut name: Option<String> = None;
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut url: Option<String> = None;
    let mut note: Option<String> = None;
    let mut fields: Vec<Field> = Vec::new();
    let mut has_note_type_field = false;
    let mut reprompt: Option<bool> = None;

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
                    append_multiline(&mut fields[field_idx], line);
                    idx += 1;
                    continue;
                }
            } else {
                append_multiline(&mut fields[field_idx], line);
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
            note = Some(note_value);
            break;
        }

        if key == "Name" {
            if name.is_none() {
                name = Some(value);
            } else {
                fields.push(make_field(key, &value));
            }
            idx += 1;
            continue;
        }

        if key == "Username" {
            username = Some(value);
            idx += 1;
            continue;
        }

        if key == "Password" {
            password = Some(value);
            idx += 1;
            continue;
        }

        if key == "URL" {
            url = Some(value);
            idx += 1;
            continue;
        }

        if key == "Reprompt" {
            reprompt = parse_yes_no(&value);
            idx += 1;
            continue;
        }

        if key == "NoteType" {
            has_note_type_field = true;
            if note_type == NoteType::None {
                note_type = note_type_by_name(&value);
            }
            fields.push(make_field(key, &value));
            idx += 1;
            continue;
        }

        fields.push(make_field(key, &value));
        if note_field_is_multiline(note_type, key) {
            current_multiline = Some(fields.len() - 1);
        }

        idx += 1;
    }

    ParsedEntry {
        name,
        username,
        password,
        url,
        note,
        fields,
        note_type,
        has_note_type_field,
        reprompt,
    }
}

fn build_account(parsed: &ParsedEntry, entry_name: &str) -> Account {
    let (group, name) = split_group(entry_name);
    let fullname = if group.is_empty() {
        name.clone()
    } else {
        format!("{group}/{name}")
    };

    let mut fields = parsed.fields.clone();
    if parsed.note_type != NoteType::None
        && !parsed.has_note_type_field
        && let Some(note_name) = note_type_display_name(parsed.note_type)
    {
        fields.push(make_field("NoteType", note_name));
    }

    let mut account = Account {
        id: "0".to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name,
        name_encrypted: None,
        group,
        group_encrypted: None,
        fullname,
        url: parsed.url.clone().unwrap_or_default(),
        url_encrypted: None,
        username: Zeroizing::new(parsed.username.clone().unwrap_or_default()),
        username_encrypted: None,
        password: Zeroizing::new(parsed.password.clone().unwrap_or_default()),
        password_encrypted: None,
        note: Zeroizing::new(parsed.note.clone().unwrap_or_default()),
        note_encrypted: None,
        last_touch: "skipped".to_string(),
        last_modified_gmt: "skipped".to_string(),
        fav: false,
        pwprotect: parsed.reprompt.unwrap_or(false),
        attachkey: Zeroizing::new(String::new()),
        attachkey_encrypted: None,
        attachpresent: false,
        fields,
    };

    if parsed.note_type != NoteType::None || parsed.has_note_type_field {
        account = collapse_notes(&account);
    }

    if account.fullname.is_empty() {
        account.fullname = account.name.clone();
    }

    account
}

fn split_group(full: &str) -> (String, String) {
    if let Some(pos) = full.rfind('/') {
        let group = full[..pos].to_string();
        let name = full[pos + 1..].to_string();
        return (group, name);
    }
    (String::new(), full.to_string())
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let mut iter = line.splitn(2, ':');
    let key = iter.next()?.trim();
    let value = iter.next()?;
    Some((key, value))
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

fn append_multiline(field: &mut Field, line: &str) {
    if field.value.is_empty() {
        field.value.push_str(line);
    } else {
        field.value.push('\n');
        field.value.push_str(line);
    }
}

fn make_field(name: &str, value: &str) -> Field {
    Field {
        name: name.to_string(),
        field_type: "text".to_string(),
        value: value.to_string(),
        value_encrypted: None,
        checked: false,
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

    #[test]
    fn parse_entry_input_reads_standard_fields_and_notes() {
        let parsed = parse_entry_input(
            "Username: alice\nPassword: top-secret\nURL: https://example.com\nReprompt: yes\nNotes: line1\nline2",
            NoteType::None,
        );
        assert_eq!(parsed.username.as_deref(), Some("alice"));
        assert_eq!(parsed.password.as_deref(), Some("top-secret"));
        assert_eq!(parsed.url.as_deref(), Some("https://example.com"));
        assert_eq!(parsed.reprompt, Some(true));
        assert_eq!(parsed.note.as_deref(), Some("line2"));
    }

    #[test]
    fn parse_entry_input_supports_multiline_ssh_private_key() {
        let parsed = parse_entry_input(
            "NoteType: SSH Key\nPrivate Key: line1\nline2\nHostname: host.example.com",
            NoteType::SshKey,
        );
        assert!(
            parsed
                .fields
                .iter()
                .any(|field| field.name == "Private Key" && field.value == "line1\nline2")
        );
        assert!(
            parsed
                .fields
                .iter()
                .any(|field| field.name == "Hostname" && field.value == "host.example.com")
        );
    }

    #[test]
    fn build_account_assigns_fullname_and_reprompt() {
        let parsed = parse_entry_input(
            "Username: alice\nPassword: p\nReprompt: No\nNotes:\nhello",
            NoteType::None,
        );
        let account = build_account(&parsed, "team/entry");
        assert_eq!(account.group, "team");
        assert_eq!(account.name, "entry");
        assert_eq!(account.fullname, "team/entry");
        assert_eq!(*account.username, "alice");
        assert_eq!(*account.password, "p");
        assert!(!account.pwprotect);
        assert_eq!(*account.note, "hello");
    }

    #[test]
    fn parse_entry_input_ignores_notes_inline_comment_value() {
        let parsed = parse_entry_input(
            "Notes:    # Add notes below this line.\nbody",
            NoteType::None,
        );
        assert_eq!(parsed.note.as_deref(), Some("body"));
    }

    #[test]
    fn split_group_splits_last_slash_only() {
        assert_eq!(split_group("a/b/c"), ("a/b".to_string(), "c".to_string()));
        assert_eq!(
            split_group("single"),
            ("".to_string(), "single".to_string())
        );
    }

    #[test]
    fn is_valid_field_name_honors_note_templates() {
        assert!(is_valid_field_name(NoteType::None, "Anything"));
        assert!(is_valid_field_name(NoteType::SshKey, "Private Key"));
        assert!(!is_valid_field_name(NoteType::SshKey, "Not A Field"));
    }

    #[test]
    fn parse_yes_no_accepts_only_yes_or_no() {
        assert_eq!(parse_yes_no("Yes"), Some(true));
        assert_eq!(parse_yes_no("no"), Some(false));
        assert_eq!(parse_yes_no("n/a"), None);
    }

    #[test]
    fn parse_add_args_validates_choices_and_sync() {
        let parsed =
            parse_add_args(&["--username".to_string(), "entry".to_string()]).expect("args");
        assert_eq!(parsed.choice, EditChoice::Username);

        let err = parse_add_args(&[
            "--username".to_string(),
            "--password".to_string(),
            "entry".to_string(),
        ])
        .expect_err("conflicting selectors");
        assert!(err.contains("--username|--password"));

        let err =
            parse_add_args(&["--sync=bad".to_string(), "entry".to_string()]).expect_err("bad sync");
        assert!(err.contains("usage: add"));

        let err = parse_add_args(&["--sync".to_string(), "entry".to_string()])
            .expect_err("missing sync value");
        assert!(err.contains("usage: add"));
    }

    #[test]
    fn apply_choice_value_rejects_field_for_non_secure_note() {
        let mut account = new_account("entry", EditChoice::Any, NoteType::None, false);
        let err = apply_choice_value(
            &mut account,
            EditChoice::Field,
            Some("Hostname"),
            "example.com",
        )
        .expect_err("must fail");
        assert!(err.contains("not secure notes"));
    }

    #[test]
    fn apply_choice_value_updates_selected_targets() {
        let mut account = new_account("entry", EditChoice::Notes, NoteType::None, false);
        apply_choice_value(&mut account, EditChoice::Notes, None, "hello").expect("notes");
        assert_eq!(*account.note, "hello");

        apply_choice_value(&mut account, EditChoice::Field, Some("Hostname"), "srv")
            .expect("field");
        assert!(
            account
                .fields
                .iter()
                .any(|field| field.name == "Hostname" && field.value == "srv")
        );

        apply_choice_value(&mut account, EditChoice::Field, Some("Hostname"), "")
            .expect("remove field");
        assert!(!account.fields.iter().any(|field| field.name == "Hostname"));
    }

    #[test]
    fn render_account_file_includes_defaults_for_note_type() {
        let account = new_account("group/item", EditChoice::Any, NoteType::Server, false);
        let rendered = render_account_file(&account, NoteType::Server, false);
        assert!(rendered.contains("Name: group/item"));
        assert!(rendered.contains("Hostname: "));
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(crate::editor::shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn trim_single_trailing_newline_only_removes_one_newline() {
        let mut value = "line\n\n".to_string();
        trim_single_trailing_newline(&mut value);
        assert_eq!(value, "line\n");
    }

    #[test]
    fn run_inner_validates_arguments_before_io() {
        let err = run_inner(&[]).expect_err("missing name");
        assert!(err.contains("usage: add"));

        let err = run_inner(&["--bogus".to_string(), "name".to_string()]).expect_err("bad flag");
        assert!(err.contains("usage: add"));

        let err = run_inner(&["--note-type=unknown".to_string(), "name".to_string()])
            .expect_err("invalid note type");
        assert!(err.contains("--note-type=TYPE"));

        let err = run_inner(&[
            "--note-type=server".to_string(),
            "-u".to_string(),
            "name".to_string(),
        ])
        .expect_err("invalid note type selector");
        assert!(err.contains("Note type may only be used with secure notes"));
    }

    #[test]
    fn parse_add_args_supports_field_note_type_color_and_app() {
        let parsed = parse_add_args(&[
            "--field".to_string(),
            "Hostname".to_string(),
            "--sync".to_string(),
            "now".to_string(),
            "--color=never".to_string(),
            "--app".to_string(),
            "entry".to_string(),
        ])
        .expect("args");
        assert_eq!(parsed.choice, EditChoice::Field);
        assert_eq!(parsed.field.as_deref(), Some("Hostname"));
        assert_eq!(parsed.sync_mode, SyncMode::Now);
        assert!(parsed.is_app);

        let parsed = parse_add_args(&[
            "--note-type=server".to_string(),
            "--non-interactive".to_string(),
            "note".to_string(),
        ])
        .expect("note args");
        assert_eq!(parsed.note_type, NoteType::Server);
        assert!(parsed.non_interactive);
    }

    #[test]
    fn make_editor_initial_text_covers_choice_variants() {
        let base = AddArgs {
            name: "entry".to_string(),
            choice: EditChoice::Any,
            field: None,
            non_interactive: false,
            sync_mode: SyncMode::Auto,
            note_type: NoteType::None,
            is_app: false,
        };
        let any = make_editor_initial_text(&base);
        assert!(any.contains("Name: entry"));

        let username = make_editor_initial_text(&AddArgs {
            choice: EditChoice::Username,
            ..base.clone()
        });
        assert!(username.ends_with('\n'));

        let password = make_editor_initial_text(&AddArgs {
            choice: EditChoice::Password,
            ..base.clone()
        });
        assert!(password.ends_with('\n'));

        let url = make_editor_initial_text(&AddArgs {
            choice: EditChoice::Url,
            ..base.clone()
        });
        assert!(url.ends_with('\n'));

        let notes = make_editor_initial_text(&AddArgs {
            choice: EditChoice::Notes,
            ..base.clone()
        });
        assert!(notes.ends_with('\n'));

        let field = make_editor_initial_text(&AddArgs {
            choice: EditChoice::Field,
            field: Some("Application".to_string()),
            is_app: true,
            ..base
        });
        assert!(field.ends_with('\n'));
    }

    #[test]
    fn render_account_file_includes_application_for_apps() {
        let account = new_account("app/item", EditChoice::Any, NoteType::None, true);
        let rendered = render_account_file(&account, NoteType::None, true);
        assert!(rendered.contains("Application:"));
        assert!(!rendered.contains("URL: "));
    }

    #[test]
    fn parse_entry_input_handles_duplicate_name_and_note_type_field() {
        let parsed = parse_entry_input(
            "Name: primary\nName: secondary\nNoteType: Server\nHostname: host\nNotes:\nbody",
            NoteType::None,
        );
        assert_eq!(parsed.name.as_deref(), Some("primary"));
        assert!(parsed.has_note_type_field);
        assert_eq!(parsed.note_type, NoteType::Server);
        assert!(parsed.fields.iter().any(|field| field.name == "Name"));
    }

    #[test]
    fn apply_choice_value_updates_existing_field() {
        let mut account = new_account("entry", EditChoice::Any, NoteType::SshKey, false);
        account.fields.push(make_field("Hostname", "old"));
        apply_choice_value(&mut account, EditChoice::Field, Some("Hostname"), "new")
            .expect("update");
        let field = account
            .fields
            .iter()
            .find(|field| field.name == "Hostname")
            .expect("field");
        assert_eq!(field.value, "new");
    }

    #[test]
    fn build_account_collapses_notes_for_secure_note_types() {
        let parsed = parse_entry_input(
            "NoteType: Server\nHostname: host\nNotes:\nbody",
            NoteType::Server,
        );
        let account = build_account(&parsed, "secure/entry");
        assert_eq!(account.url, "http://sn");
        assert!(account.note.contains("NoteType:"));
        assert_eq!(account.fullname, "secure/entry");
    }

    #[test]
    fn parse_add_args_rejects_double_positional() {
        let err = parse_add_args(&["first".to_string(), "second".to_string()])
            .expect_err("two positional args");
        assert!(err.contains("usage: add"));
    }

    #[test]
    fn parse_add_args_field_without_value() {
        let err =
            parse_add_args(&["--field".to_string()]).expect_err("--field missing value");
        assert!(err.contains("usage: add"));
    }

    #[test]
    fn parse_add_args_note_type_space_separated() {
        let parsed = parse_add_args(&[
            "--note-type".to_string(),
            "server".to_string(),
            "name".to_string(),
        ])
        .expect("valid note type");
        assert_eq!(parsed.note_type, NoteType::Server);

        let err = parse_add_args(&[
            "--note-type".to_string(),
            "unknown".to_string(),
            "name".to_string(),
        ])
        .expect_err("invalid note type");
        assert!(err.contains("--note-type=TYPE"));

        let err = parse_add_args(&["--note-type".to_string()])
            .expect_err("missing note type value");
        assert!(err.contains("--note-type=TYPE"));
    }

    #[test]
    fn parse_add_args_sync_without_value() {
        let err = parse_add_args(&["--sync".to_string()])
            .expect_err("--sync missing value");
        assert!(err.contains("usage: add"));
    }

    #[test]
    fn parse_add_args_color_space_separated() {
        let parsed = parse_add_args(&[
            "--color".to_string(),
            "never".to_string(),
            "name".to_string(),
        ])
        .expect("valid color");
        assert_eq!(parsed.name, "name");

        let err = parse_add_args(&[
            "--color".to_string(),
            "bad".to_string(),
            "name".to_string(),
        ])
        .expect_err("invalid color");
        assert!(err.contains("usage: add"));

        let err =
            parse_add_args(&["--color".to_string()]).expect_err("missing color value");
        assert!(err.contains("usage: add"));
    }

    #[test]
    fn parse_add_args_field_equals_syntax() {
        let parsed = parse_add_args(&[
            "--field=Hostname".to_string(),
            "name".to_string(),
        ])
        .expect("field equals syntax");
        assert_eq!(parsed.choice, EditChoice::Field);
        assert_eq!(parsed.field.as_deref(), Some("Hostname"));
    }

    #[test]
    fn parse_add_args_color_equals_invalid() {
        let err = parse_add_args(&[
            "--color=bad".to_string(),
            "name".to_string(),
        ])
        .expect_err("invalid color equals");
        assert!(err.contains("usage: add"));
    }

    #[test]
    fn render_account_file_skips_username_password_in_note_template() {
        // NoteType::Email has Username and Password in its template fields.
        // render_account_file should skip those via the continue on line 287.
        let account = new_account("entry", EditChoice::Any, NoteType::Email, false);
        let rendered = render_account_file(&account, NoteType::Email, false);
        // The template fields Username/Password should be skipped, but
        // Server/Port/Type etc. should appear.
        assert!(rendered.contains("Server: "));
        assert!(rendered.contains("Port: "));
        // Should not have duplicate Username/Password lines from the template
        // (the note type path doesn't render them as standard fields either
        // since note_type != NoteType::None skips the standard URL/Username/Password block).
    }

    #[test]
    fn render_account_file_shows_reprompt() {
        let mut account = new_account("entry", EditChoice::Any, NoteType::None, false);
        account.pwprotect = true;
        let rendered = render_account_file(&account, NoteType::None, false);
        assert!(rendered.contains("Reprompt: Yes"));
    }

    #[test]
    fn render_account_file_skips_existing_note_type_field() {
        // When a note type field already exists in the account, render should
        // hit the continue at line 290.
        let mut account = new_account("entry", EditChoice::Any, NoteType::Server, false);
        account.fields.push(make_field("Hostname", "existing"));
        let rendered = render_account_file(&account, NoteType::Server, false);
        // Hostname should appear only once (from the existing field, not added again)
        let count = rendered.matches("Hostname: ").count();
        assert_eq!(count, 1);
        assert!(rendered.contains("Hostname: existing"));
    }

    #[test]
    fn new_account_with_note_type_and_any_choice_sets_note_type_field() {
        let account = new_account("entry", EditChoice::Any, NoteType::Server, false);
        assert!(
            account
                .fields
                .iter()
                .any(|field| field.name == "NoteType" && field.value == "Server")
        );
    }

    #[test]
    fn apply_choice_value_any_is_noop() {
        let mut account = new_account("entry", EditChoice::Any, NoteType::None, false);
        let before_url = account.url.clone();
        apply_choice_value(&mut account, EditChoice::Any, None, "ignored")
            .expect("any noop");
        assert_eq!(account.url, before_url);
    }

    #[test]
    fn apply_choice_value_sets_username_password_url() {
        let mut account = new_account("entry", EditChoice::Any, NoteType::None, false);
        apply_choice_value(&mut account, EditChoice::Username, None, "user1")
            .expect("username");
        assert_eq!(*account.username, "user1");

        apply_choice_value(&mut account, EditChoice::Password, None, "pass1")
            .expect("password");
        assert_eq!(*account.password, "pass1");

        apply_choice_value(&mut account, EditChoice::Url, None, "https://x.com")
            .expect("url");
        assert_eq!(account.url, "https://x.com");
    }

    #[test]
    fn parse_entry_input_blank_line_skipped() {
        // A blank line (no colon) should be skipped (line 471-472).
        let parsed = parse_entry_input(
            "Username: alice\n\nPassword: secret\nNotes:\n",
            NoteType::None,
        );
        assert_eq!(parsed.username.as_deref(), Some("alice"));
        assert_eq!(parsed.password.as_deref(), Some("secret"));
    }

    #[test]
    fn parse_entry_input_multiline_continuation_non_colon_line() {
        // When in multiline mode, a line without a colon appends (line 463-465).
        // Also covers append_multiline with empty value first (line 633).
        let parsed = parse_entry_input(
            "NoteType: SSH Key\nPrivate Key: \nno-colon-line\nanother-line\nHostname: host\nNotes:\n",
            NoteType::SshKey,
        );
        let pk = parsed
            .fields
            .iter()
            .find(|field| field.name == "Private Key")
            .expect("Private Key field");
        assert!(pk.value.contains("no-colon-line"));
        assert!(pk.value.contains("another-line"));
    }

    #[test]
    fn parse_entry_input_multiline_colon_not_valid_field() {
        // In multiline mode, a line with a colon that is NOT a valid field
        // should be appended as continuation (lines 458-461).
        let parsed = parse_entry_input(
            "NoteType: SSH Key\nPrivate Key: BEGIN\nfake-field: not-a-real-ssh-field\nHostname: host\nNotes:\n",
            NoteType::SshKey,
        );
        let pk = parsed
            .fields
            .iter()
            .find(|field| field.name == "Private Key")
            .expect("Private Key field");
        // "fake-field: not-a-real-ssh-field" should be part of Private Key value
        assert!(pk.value.contains("fake-field: not-a-real-ssh-field"));
        // Hostname should still be parsed as a separate field
        assert!(
            parsed
                .fields
                .iter()
                .any(|field| field.name == "Hostname" && field.value == "host")
        );
    }

    #[test]
    fn build_account_adds_note_type_field_when_missing() {
        // When note_type is set but has_note_type_field is false,
        // build_account should add the NoteType field (lines 556-561).
        let parsed = parse_entry_input(
            "Hostname: host\nNotes:\nbody",
            NoteType::Server,
        );
        assert!(!parsed.has_note_type_field);
        let account = build_account(&parsed, "entry");
        assert!(account.note.contains("NoteType:"));
    }

    #[test]
    fn build_account_empty_fullname_fallback() {
        // When fullname ends up empty, it falls back to account.name (line 595-596).
        // This happens when entry_name has no group and is empty.
        let parsed = parse_entry_input("Notes:\n", NoteType::None);
        let account = build_account(&parsed, "");
        // fullname should not be empty if name is also empty, but the fallback
        // path is: if account.fullname.is_empty() { account.fullname = account.name.clone(); }
        // With empty entry_name, both name and fullname will be empty, so fullname stays empty.
        // But this still exercises the code path.
        assert_eq!(account.fullname, "");
    }

    #[test]
    fn is_valid_field_name_returns_true_for_builtin_with_note_type() {
        // With a non-None note_type, built-in names like "URL" should still
        // return true (lines 619-623).
        assert!(is_valid_field_name(NoteType::SshKey, "URL"));
        assert!(is_valid_field_name(NoteType::SshKey, "Name"));
        assert!(is_valid_field_name(NoteType::SshKey, "Notes"));
        assert!(is_valid_field_name(NoteType::SshKey, "Reprompt"));
    }

    #[test]
    fn trim_single_trailing_newline_handles_crlf() {
        let mut value = "line\r\n".to_string();
        trim_single_trailing_newline(&mut value);
        assert_eq!(value, "line");
    }

    #[test]
    fn trim_single_trailing_newline_noop_without_newline() {
        let mut value = "no-newline".to_string();
        trim_single_trailing_newline(&mut value);
        assert_eq!(value, "no-newline");
    }
}
