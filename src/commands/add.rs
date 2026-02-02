#![forbid(unsafe_code)]

use std::io::{self, Read};

use crate::blob::{Account, Blob, Field};
use crate::commands::data::{load_blob, save_blob};
use crate::notes::{
    NoteType, collapse_notes, note_field_is_multiline, note_has_field, note_type_by_name,
    note_type_by_shortname, note_type_display_name,
};
use crate::terminal;

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
            eprintln!("error: {err}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<i32, String> {
    let usage = "usage: add [--sync=auto|now|no] [--non-interactive] [--color=auto|never|always] {--username|--password|--url|--notes|--field=FIELD|--note-type=NOTETYPE} NAME";
    let mut non_interactive = false;
    let mut note_type = NoteType::None;
    let mut name: Option<String> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            name = Some(arg.clone());
            continue;
        }
        if arg == "--non-interactive" {
            non_interactive = true;
        } else if arg == "--note-type" {
            if let Some(next) = iter.next() {
                note_type = note_type_by_shortname(next);
                if note_type == NoteType::None {
                    return Err(crate::notes::note_type_usage());
                }
            } else {
                return Err(crate::notes::note_type_usage());
            }
        } else if let Some(value) = arg.strip_prefix("--note-type=") {
            note_type = note_type_by_shortname(value);
            if note_type == NoteType::None {
                return Err(crate::notes::note_type_usage());
            }
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
        } else if matches!(
            arg.as_str(),
            "--username" | "--password" | "--url" | "--notes" | "--field"
        ) {
            // interactive-only flags ignored for now
            if arg == "--field" {
                let _ = iter.next();
            }
        } else {
            return Err(usage.to_string());
        }
    }

    let name = name.ok_or_else(|| usage.to_string())?;

    if !non_interactive {
        return Err("interactive add not implemented; use --non-interactive".to_string());
    }

    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|err| format!("stdin: {err}"))?;

    let parsed = parse_entry_input(&input, note_type);
    let entry_name = parsed.name.clone().unwrap_or_else(|| name.clone());

    let mut blob = load_blob().map_err(|err| format!("{err}"))?;
    let mut account = build_account(&parsed, &entry_name);
    account.id = next_id(&blob);

    blob.accounts.push(account);
    save_blob(&blob).map_err(|err| format!("{err}"))?;

    Ok(0)
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
        format!("{}/{}", group, name)
    };

    let mut fields = parsed.fields.clone();
    if parsed.note_type != NoteType::None && !parsed.has_note_type_field {
        if let Some(note_name) = note_type_display_name(parsed.note_type) {
            fields.push(make_field("NoteType", note_name));
        }
    }

    let mut account = Account {
        id: "0".to_string(),
        share_name: None,
        name,
        name_encrypted: None,
        group,
        group_encrypted: None,
        fullname,
        url: parsed.url.clone().unwrap_or_default(),
        url_encrypted: None,
        username: parsed.username.clone().unwrap_or_default(),
        username_encrypted: None,
        password: parsed.password.clone().unwrap_or_default(),
        password_encrypted: None,
        note: parsed.note.clone().unwrap_or_default(),
        note_encrypted: None,
        last_touch: "skipped".to_string(),
        last_modified_gmt: "skipped".to_string(),
        fav: false,
        pwprotect: parsed.reprompt.unwrap_or(false),
        attachkey: String::new(),
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
        assert_eq!(parsed.note.as_deref(), Some("line1\nline2"));
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
            "Username: alice\nPassword: p\nReprompt: No\nNotes: hello",
            NoteType::None,
        );
        let account = build_account(&parsed, "team/entry");
        assert_eq!(account.group, "team");
        assert_eq!(account.name, "entry");
        assert_eq!(account.fullname, "team/entry");
        assert_eq!(account.username, "alice");
        assert_eq!(account.password, "p");
        assert!(!account.pwprotect);
        assert_eq!(account.note, "hello");
    }

    #[test]
    fn split_group_splits_last_slash_only() {
        assert_eq!(
            split_group("a/b/c"),
            ("a/b".to_string(), "c".to_string())
        );
        assert_eq!(split_group("single"), ("".to_string(), "single".to_string()));
    }

    #[test]
    fn next_id_ignores_non_numeric_ids() {
        let blob = Blob {
            version: 1,
            local_version: false,
            accounts: vec![
                Account {
                    id: "0009".to_string(),
                    ..Account::default()
                },
                Account {
                    id: "abc".to_string(),
                    ..Account::default()
                },
            ],
        };
        assert_eq!(next_id(&blob), "0010");
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
    fn run_inner_validates_arguments_before_io() {
        let err = run_inner(&[]).expect_err("missing name");
        assert!(err.contains("usage: add"));

        let err = run_inner(&["--bogus".to_string(), "name".to_string()]).expect_err("bad flag");
        assert!(err.contains("usage: add"));

        let err = run_inner(&["--note-type=unknown".to_string(), "name".to_string()])
            .expect_err("invalid note type");
        assert!(err.contains("--note-type=TYPE"));
    }
}
