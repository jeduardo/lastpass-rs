#![forbid(unsafe_code)]

use crate::blob::Account;
use crate::commands::data::load_blob;
use crate::terminal;

const DEFAULT_FIELDS: &[&str] = &[
    "url", "username", "password", "extra", "name", "grouping", "fav",
];

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
        "usage: export [--sync=auto|now|no] [--color=auto|never|always] [--fields=FIELDLIST]";
    let mut fields: Vec<String> = Vec::new();

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            return Err(usage.to_string());
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
        if arg == "--fields" {
            if let Some(next) = iter.next() {
                fields.extend(parse_fields(next));
            }
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

    let blob = load_blob().map_err(|err| format!("{err}"))?;
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
        "grouping" => account.group.clone(),
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
            out.push('\n');
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::Account;

    fn account() -> Account {
        Account {
            id: "42".to_string(),
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
        assert_eq!(out, "plain,\"a,b\",\"quote\"\"inside\"\n");
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
    }
}
