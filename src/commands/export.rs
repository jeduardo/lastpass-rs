#![forbid(unsafe_code)]

use crate::blob::Account;
use crate::commands::data::load_blob;
use crate::terminal;

const DEFAULT_FIELDS: &[&str] = &[
    "url",
    "username",
    "password",
    "extra",
    "name",
    "grouping",
    "fav",
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
    let mut fields: Vec<String> = Vec::new();

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            return Err("usage: export [--sync=auto|now|no] [--color=auto|never|always] [--fields=FIELDLIST]".to_string());
        }
        if arg.starts_with("--sync=") {
            continue;
        }
        if arg == "--sync" || arg == "-S" {
            let _ = iter.next();
            continue;
        }
        if arg == "--color" || arg == "-C" {
            let value = iter.next().ok_or_else(|| {
                "... --color=auto|never|always".to_string()
            })?;
            let mode = terminal::parse_color_mode(value)
                .ok_or_else(|| "... --color=auto|never|always".to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value)
                .ok_or_else(|| "... --color=auto|never|always".to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if arg == "--fields" || arg == "-f" {
            if let Some(next) = iter.next() {
                fields.extend(parse_fields(next));
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("--fields=") {
            fields.extend(parse_fields(value));
            continue;
        }
        return Err("usage: export [--sync=auto|now|no] [--color=auto|never|always] [--fields=FIELDLIST]".to_string());
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
    if value { "1".to_string() } else { "0".to_string() }
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
    let needs_quote = value.chars().any(|ch| ch == '"' || ch == ',' || ch == '\n' || ch == '\r');
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
