#![forbid(unsafe_code)]

use crate::blob::Account;
use crate::commands::argparse::parse_sync_option;
use crate::commands::data::{SyncMode, load_blob};
use crate::format::{format_account, format_field};
use crate::notes::expand_notes;
use crate::terminal::{self, BOLD, FG_BLUE, FG_CYAN, FG_GREEN, FG_YELLOW, RESET};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ShowChoice {
    All,
    Username,
    Password,
    Url,
    Field,
    Id,
    Name,
    Notes,
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
    let usage = "usage: show [--sync=auto|now|no] [--clip, -c] [--quiet, -q] [--expand-multi, -x] [--json, -j] [--all|--username|--password|--url|--notes|--field=FIELD|--id|--name|--attach=ATTACHID] [--basic-regexp, -G|--fixed-strings, -F] [--color=auto|never|always] {UNIQUENAME|UNIQUEID}";
    let mut choice = ShowChoice::All;
    let mut field_name: Option<String> = None;
    let mut json = false;
    let mut names: Vec<String> = Vec::new();
    let mut title_format_override: Option<String> = None;
    let mut field_format_override: Option<String> = None;
    let mut sync_mode = SyncMode::Auto;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            names.push(arg.clone());
            continue;
        }
        if arg == "--json" || arg == "-j" {
            json = true;
        } else if arg == "--username" || arg == "-u" {
            choice = ShowChoice::Username;
        } else if arg == "--password" || arg == "-p" {
            choice = ShowChoice::Password;
        } else if arg == "--url" || arg == "-L" {
            choice = ShowChoice::Url;
        } else if arg == "--id" || arg == "-I" {
            choice = ShowChoice::Id;
        } else if arg == "--name" || arg == "-N" {
            choice = ShowChoice::Name;
        } else if arg == "--notes" || arg == "--note" || arg == "-O" {
            choice = ShowChoice::Notes;
        } else if arg.starts_with("--field=") {
            choice = ShowChoice::Field;
            field_name = Some(arg.trim_start_matches("--field=").to_string());
        } else if arg == "--field" || arg == "-f" {
            choice = ShowChoice::Field;
            if let Some(next) = iter.next() {
                field_name = Some(next.clone());
            }
        } else if arg == "--format" || arg == "-o" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            field_format_override = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("--format=") {
            field_format_override = Some(value.to_string());
        } else if arg == "--title-format" || arg == "-t" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            title_format_override = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("--title-format=") {
            title_format_override = Some(value.to_string());
        } else if let Some(mode) = parse_sync_option(arg, &mut iter, usage)? {
            sync_mode = mode;
        } else if arg == "--all" || arg == "-A" {
            choice = ShowChoice::All;
        } else if arg == "--basic-regexp" || arg == "-G" {
            // not implemented
        } else if arg == "--fixed-strings" || arg == "-F" {
            // not implemented
        } else if arg == "--expand-multi" || arg == "-x" {
            // ignored
        } else if arg == "--clip" || arg == "-c" {
            // not implemented
        } else if arg == "--attach" {
            let _ = iter.next();
            // not implemented
        } else if arg.starts_with("--attach=") {
            // not implemented
        } else if arg == "--color" || arg == "-C" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
        } else if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
        } else if arg == "--quiet" || arg == "-q" {
            // ignored
        } else {
            return Err(usage.to_string());
        }
    }

    if names.is_empty() {
        return Err(usage.to_string());
    }

    let title_format = title_format_override.unwrap_or_else(|| {
        format!("{FG_CYAN}%/as{RESET}{FG_BLUE}%/ag{BOLD}%an{RESET}{FG_GREEN} [id: %ai]{RESET}")
    });
    let field_format =
        field_format_override.unwrap_or_else(|| format!("{FG_YELLOW}%fn{RESET}: %fv"));

    let blob = load_blob(sync_mode).map_err(|err| format!("{err}"))?;
    let matches = find_matches(&blob.accounts, &names);
    if matches.is_empty() {
        return Err("Could not find specified account(s).".to_string());
    }

    if json {
        let output = format_json(&matches);
        println!("{output}");
        return Ok(0);
    }

    for account in matches {
        let display = expand_notes(account).unwrap_or_else(|| account.clone());
        match choice {
            ShowChoice::All => {
                println!(
                    "{}",
                    terminal::render_stdout(&format_account(&title_format, &display))
                );
                if !display.username.is_empty() {
                    println!(
                        "{}",
                        terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("Username"),
                            Some(&display.username)
                        ))
                    );
                }
                if !display.password.is_empty() {
                    println!(
                        "{}",
                        terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("Password"),
                            Some(&display.password)
                        ))
                    );
                }
                if !display.url.is_empty() && display.url != "http://" {
                    println!(
                        "{}",
                        terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("URL"),
                            Some(&display.url)
                        ))
                    );
                }

                for field in &display.fields {
                    println!(
                        "{}",
                        terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some(&field.name),
                            Some(&field.value)
                        ))
                    );
                }

                if display.pwprotect {
                    println!(
                        "{}",
                        terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("Reprompt"),
                            Some("Yes")
                        ))
                    );
                }

                if !display.note.is_empty() {
                    println!(
                        "{}",
                        terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("Notes"),
                            Some(&display.note)
                        ))
                    );
                }
            }
            ShowChoice::Username => {
                println!("{}", display.username);
            }
            ShowChoice::Password => {
                println!("{}", display.password);
            }
            ShowChoice::Url => {
                println!("{}", display.url);
            }
            ShowChoice::Id => {
                println!("{}", display.id);
            }
            ShowChoice::Name => {
                println!("{}", display.name);
            }
            ShowChoice::Notes => {
                println!("{}", display.note);
            }
            ShowChoice::Field => {
                let field_name = field_name.clone().unwrap_or_default();
                let mut found = None;
                for field in &display.fields {
                    if field.name == field_name {
                        found = Some(field.value.clone());
                        break;
                    }
                }
                if let Some(value) = found {
                    println!("{value}");
                } else {
                    return Err(format!("Could not find specified field '{field_name}'."));
                }
            }
        }
    }

    Ok(0)
}

fn find_matches<'a>(accounts: &'a [Account], names: &[String]) -> Vec<&'a Account> {
    let mut out = Vec::new();

    for name in names {
        if name != "0" {
            if let Some(account) = accounts
                .iter()
                .find(|acct| acct.id.eq_ignore_ascii_case(name))
            {
                out.push(account);
                continue;
            }
        }

        for account in accounts {
            if account.fullname == *name || account.name == *name {
                out.push(account);
            }
        }
    }

    out
}

fn format_json(matches: &[&Account]) -> String {
    let mut out = String::from("[\n");
    for (idx, account) in matches.iter().enumerate() {
        out.push_str("  {\n");
        out.push_str(&format!("    \"id\": \"{}\",\n", escape_json(&account.id)));
        out.push_str(&format!(
            "    \"name\": \"{}\",\n",
            escape_json(&account.name)
        ));
        out.push_str(&format!(
            "    \"fullname\": \"{}\",\n",
            escape_json(&account.fullname)
        ));
        out.push_str(&format!(
            "    \"username\": \"{}\",\n",
            escape_json(&account.username)
        ));
        out.push_str(&format!(
            "    \"password\": \"{}\",\n",
            escape_json(&account.password)
        ));
        out.push_str(&format!(
            "    \"last_modified_gmt\": \"{}\",\n",
            escape_json(&account.last_modified_gmt)
        ));
        out.push_str(&format!(
            "    \"last_touch\": \"{}\",\n",
            escape_json(&account.last_touch)
        ));
        out.push_str(&format!(
            "    \"group\": \"{}\",\n",
            escape_json(&account.group)
        ));
        out.push_str(&format!(
            "    \"url\": \"{}\",\n",
            escape_json(&account.url)
        ));
        out.push_str(&format!(
            "    \"note\": \"{}\"\n",
            escape_json(&account.note)
        ));
        out.push_str("  }");
        if idx + 1 != matches.len() {
            out.push_str(",\n");
        } else {
            out.push('\n');
        }
    }
    out.push(']');
    out
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: "alice".to_string(),
            username_encrypted: None,
            password: "secret".to_string(),
            password_encrypted: None,
            note: "note".to_string(),
            note_encrypted: None,
            last_touch: "touch".to_string(),
            last_modified_gmt: "gmt".to_string(),
            fav: false,
            pwprotect: false,
            attachkey: String::new(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        }
    }

    #[test]
    fn find_matches_prefers_id_and_supports_names() {
        let accounts = vec![
            account("0001", "alpha", "team"),
            account("0002", "beta", ""),
        ];
        let by_id = find_matches(&accounts, &["0002".to_string()]);
        assert_eq!(by_id.len(), 1);
        assert_eq!(by_id[0].name, "beta");

        let by_fullname = find_matches(&accounts, &["team/alpha".to_string()]);
        assert_eq!(by_fullname.len(), 1);
        assert_eq!(by_fullname[0].id, "0001");
    }

    #[test]
    fn format_json_escapes_quoted_fields() {
        let mut acct = account("0003", "quoted", "team");
        acct.note = "line1\n\"line2\"".to_string();
        let json = format_json(&[&acct]);
        assert!(json.contains("\"id\": \"0003\""));
        assert!(json.contains("\\n"));
        assert!(json.contains("\\\"line2\\\""));
    }

    #[test]
    fn escape_json_escapes_backslash_quote_and_newline() {
        assert_eq!(escape_json("a\\b"), "a\\\\b");
        assert_eq!(escape_json("\"x\""), "\\\"x\\\"");
        assert_eq!(escape_json("a\nb"), "a\\nb");
    }

    #[test]
    fn run_inner_rejects_invalid_invocations() {
        assert!(run_inner(&[]).is_err());
        assert!(run_inner(&["--bogus".to_string()]).is_err());
        assert!(run_inner(&["--sync".to_string()]).is_err());
        assert!(run_inner(&["--sync=bad".to_string(), "x".to_string()]).is_err());
        assert!(run_inner(&["--field".to_string()]).is_err());
        assert!(run_inner(&["--format".to_string()]).is_err());
        assert!(run_inner(&["--title-format".to_string()]).is_err());
    }
}
