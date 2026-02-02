#![forbid(unsafe_code)]

use crate::blob::Account;
use crate::commands::data::load_blob;
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

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            names.push(arg.clone());
            continue;
        }
        if arg == "--json" || arg == "-j" {
            json = true;
        } else if arg == "--username" {
            choice = ShowChoice::Username;
        } else if arg == "--password" {
            choice = ShowChoice::Password;
        } else if arg == "--url" {
            choice = ShowChoice::Url;
        } else if arg == "--id" {
            choice = ShowChoice::Id;
        } else if arg == "--name" {
            choice = ShowChoice::Name;
        } else if arg == "--notes" || arg == "--note" {
            choice = ShowChoice::Notes;
        } else if arg.starts_with("--field=") {
            choice = ShowChoice::Field;
            field_name = Some(arg.trim_start_matches("--field=").to_string());
        } else if arg == "--field" {
            choice = ShowChoice::Field;
            if let Some(next) = iter.next() {
                field_name = Some(next.clone());
            }
        } else if arg.starts_with("--sync=") {
            // ignored
        } else if arg == "--sync" {
            let _ = iter.next();
        } else if arg == "--all" {
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
        } else if arg == "--color" {
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

    let title_format =
        format!("{FG_CYAN}%/as{RESET}{FG_BLUE}%/ag{BOLD}%an{RESET}{FG_GREEN} [id: %ai]{RESET}");
    let field_format = format!("{FG_YELLOW}%fn{RESET}: %fv");

    let blob = load_blob().map_err(|err| format!("{err}"))?;
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
