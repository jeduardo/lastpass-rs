#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};

use crate::blob::{Account, Blob};
use crate::commands::data::{load_blob, save_blob};

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
    let usage = "usage: import [--keep-dupes] [CSV_FILENAME]";
    let mut keep_dupes = false;
    let mut positional: Vec<String> = Vec::new();

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            positional.push(arg.clone());
            continue;
        }

        if arg == "--keep-dupes" {
            keep_dupes = true;
            continue;
        }
        if arg.starts_with("--sync=") {
            continue;
        }
        if arg == "--sync" {
            let _ = iter.next();
            continue;
        }
        return Err(usage.to_string());
    }

    let mut input = String::new();
    if let Some(path) = positional.first() {
        let mut file = File::open(path).map_err(|_| format!("Unable to open {path}"))?;
        file.read_to_string(&mut input)
            .map_err(|err| format!("read csv: {err}"))?;
    } else {
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|err| format!("stdin: {err}"))?;
    }

    let mut blob = load_blob().map_err(|err| format!("{err}"))?;
    let mut imported = parse_import_accounts(&input)?;
    println!("Parsed {} accounts", imported.len());

    let removed = if keep_dupes {
        0
    } else {
        dedupe_against_blob(&blob, &mut imported)
    };
    if removed > 0 {
        println!("Removed {removed} duplicate accounts");
    }

    let mut next_id = next_id_value(&blob).saturating_add(1);
    for account in &mut imported {
        account.id = format!("{next_id:04}");
        next_id = next_id.saturating_add(1);
    }
    blob.accounts.extend(imported);
    save_blob(&blob).map_err(|err| format!("{err}"))?;
    Ok(0)
}

fn parse_import_accounts(input: &str) -> Result<Vec<Account>, String> {
    let records = parse_csv_records(input)?;
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let header = &records[0];
    let url_idx = find_header_index(header, "url");
    let username_idx = find_header_index(header, "username");
    let password_idx = find_header_index(header, "password");
    let extra_idx = find_header_index(header, "extra");
    let name_idx = find_header_index(header, "name");
    let grouping_idx = find_header_index(header, "grouping");
    let fav_idx = find_header_index(header, "fav");

    if url_idx.is_none()
        && username_idx.is_none()
        && password_idx.is_none()
        && extra_idx.is_none()
        && name_idx.is_none()
        && grouping_idx.is_none()
        && fav_idx.is_none()
    {
        return Err("Could not read the CSV header at the first line of the input file".to_string());
    }

    let mut out = Vec::new();
    for record in records.into_iter().skip(1) {
        let mut account = new_import_account();
        if let Some(idx) = url_idx {
            account.url = record.get(idx).cloned().unwrap_or_default();
        }
        if let Some(idx) = username_idx {
            account.username = record.get(idx).cloned().unwrap_or_default();
        }
        if let Some(idx) = password_idx {
            account.password = record.get(idx).cloned().unwrap_or_default();
        }
        if let Some(idx) = extra_idx {
            account.note = record.get(idx).cloned().unwrap_or_default();
        }
        if let Some(idx) = name_idx {
            account.name = record.get(idx).cloned().unwrap_or_default();
        }
        if let Some(idx) = grouping_idx {
            account.group = record.get(idx).cloned().unwrap_or_default();
        }
        if let Some(idx) = fav_idx {
            account.fav = record
                .get(idx)
                .map(|value| value.chars().next() == Some('1'))
                .unwrap_or(false);
        }

        account.fullname = if account.group.is_empty() {
            account.name.clone()
        } else {
            format!("{}/{}", account.group, account.name)
        };
        out.push(account);
    }
    Ok(out)
}

fn parse_csv_records(input: &str) -> Result<Vec<Vec<String>>, String> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut chars = input.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    let _ = chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(ch);
            }
            continue;
        }

        match ch {
            '"' => {
                if field.is_empty() {
                    in_quotes = true;
                } else {
                    field.push(ch);
                }
            }
            ',' => {
                record.push(std::mem::take(&mut field));
            }
            '\n' => {
                record.push(std::mem::take(&mut field));
                trim_crlf(&mut record);
                if !record.is_empty() {
                    records.push(std::mem::take(&mut record));
                }
            }
            '\r' => {
                if chars.peek() != Some(&'\n') {
                    field.push('\r');
                }
            }
            _ => field.push(ch),
        }
    }

    if in_quotes {
        return Err("invalid CSV input: unterminated quoted field".to_string());
    }

    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        trim_crlf(&mut record);
        records.push(record);
    }

    Ok(records)
}

fn trim_crlf(record: &mut [String]) {
    for value in record {
        while value.ends_with('\r') || value.ends_with('\n') {
            value.pop();
        }
    }
}

fn find_header_index(header: &[String], name: &str) -> Option<usize> {
    header.iter().position(|field| field == name)
}

fn new_import_account() -> Account {
    Account {
        id: String::new(),
        share_name: None,
        name: String::new(),
        name_encrypted: None,
        group: String::new(),
        group_encrypted: None,
        fullname: String::new(),
        url: String::new(),
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

fn dedupe_against_blob(blob: &Blob, imported: &mut Vec<Account>) -> usize {
    let before = imported.len();
    imported.retain(|candidate| {
        !blob.accounts.iter().any(|existing| {
            existing.password == candidate.password
                && existing.username == candidate.username
                && existing.url == candidate.url
                && existing.name == candidate.name
        })
    });
    before.saturating_sub(imported.len())
}

fn next_id_value(blob: &Blob) -> u32 {
    blob.accounts
        .iter()
        .filter_map(|account| account.id.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_records_handles_quotes_and_commas() {
        let csv = "name,url\n\"entry, one\",https://example.com\n";
        let records = parse_csv_records(csv).expect("parse csv");
        assert_eq!(records.len(), 2);
        assert_eq!(records[1][0], "entry, one");
    }

    #[test]
    fn parse_csv_records_rejects_unterminated_quote() {
        let err = parse_csv_records("name\n\"unterminated").expect_err("must fail");
        assert!(err.contains("unterminated"));
    }

    #[test]
    fn parse_import_accounts_requires_supported_header() {
        let err =
            parse_import_accounts("foo,bar\n1,2\n").expect_err("unknown header should fail");
        assert!(err.contains("Could not read the CSV header"));
    }

    #[test]
    fn parse_import_accounts_maps_known_columns() {
        let csv = "url,username,password,extra,name,grouping,fav\nhttps://x,u,p,n,entry,team,1\n";
        let accounts = parse_import_accounts(csv).expect("parse accounts");
        assert_eq!(accounts.len(), 1);
        let account = &accounts[0];
        assert_eq!(account.url, "https://x");
        assert_eq!(account.username, "u");
        assert_eq!(account.password, "p");
        assert_eq!(account.note, "n");
        assert_eq!(account.name, "entry");
        assert_eq!(account.group, "team");
        assert_eq!(account.fullname, "team/entry");
        assert!(account.fav);
    }

    #[test]
    fn dedupe_against_blob_uses_password_username_url_and_name() {
        let mut blob = Blob {
            version: 1,
            local_version: false,
            accounts: vec![new_import_account()],
        };
        blob.accounts[0].name = "entry".to_string();
        blob.accounts[0].username = "u".to_string();
        blob.accounts[0].password = "p".to_string();
        blob.accounts[0].url = "https://x".to_string();

        let mut imported = vec![new_import_account(), new_import_account()];
        imported[0].name = "entry".to_string();
        imported[0].username = "u".to_string();
        imported[0].password = "p".to_string();
        imported[0].url = "https://x".to_string();
        imported[1].name = "entry2".to_string();

        let removed = dedupe_against_blob(&blob, &mut imported);
        assert_eq!(removed, 1);
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].name, "entry2");
    }

    #[test]
    fn run_inner_rejects_unknown_flags() {
        let err = run_inner(&["--bogus".to_string()]).expect_err("unknown flag");
        assert!(err.contains("usage: import"));
    }
}
