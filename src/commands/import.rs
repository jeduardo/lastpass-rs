#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};

use crate::agent::agent_get_decryption_key;
use crate::blob::{Account, Blob};
use crate::commands::argparse::parse_sync_option;
use crate::commands::data::{SyncMode, encrypt_and_encode, load_blob, save_blob};
use crate::error::LpassError;
use crate::http::HttpClient;
use crate::kdf::KDF_HASH_LEN;
use crate::session::{Session, session_load};
use crate::terminal;

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
    let usage = "usage: import [--keep-dupes] [CSV_FILENAME]";
    let mut keep_dupes = false;
    let mut positional: Vec<String> = Vec::new();
    let mut sync_mode = SyncMode::Auto;

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
        if let Some(mode) = parse_sync_option(arg, &mut iter, usage)? {
            sync_mode = mode;
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

    let mut blob = load_blob(sync_mode).map_err(|err| format!("{err}"))?;
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

    if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
        assign_mock_ids(&blob, &mut imported);
        blob.accounts.extend(imported);
        save_blob(&blob).map_err(|err| format!("{err}"))?;
        return Ok(0);
    }

    let (key, session) = load_upload_credentials()?;
    let client = HttpClient::from_env().map_err(|err| format!("{err}"))?;
    upload_accounts_with_client(&client, &session, &key, &imported)?;
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
        return Err(
            "Could not read the CSV header at the first line of the input file".to_string(),
        );
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
                .map(|value| value.starts_with('1'))
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
        share_id: None,
        share_readonly: false,
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

fn assign_mock_ids(blob: &Blob, imported: &mut [Account]) {
    let mut next_id = next_id_value(blob).saturating_add(1);
    for account in imported {
        account.id = format!("{next_id:04}");
        next_id = next_id.saturating_add(1);
    }
}

fn load_upload_credentials() -> Result<([u8; KDF_HASH_LEN], Session), String> {
    let key = agent_get_decryption_key().map_err(map_decryption_key_error)?;
    let session = session_load(&key)
        .map_err(map_decryption_key_error)?
        .ok_or_else(|| {
            "Could not find session. Perhaps you need to login with `lpass login`.".to_string()
        })?;
    Ok((key, session))
}

fn map_decryption_key_error(err: LpassError) -> String {
    match err {
        LpassError::Crypto("missing iterations")
        | LpassError::Crypto("missing username")
        | LpassError::Crypto("missing verify") => {
            "Could not find decryption key. Perhaps you need to login with `lpass login`."
                .to_string()
        }
        _ => format!("{err}"),
    }
}

fn upload_accounts_with_client(
    client: &HttpClient,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
    accounts: &[Account],
) -> Result<(), String> {
    if accounts.is_empty() {
        return Ok(());
    }

    let params = build_upload_accounts_params(accounts, session, key)?;
    let params_ref: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let response = client
        .post_lastpass(None, "lastpass/api.php", Some(session), &params_ref)
        .map_err(|err| format!("{err}"))?;

    if response.status >= 400 {
        return Err("Import failed (-22)".to_string());
    }
    match crate::xml::parse_lastpass_api_ok(&response.body) {
        Some(true) => Ok(()),
        Some(false) => Err("Import failed (-1)".to_string()),
        None => Err("Import failed (-22)".to_string()),
    }
}

fn build_upload_accounts_params(
    accounts: &[Account],
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<Vec<(String, String)>, String> {
    let mut params = vec![
        ("token".to_string(), session.token.clone()),
        ("cmd".to_string(), "uploadaccounts".to_string()),
    ];

    for (index, account) in accounts.iter().enumerate() {
        params.push((
            format!("name{index}"),
            encrypt_and_encode(&account.name, key).map_err(|err| format!("{err}"))?,
        ));
        params.push((
            format!("grouping{index}"),
            encrypt_and_encode(&account.group, key).map_err(|err| format!("{err}"))?,
        ));
        params.push((
            format!("url{index}"),
            if session.url_encryption_enabled {
                encrypt_and_encode(&account.url, key).map_err(|err| format!("{err}"))?
            } else {
                hex::encode(account.url.as_bytes())
            },
        ));
        params.push((
            format!("username{index}"),
            encrypt_and_encode(&account.username, key).map_err(|err| format!("{err}"))?,
        ));
        params.push((
            format!("password{index}"),
            encrypt_and_encode(&account.password, key).map_err(|err| format!("{err}"))?,
        ));
        params.push((
            format!("fav{index}"),
            if account.fav { "1" } else { "0" }.to_string(),
        ));
        params.push((
            format!("extra{index}"),
            encrypt_and_encode(&account.note, key).map_err(|err| format!("{err}"))?,
        ));
        if session.url_logging_enabled {
            params.push((
                format!("recordUrl{index}"),
                hex::encode(account.url.as_bytes()),
            ));
        }
    }

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ConfigEnv, config_write_buffer, config_write_encrypted_string, set_test_env,
    };
    use crate::session::session_save;
    use std::fs;
    use tempfile::{NamedTempFile, TempDir};

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
        let err = parse_import_accounts("foo,bar\n1,2\n").expect_err("unknown header should fail");
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
    fn parse_import_accounts_handles_empty_and_header_only_csv() {
        assert!(parse_import_accounts("").expect("empty").is_empty());
        let accounts = parse_import_accounts("name,url\n").expect("header-only");
        assert!(accounts.is_empty());
    }

    #[test]
    fn parse_csv_records_handles_cr_without_lf() {
        let records = parse_csv_records("name,url\rvalue,https://x\r\n").expect("parse csv");
        assert_eq!(records.len(), 1);
        assert!(records[0][1].contains('\r'));
    }

    #[test]
    fn parse_csv_records_handles_escaped_quotes_literal_quotes_and_trailing_rows() {
        let csv = "name,url\n\"a\"\"b\",literal\"quote\nentry,https://x";
        let records = parse_csv_records(csv).expect("parse csv");
        assert_eq!(records.len(), 3);
        assert_eq!(records[1][0], "a\"b");
        assert_eq!(records[1][1], "literal\"quote");
        assert_eq!(records[2][0], "entry");
    }

    #[test]
    fn parse_import_accounts_defaults_missing_values_and_groupless_fullname() {
        let csv = "name,fav\nentry,\n";
        let accounts = parse_import_accounts(csv).expect("parse accounts");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].fullname, "entry");
        assert!(!accounts[0].fav);
    }

    #[test]
    fn trim_crlf_removes_all_trailing_line_endings() {
        let mut record = ["value\r\n\r".to_string()];
        trim_crlf(&mut record);
        assert_eq!(record[0], "value");
    }

    #[test]
    fn dedupe_against_blob_uses_password_username_url_and_name() {
        let mut blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![new_import_account()],
            attachments: Vec::new(),
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
        let err = run_inner(&["--sync".to_string()]).expect_err("missing sync value");
        assert!(err.contains("usage: import"));

        let err = run_inner(&["--sync=bad".to_string()]).expect_err("bad sync value");
        assert!(err.contains("usage: import"));

        let err = run_inner(&["--bogus".to_string()]).expect_err("unknown flag");
        assert!(err.contains("usage: import"));
    }

    #[test]
    fn run_reports_errors_for_missing_file() {
        let status = run(&["/definitely/missing.csv".to_string()]);
        assert_eq!(status, 1);
    }

    #[test]
    fn run_inner_imports_from_file_in_mock_mode() {
        let _guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        crate::lpenv::set_override_for_tests("LPASS_HOME", &home.path().display().to_string());
        let file = NamedTempFile::new().expect("temp csv");
        fs::write(
            file.path(),
            "url,username,password,extra,name,grouping,fav\nhttps://x,u,p,n,entry,team,1\n",
        )
        .expect("write csv");

        let status = run_inner(&[
            "--sync=no".to_string(),
            "--keep-dupes".to_string(),
            file.path().to_string_lossy().to_string(),
        ])
        .expect("import");
        assert_eq!(status, 0);
    }

    #[test]
    fn next_id_value_uses_highest_numeric_id() {
        let mut blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![new_import_account(), new_import_account()],
            attachments: Vec::new(),
        };
        blob.accounts[0].id = "0003".to_string();
        blob.accounts[1].id = "n/a".to_string();
        assert_eq!(next_id_value(&blob), 3);
    }

    #[test]
    fn assign_mock_ids_uses_next_numeric_id() {
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![Account {
                id: "0007".to_string(),
                ..new_import_account()
            }],
            attachments: Vec::new(),
        };
        let mut imported = vec![new_import_account(), new_import_account()];
        assign_mock_ids(&blob, &mut imported);
        assert_eq!(imported[0].id, "0008");
        assert_eq!(imported[1].id, "0009");
    }

    #[test]
    fn load_upload_credentials_reads_saved_key_and_session() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [3u8; KDF_HASH_LEN];

        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        session_save(
            &Session {
                uid: "u".to_string(),
                session_id: "s".to_string(),
                token: "tok".to_string(),
                url_encryption_enabled: false,
                url_logging_enabled: false,
                server: None,
                private_key: None,
                private_key_enc: None,
            },
            &key,
        )
        .expect("save session");

        let (loaded_key, loaded_session) = load_upload_credentials().expect("credentials");
        assert_eq!(loaded_key, key);
        assert_eq!(loaded_session.token, "tok");
    }

    #[test]
    fn load_upload_credentials_reports_missing_values() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let err = load_upload_credentials().expect_err("missing key");
        assert!(err.contains("Could not find decryption key"));

        let key = [7u8; KDF_HASH_LEN];
        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        let err = load_upload_credentials().expect_err("missing session");
        assert!(err.contains("Could not find session"));
    }

    #[test]
    fn map_decryption_key_error_covers_remaining_branches() {
        assert!(
            map_decryption_key_error(LpassError::Crypto("missing username"))
                .contains("Could not find decryption key")
        );
        assert!(
            map_decryption_key_error(LpassError::Crypto("missing verify"))
                .contains("Could not find decryption key")
        );
        assert!(map_decryption_key_error(LpassError::Crypto("other")).contains("crypto error"));
    }

    #[test]
    fn build_upload_accounts_params_matches_expected_keys() {
        let mut account = new_import_account();
        account.name = "entry".to_string();
        account.group = "team".to_string();
        account.url = "https://example.com".to_string();
        account.username = "alice".to_string();
        account.password = "secret".to_string();
        account.note = "note".to_string();
        account.fav = true;

        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: true,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [4u8; KDF_HASH_LEN];
        let params =
            build_upload_accounts_params(&[account], &session, &key).expect("build upload params");
        assert!(
            params
                .iter()
                .any(|(name, value)| name == "token" && value == "tok")
        );
        assert!(
            params
                .iter()
                .any(|(name, value)| name == "cmd" && value == "uploadaccounts")
        );
        assert!(params.iter().any(|(name, _)| name == "name0"));
        assert!(params.iter().any(
            |(name, value)| name == "url0" && value == "68747470733a2f2f6578616d706c652e636f6d"
        ));
        assert!(
            params
                .iter()
                .any(|(name, value)| name == "fav0" && value == "1")
        );
        assert!(params.iter().any(|(name, value)| name == "recordUrl0"
            && value == "68747470733a2f2f6578616d706c652e636f6d"));
    }

    #[test]
    fn build_upload_accounts_params_encrypts_url_when_enabled() {
        let mut account = new_import_account();
        account.url = "https://example.com".to_string();

        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: true,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [8u8; KDF_HASH_LEN];
        let params =
            build_upload_accounts_params(&[account], &session, &key).expect("build upload params");
        let url = params
            .iter()
            .find(|(name, _)| name == "url0")
            .map(|(_, value)| value.clone())
            .expect("url field");
        assert!(url.starts_with('!'));
        assert!(!params.iter().any(|(name, _)| name == "recordUrl0"));
    }

    #[test]
    fn upload_accounts_with_client_accepts_mock_success_and_empty_input() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [5u8; KDF_HASH_LEN];
        upload_accounts_with_client(&HttpClient::mock(), &session, &key, &[]).expect("empty");
        upload_accounts_with_client(&HttpClient::mock(), &session, &key, &[new_import_account()])
            .expect("mock upload");
    }

    #[test]
    fn upload_accounts_with_client_reports_fail_and_invalid_responses() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [6u8; KDF_HASH_LEN];

        let fail = upload_accounts_with_client(
            &HttpClient::mock_with_overrides(&[(
                "lastpass/api.php",
                200,
                "<lastpass rc=\"FAIL\"><error/></lastpass>",
            )]),
            &session,
            &key,
            &[new_import_account()],
        )
        .expect_err("fail rc");
        assert_eq!(fail, "Import failed (-1)");

        let invalid = upload_accounts_with_client(
            &HttpClient::mock_with_overrides(&[("lastpass/api.php", 200, "<response/>")]),
            &session,
            &key,
            &[new_import_account()],
        )
        .expect_err("invalid body");
        assert_eq!(invalid, "Import failed (-22)");

        let status = upload_accounts_with_client(
            &HttpClient::mock_with_overrides(&[("lastpass/api.php", 500, "server error")]),
            &session,
            &key,
            &[new_import_account()],
        )
        .expect_err("status failure");
        assert_eq!(status, "Import failed (-22)");
    }

    #[test]
    fn run_inner_non_mock_upload_path_reaches_http_client() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [9u8; KDF_HASH_LEN];

        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", &key)
            .expect("write verify");
        session_save(
            &Session {
                uid: "u".to_string(),
                session_id: "s".to_string(),
                token: "tok".to_string(),
                url_encryption_enabled: false,
                url_logging_enabled: false,
                server: Some("127.0.0.1:1".to_string()),
                private_key: None,
                private_key_enc: None,
            },
            &key,
        )
        .expect("save session");

        let blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        let buffer = serde_json::to_vec_pretty(&blob).expect("blob json");
        crate::config::config_write_encrypted_buffer("blob.json", &buffer, &key).expect("blob");

        let file = NamedTempFile::new().expect("temp csv");
        fs::write(file.path(), "name,url\nentry,https://example.com\n").expect("write csv");

        let err = run_inner(&[file.path().to_string_lossy().to_string()]).expect_err("network");
        assert!(err.contains("IO error while http post"));
    }
}
