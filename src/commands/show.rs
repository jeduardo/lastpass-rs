#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use regex::RegexBuilder;

use crate::agent::{agent_get_decryption_key, agent_load_on_disk_key};
use crate::blob::{Account, Attachment};
use crate::commands::argparse::parse_sync_option;
use crate::commands::data::{SyncMode, load_blob};
use crate::crypto::aes_decrypt_base64_lastpass;
use crate::format::{format_account, format_field};
use crate::http::HttpClient;
use crate::kdf::KDF_HASH_LEN;
use crate::notes::expand_notes;
use crate::session::session_load;
use crate::terminal::{self, BOLD, FG_BLUE, FG_CYAN, FG_GREEN, FG_RED, FG_YELLOW, RESET};

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
    Attach,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SearchMode {
    Exact,
    BasicRegex,
    FixedSubstring,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BinaryAttachmentAction {
    Print,
    Skip,
    Save,
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
    let mut attach_id: Option<String> = None;
    let mut json = false;
    let mut clip = false;
    let mut quiet = false;
    let mut expand_multi = false;
    let mut search_mode = SearchMode::Exact;
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
            let next = iter.next().ok_or_else(|| usage.to_string())?;
            field_name = Some(next.clone());
        } else if arg == "--attach" {
            choice = ShowChoice::Attach;
            let next = iter.next().ok_or_else(|| usage.to_string())?;
            attach_id = Some(next.clone());
        } else if let Some(value) = arg.strip_prefix("--attach=") {
            choice = ShowChoice::Attach;
            attach_id = Some(value.to_string());
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
            search_mode = SearchMode::BasicRegex;
        } else if arg == "--fixed-strings" || arg == "-F" {
            search_mode = SearchMode::FixedSubstring;
        } else if arg == "--expand-multi" || arg == "-x" {
            expand_multi = true;
        } else if arg == "--clip" || arg == "-c" {
            clip = true;
        } else if arg == "--color" || arg == "-C" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
        } else if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
        } else if arg == "--quiet" || arg == "-q" {
            quiet = true;
        } else {
            return Err(usage.to_string());
        }
    }

    if names.is_empty() {
        return Err(usage.to_string());
    }
    if names.len() > 1 {
        expand_multi = true;
    }

    let title_format = title_format_override.unwrap_or_else(|| {
        format!("{FG_CYAN}%/as{RESET}{FG_BLUE}%/ag{BOLD}%an{RESET}{FG_GREEN} [id: %ai]{RESET}")
    });
    let field_format =
        field_format_override.unwrap_or_else(|| format!("{FG_YELLOW}%fn{RESET}: %fv"));

    let blob = load_blob(sync_mode).map_err(|err| format!("{err}"))?;
    let match_indexes = find_matches(&blob.accounts, &names, search_mode)?;
    if match_indexes.is_empty() {
        return Err("Could not find specified account(s).".to_string());
    }

    let matches: Vec<&Account> = match_indexes
        .iter()
        .map(|idx| &blob.accounts[*idx])
        .collect();

    if matches.len() > 1 && !expand_multi {
        println!(
            "{}",
            terminal::render_stdout(&format!("{FG_YELLOW}{BOLD}Multiple matches found."))
        );
        for account in &matches {
            println!(
                "{}",
                terminal::render_stdout(&format_account(&title_format, account))
            );
        }
        return Ok(0);
    }

    authenticate_protected_entries(&matches)?;

    if json {
        let output = format_json(&matches);
        if clip {
            let mut clipboard_data = output.into_bytes();
            clipboard_data.push(b'\n');
            copy_to_clipboard(&clipboard_data)?;
        } else {
            println!("{output}");
        }
        return Ok(0);
    }

    let mut clipboard_data = Vec::new();

    for account in matches {
        let display = expand_notes(account).unwrap_or_else(|| account.clone());
        match choice {
            ShowChoice::All => {
                emit_line(
                    &terminal::render_stdout(&format_account(&title_format, &display)),
                    clip,
                    &mut clipboard_data,
                )?;

                if !display.username.is_empty() {
                    emit_line(
                        &terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("Username"),
                            Some(&display.username),
                        )),
                        clip,
                        &mut clipboard_data,
                    )?;
                }

                if !display.password.is_empty() {
                    emit_line(
                        &terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("Password"),
                            Some(&display.password),
                        )),
                        clip,
                        &mut clipboard_data,
                    )?;
                }

                if !display.url.is_empty() && display.url != "http://" {
                    emit_line(
                        &terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("URL"),
                            Some(&display.url),
                        )),
                        clip,
                        &mut clipboard_data,
                    )?;
                }

                for field in &display.fields {
                    let field_value = pretty_field_value(field);
                    emit_line(
                        &terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some(&field.name),
                            Some(&field_value),
                        )),
                        clip,
                        &mut clipboard_data,
                    )?;
                }

                for attachment in attachments_for_account(&blob.attachments, &display.id) {
                    let field_name = format!("att-{}", attachment.id);
                    let filename = attachment_filename(&display, attachment)
                        .unwrap_or_else(|| "unknown".to_string());
                    emit_line(
                        &terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some(&field_name),
                            Some(&filename),
                        )),
                        clip,
                        &mut clipboard_data,
                    )?;
                }

                if display.pwprotect {
                    emit_line(
                        &terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("Reprompt"),
                            Some("Yes"),
                        )),
                        clip,
                        &mut clipboard_data,
                    )?;
                }

                if !display.note.is_empty() {
                    emit_line(
                        &terminal::render_stdout(&format_field(
                            &field_format,
                            &display,
                            Some("Notes"),
                            Some(&display.note),
                        )),
                        clip,
                        &mut clipboard_data,
                    )?;
                }
            }
            ShowChoice::Username => {
                emit_value(&display.username, clip, &mut clipboard_data)?;
            }
            ShowChoice::Password => {
                emit_value(&display.password, clip, &mut clipboard_data)?;
            }
            ShowChoice::Url => {
                emit_value(&display.url, clip, &mut clipboard_data)?;
            }
            ShowChoice::Id => {
                emit_value(&display.id, clip, &mut clipboard_data)?;
            }
            ShowChoice::Name => {
                emit_value(&display.name, clip, &mut clipboard_data)?;
            }
            ShowChoice::Notes => {
                emit_value(&display.note, clip, &mut clipboard_data)?;
            }
            ShowChoice::Field => {
                let name = field_name.as_deref().unwrap_or_default();
                let value = display
                    .fields
                    .iter()
                    .find(|field| field.name == name)
                    .map(pretty_field_value)
                    .ok_or_else(|| format!("Could not find specified field '{name}'."))?;
                emit_value(&value, clip, &mut clipboard_data)?;
            }
            ShowChoice::Attach => {
                let id = attach_id.as_deref().unwrap_or_default();
                let attachment = find_attachment(&blob.attachments, &display.id, id)
                    .ok_or_else(|| format!("Could not find specified attachment '{id}'."))?;
                let data = load_attachment_data(&display, attachment)?;
                if attachment_is_binary(&data) && !quiet {
                    let filename = attachment_filename(&display, attachment)
                        .unwrap_or_else(|| "unknown".to_string());
                    match ask_binary_attachment_action(&filename)? {
                        BinaryAttachmentAction::Skip => continue,
                        BinaryAttachmentAction::Save => {
                            save_attachment_to_file(&filename, &data)?;
                            continue;
                        }
                        BinaryAttachmentAction::Print => {}
                    }
                }
                emit_bytes(&data, clip, &mut clipboard_data)?;
            }
        }
    }

    if clip {
        copy_to_clipboard(&clipboard_data)?;
    }

    Ok(0)
}

fn emit_line(line: &str, clip: bool, clipboard: &mut Vec<u8>) -> Result<(), String> {
    if clip {
        clipboard.extend_from_slice(line.as_bytes());
        clipboard.push(b'\n');
        return Ok(());
    }
    println!("{line}");
    Ok(())
}

fn emit_value(value: &str, clip: bool, clipboard: &mut Vec<u8>) -> Result<(), String> {
    if clip {
        clipboard.extend_from_slice(value.as_bytes());
        return Ok(());
    }
    println!("{value}");
    Ok(())
}

fn emit_bytes(data: &[u8], clip: bool, clipboard: &mut Vec<u8>) -> Result<(), String> {
    if clip {
        clipboard.extend_from_slice(data);
        return Ok(());
    }
    std::io::stdout()
        .write_all(data)
        .map_err(|err| format!("{err}"))?;
    Ok(())
}

fn authenticate_protected_entries(matches: &[&Account]) -> Result<(), String> {
    if !matches.iter().any(|account| account.pwprotect) {
        return Ok(());
    }

    let prompted_key = agent_load_on_disk_key()
        .map_err(|_| "Could not authenticate for protected entry.".to_string())?;
    let current_key = agent_get_decryption_key()
        .map_err(|_| "Could not authenticate for protected entry.".to_string())?;
    if prompted_key != current_key {
        return Err("Current key is not on-disk key.".to_string());
    }
    Ok(())
}

fn ask_binary_attachment_action(filename: &str) -> Result<BinaryAttachmentAction, String> {
    loop {
        let prompt = format!(
            "{FG_YELLOW}\"{filename}\" is a binary file, print it anyway (or save)? {RESET}[y/n/{BOLD}S{RESET}] "
        );
        eprint!("{}", terminal::render_stderr(&prompt));
        std::io::stderr()
            .flush()
            .map_err(|_| "aborted response.".to_string())?;

        let mut response = String::new();
        let bytes = std::io::stdin()
            .read_line(&mut response)
            .map_err(|_| "aborted response.".to_string())?;
        if bytes == 0 {
            return Err("aborted response.".to_string());
        }

        if let Some(action) = parse_binary_attachment_response(&response) {
            return Ok(action);
        }

        let error = format!("{FG_RED}{BOLD}Error{RESET}: Response not understood.");
        eprintln!("{}", terminal::render_stderr(&error));
    }
}

fn parse_binary_attachment_response(response: &str) -> Option<BinaryAttachmentAction> {
    let response = response.trim_end_matches(['\r', '\n']).to_ascii_lowercase();
    if response.is_empty() {
        return Some(BinaryAttachmentAction::Save);
    }
    match response.chars().next() {
        Some('y') => Some(BinaryAttachmentAction::Print),
        Some('n') => Some(BinaryAttachmentAction::Skip),
        Some('s') => Some(BinaryAttachmentAction::Save),
        _ => None,
    }
}

fn save_attachment_to_file(filename: &str, data: &[u8]) -> Result<(), String> {
    let mut file =
        std::fs::File::create(filename).map_err(|_| format!("Unable to open {filename}"))?;
    file.write_all(data)
        .map_err(|err| format!("write: {err}"))?;
    let notice = format!(
        "{FG_GREEN}Wrote {} bytes to \"{}\"{RESET}",
        data.len(),
        filename
    );
    eprintln!("{}", terminal::render_stderr(&notice));
    Ok(())
}

fn find_matches(
    accounts: &[Account],
    names: &[String],
    search_mode: SearchMode,
) -> Result<Vec<usize>, String> {
    let mut matches = Vec::new();
    let mut potential: Vec<usize> = (0..accounts.len()).collect();

    for name in names {
        match search_mode {
            SearchMode::Exact => {
                if name != "0" {
                    let mut id_match = None;
                    for (offset, idx) in potential.iter().enumerate() {
                        if accounts[*idx].id.eq_ignore_ascii_case(name) {
                            id_match = Some((offset, *idx));
                            break;
                        }
                    }
                    if let Some((offset, idx)) = id_match {
                        let _ = potential.remove(offset);
                        matches.push(idx);
                        continue;
                    }
                }

                let mut remaining = Vec::new();
                for idx in potential {
                    let account = &accounts[idx];
                    if account.fullname == *name || account.name == *name {
                        matches.push(idx);
                    } else {
                        remaining.push(idx);
                    }
                }
                potential = remaining;
            }
            SearchMode::BasicRegex => {
                let regex = RegexBuilder::new(name)
                    .case_insensitive(true)
                    .build()
                    .map_err(|_| format!("Invalid regex '{name}'"))?;
                let mut remaining = Vec::new();
                for idx in potential {
                    let account = &accounts[idx];
                    if regex.is_match(&account.id)
                        || regex.is_match(&account.name)
                        || regex.is_match(&account.fullname)
                    {
                        matches.push(idx);
                    } else {
                        remaining.push(idx);
                    }
                }
                potential = remaining;
            }
            SearchMode::FixedSubstring => {
                let mut remaining = Vec::new();
                for idx in potential {
                    let account = &accounts[idx];
                    if account.id.contains(name)
                        || account.name.contains(name)
                        || account.fullname.contains(name)
                    {
                        matches.push(idx);
                    } else {
                        remaining.push(idx);
                    }
                }
                potential = remaining;
            }
        }
    }

    Ok(matches)
}

fn attachments_for_account<'a>(
    attachments: &'a [Attachment],
    account_id: &str,
) -> Vec<&'a Attachment> {
    attachments
        .iter()
        .filter(|attachment| attachment.parent == account_id)
        .collect()
}

fn find_attachment<'a>(
    attachments: &'a [Attachment],
    account_id: &str,
    attach_id: &str,
) -> Option<&'a Attachment> {
    let normalized = attach_id.strip_prefix("att-").unwrap_or(attach_id);
    attachments
        .iter()
        .find(|attachment| attachment.parent == account_id && attachment.id == normalized)
}

fn attachment_filename(account: &Account, attachment: &Attachment) -> Option<String> {
    let key = decode_attachment_key(account).ok()?;
    let bytes = aes_decrypt_base64_lastpass(&attachment.filename, &key).ok()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn decode_attachment_key(account: &Account) -> Result<[u8; KDF_HASH_LEN], String> {
    if account.attachkey.is_empty() || account.attachkey.len() != KDF_HASH_LEN * 2 {
        return Err(format!("Missing attach key for account {}", account.name));
    }

    let bytes = hex::decode(&account.attachkey)
        .map_err(|_| format!("Invalid attach key for account {}", account.name))?;
    let mut key = [0u8; KDF_HASH_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn load_attachment_data(account: &Account, attachment: &Attachment) -> Result<Vec<u8>, String> {
    let key = decode_attachment_key(account)?;
    let encrypted = fetch_attachment_ciphertext(account, attachment)?;

    let plaintext_b64 = aes_decrypt_base64_lastpass(&encrypted, &key)
        .map_err(|_| format!("Unable to decrypt attachment {}", attachment.id))?;
    let plaintext_b64 = String::from_utf8_lossy(&plaintext_b64);

    BASE64_STD
        .decode(plaintext_b64.trim().as_bytes())
        .map_err(|_| format!("Unable to decrypt attachment {}", attachment.id))
}

fn fetch_attachment_ciphertext(
    account: &Account,
    attachment: &Attachment,
) -> Result<String, String> {
    let key = agent_get_decryption_key().map_err(|err| format!("{err}"))?;
    let session = session_load(&key)
        .map_err(|err| format!("{err}"))?
        .ok_or_else(|| {
            "Could not find session. Perhaps you need to login with `lpass login`.".to_string()
        })?;

    let client = HttpClient::from_env().map_err(|err| format!("{err}"))?;

    let mut params = vec![
        ("token".to_string(), session.token.clone()),
        ("getattach".to_string(), attachment.storagekey.clone()),
    ];
    if let Some(share_id) = account.share_id.as_deref() {
        if !share_id.is_empty() {
            params.push(("sharedfolderid".to_string(), share_id.to_string()));
        }
    }

    let params_ref: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();

    let response = client
        .post_lastpass(None, "getattach.php", Some(&session), &params_ref)
        .map_err(|err| format!("{err}"))?;

    if response.body.trim().is_empty() {
        return Err(format!("Could not load attachment {}", attachment.id));
    }

    let ciphertext = parse_attachment_response(&response.body);
    if ciphertext.is_empty() {
        return Err(format!("Could not load attachment {}", attachment.id));
    }

    Ok(ciphertext)
}

fn parse_attachment_response(body: &str) -> String {
    if let Ok(decoded) = serde_json::from_str::<String>(body) {
        return decoded;
    }

    let trimmed = body.trim();
    let quoted = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(trimmed);

    let mut out = String::new();
    let mut escaped = false;
    for ch in quoted.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        out.push(ch);
    }
    out
}

fn attachment_is_binary(data: &[u8]) -> bool {
    data.iter()
        .take(100)
        .any(|byte| !byte.is_ascii_graphic() && *byte != b' ')
}

fn copy_to_clipboard(data: &[u8]) -> Result<(), String> {
    let fallback_message = "Unable to copy contents to clipboard. Please make sure you have `wl-clip`, `xclip`, `xsel`, `pbcopy`, or `putclip` installed.";

    if let Ok(command) = crate::lpenv::var("LPASS_CLIPBOARD_COMMAND") {
        run_shell_clipboard_command(&command, data).map_err(|_| fallback_message.to_string())?;
        return Ok(());
    }

    let default_commands: [(&str, &[&str]); 5] = [
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard", "-in"]),
        ("xsel", &["--clipboard", "--input"]),
        ("pbcopy", &[]),
        ("putclip", &["--dos"]),
    ];

    for (program, args) in default_commands {
        match run_clipboard_command(program, args, data) {
            Ok(status) if status.success() => return Ok(()),
            Ok(_) => continue,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => continue,
        }
    }

    Err(fallback_message.to_string())
}

fn run_shell_clipboard_command(command: &str, data: &[u8]) -> std::io::Result<()> {
    let shell = crate::lpenv::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let status = run_clipboard_command(&shell, &["-c", command], data)?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("clipboard command failed"))
    }
}

fn run_clipboard_command(
    program: &str,
    args: &[&str],
    data: &[u8],
) -> std::io::Result<std::process::ExitStatus> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data)?;
    }

    child.wait()
}

fn pretty_field_value(field: &crate::blob::Field) -> String {
    if field.field_type == "checkbox" {
        return if field.checked {
            "Checked".to_string()
        } else {
            "Unchecked".to_string()
        };
    }

    if field.field_type == "radio" {
        let checked = if field.checked {
            "Checked"
        } else {
            "Unchecked"
        };
        return format!("{}, {checked}", field.value);
    }

    fix_ascii_armor(field.value.clone())
}

fn fix_ascii_armor(value: String) -> String {
    if value.len() < 20 {
        return value;
    }
    if !value.starts_with("-----BEGIN") {
        return value;
    }

    let Some(end_header_rel) = value[10..].find("----- ") else {
        return value;
    };
    let end_header = 10 + end_header_rel;

    let Some(start_trailer_rel) = value[end_header..].find("-----END") else {
        return value;
    };
    let start_trailer = end_header + start_trailer_rel;

    if !value.ends_with("-----") {
        return value;
    }

    let mut bytes = value.into_bytes();
    let mut index = end_header;
    while index < start_trailer {
        if bytes[index] == b' ' {
            if index > 0 && bytes[index - 1] == b':' {
                index += 1;
                continue;
            }
            bytes[index] = b'\n';
        }
        index += 1;
    }

    String::from_utf8(bytes).unwrap_or_default()
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
    use crate::blob::Field;
    use tempfile::TempDir;

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

    fn attachment(id: &str, parent: &str) -> Attachment {
        Attachment {
            id: id.to_string(),
            parent: parent.to_string(),
            mimetype: "text/plain".to_string(),
            storagekey: "storage".to_string(),
            size: "4".to_string(),
            filename: String::new(),
        }
    }

    #[test]
    fn find_matches_exact_prefers_id_and_supports_names() {
        let accounts = vec![
            account("0001", "alpha", "team"),
            account("0002", "beta", ""),
        ];
        let by_id = find_matches(&accounts, &["0002".to_string()], SearchMode::Exact).expect("id");
        assert_eq!(by_id, vec![1]);

        let by_fullname =
            find_matches(&accounts, &["team/alpha".to_string()], SearchMode::Exact).expect("full");
        assert_eq!(by_fullname, vec![0]);
    }

    #[test]
    fn find_matches_regex_and_fixed_modes_follow_c_style() {
        let accounts = vec![
            account("0100", "alpha", "team"),
            account("0200", "beta", "ops"),
        ];

        let regex = find_matches(
            &accounts,
            &["TEAM/ALPHA".to_string()],
            SearchMode::BasicRegex,
        )
        .expect("regex");
        assert_eq!(regex, vec![0]);

        let fixed = find_matches(
            &accounts,
            &["team/ALPHA".to_string()],
            SearchMode::FixedSubstring,
        )
        .expect("fixed");
        assert!(fixed.is_empty());
    }

    #[test]
    fn find_matches_reports_invalid_regex() {
        let accounts = vec![account("0001", "alpha", "team")];
        let err = find_matches(&accounts, &["[".to_string()], SearchMode::BasicRegex)
            .expect_err("invalid regex");
        assert!(err.contains("Invalid regex"));
    }

    #[test]
    fn attachments_helpers_cover_id_lookup_and_binary_detection() {
        let list = vec![attachment("1", "0001"), attachment("2", "0002")];
        assert_eq!(attachments_for_account(&list, "0001").len(), 1);
        assert!(find_attachment(&list, "0001", "1").is_some());
        assert!(find_attachment(&list, "0001", "att-1").is_some());
        assert!(find_attachment(&list, "0001", "3").is_none());

        assert!(!attachment_is_binary(b"hello world"));
        assert!(attachment_is_binary(&[0, 1, 2, 3]));
    }

    #[test]
    fn parse_attachment_response_handles_json_and_escaped_fallback() {
        assert_eq!(parse_attachment_response("\"value\""), "value");
        assert_eq!(parse_attachment_response("\"a\\\\b\""), "a\\b");
    }

    #[test]
    fn pretty_field_value_handles_checkbox_radio_and_ascii_armor() {
        let checkbox = Field {
            name: "flag".to_string(),
            field_type: "checkbox".to_string(),
            value: "ignored".to_string(),
            value_encrypted: None,
            checked: true,
        };
        assert_eq!(pretty_field_value(&checkbox), "Checked");

        let radio = Field {
            name: "radio".to_string(),
            field_type: "radio".to_string(),
            value: "choice".to_string(),
            value_encrypted: None,
            checked: false,
        };
        assert_eq!(pretty_field_value(&radio), "choice, Unchecked");

        let armor = Field {
            name: "key".to_string(),
            field_type: "textarea".to_string(),
            value: "-----BEGIN TEST----- payload -----END TEST-----".to_string(),
            value_encrypted: None,
            checked: false,
        };
        assert!(pretty_field_value(&armor).contains("\n"));
    }

    #[test]
    fn decode_attachment_key_rejects_missing_key() {
        let mut acct = account("1", "n", "");
        let err = decode_attachment_key(&acct).expect_err("missing");
        assert!(err.contains("Missing attach key"));

        acct.attachkey = "zz".repeat(32);
        let err = decode_attachment_key(&acct).expect_err("invalid");
        assert!(err.contains("Invalid attach key"));
    }

    #[test]
    fn emit_helpers_cover_clip_and_stdout_paths() {
        let mut clipboard = Vec::new();
        emit_line("line", true, &mut clipboard).expect("clip line");
        emit_value("value", true, &mut clipboard).expect("clip value");
        emit_bytes(b"bytes", true, &mut clipboard).expect("clip bytes");
        assert_eq!(clipboard, b"line\nvaluebytes".to_vec());
    }

    #[test]
    fn parse_attachment_response_fallback_path_unescapes_backslashes() {
        let raw = "\"broken\\\\tail";
        assert_eq!(parse_attachment_response(raw), "\"broken\\tail");
    }

    #[test]
    fn run_shell_clipboard_command_surfaces_nonzero_status() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("SHELL", "/bin/sh");
        let err = run_shell_clipboard_command("exit 1", b"v").expect_err("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn copy_to_clipboard_maps_failed_custom_command_to_user_error() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_CLIPBOARD_COMMAND", "exit 1");
        crate::lpenv::set_override_for_tests("SHELL", "/bin/sh");
        let err = copy_to_clipboard(b"v").expect_err("must fail");
        assert!(err.contains("Unable to copy contents to clipboard"));
    }

    #[test]
    fn parse_binary_attachment_response_supports_default_and_options() {
        assert_eq!(
            parse_binary_attachment_response("\n"),
            Some(BinaryAttachmentAction::Save)
        );
        assert_eq!(
            parse_binary_attachment_response("y\n"),
            Some(BinaryAttachmentAction::Print)
        );
        assert_eq!(
            parse_binary_attachment_response("N\r\n"),
            Some(BinaryAttachmentAction::Skip)
        );
        assert_eq!(
            parse_binary_attachment_response("s"),
            Some(BinaryAttachmentAction::Save)
        );
        assert_eq!(parse_binary_attachment_response("x\n"), None);
    }

    #[test]
    fn save_attachment_to_file_writes_binary_payload() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("file.bin");
        let payload = [0u8, 1u8, 2u8];
        save_attachment_to_file(path.to_str().expect("utf8"), &payload).expect("save");
        let written = std::fs::read(&path).expect("read file");
        assert_eq!(written, payload);
    }

    #[test]
    fn run_inner_option_parsing_branches_surface_runtime_error_after_parse() {
        let err = run_inner(&[
            "--all".to_string(),
            "--field".to_string(),
            "User".to_string(),
            "--attach".to_string(),
            "1".to_string(),
            "--format".to_string(),
            "%fn".to_string(),
            "--title-format".to_string(),
            "%an".to_string(),
            "--color".to_string(),
            "never".to_string(),
            "--quiet".to_string(),
            "entry".to_string(),
        ])
        .expect_err("must fail without local config");
        assert!(
            err.contains("missing iterations")
                || err.contains("Could not find")
                || err.contains("Unable to fetch blob")
        );
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
        assert!(run_inner(&["--attach".to_string()]).is_err());
        assert!(run_inner(&["--format".to_string()]).is_err());
        assert!(run_inner(&["--title-format".to_string()]).is_err());
    }
}
