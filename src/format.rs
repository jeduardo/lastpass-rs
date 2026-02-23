#![forbid(unsafe_code)]

use crate::blob::Account;

pub fn get_display_fullname(account: &Account) -> String {
    if account.share_name.is_some() || !account.group.is_empty() {
        account.fullname.clone()
    } else {
        format!("(none)/{}", account.fullname)
    }
}

pub fn format_timestamp(timestamp: &str, utc: bool) -> String {
    let ts = timestamp.trim();
    if ts.is_empty() {
        return String::new();
    }
    let Ok(secs) = ts.parse::<i64>() else {
        return String::new();
    };
    if secs == 0 {
        return String::new();
    }

    let datetime = match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => dt,
        Err(_) => return String::new(),
    };

    let dt = if utc {
        datetime
    } else {
        let offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
        datetime.to_offset(offset)
    };

    let format = time::format_description::parse("[year]-[month]-[day] [hour]:[minute]");
    match format {
        Ok(desc) => dt.format(&desc).unwrap_or_default(),
        Err(_) => dt
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    }
}

pub fn format_account(format_str: &str, account: &Account) -> String {
    format_field(format_str, account, None, None)
}

pub fn format_field(
    format_str: &str,
    account: &Account,
    field_name: Option<&str>,
    field_value: Option<&str>,
) -> String {
    let mut out = String::new();
    let mut chars = format_str.chars().peekable();
    let mut in_format = false;
    let mut add_slash = false;

    while let Some(ch) = chars.next() {
        if !in_format {
            if ch == '%' {
                in_format = true;
            } else {
                out.push(ch);
            }
            continue;
        }

        match ch {
            '%' => {
                out.push('%');
            }
            '/' => {
                add_slash = true;
                continue;
            }
            'f' => {
                if let Some(spec) = chars.next() {
                    match spec {
                        'n' => append_str(&mut out, field_name.unwrap_or(""), add_slash),
                        'v' => append_str(&mut out, field_value.unwrap_or(""), add_slash),
                        _ => {
                            out.push('%');
                            out.push('f');
                            out.push(spec);
                        }
                    }
                } else {
                    out.push('%');
                    out.push('f');
                }
            }
            'a' => {
                if let Some(spec) = chars.next() {
                    format_account_item(&mut out, spec, account, add_slash);
                } else {
                    out.push('%');
                    out.push('a');
                }
            }
            _ => {
                out.push('%');
                out.push(ch);
            }
        }

        add_slash = false;
        in_format = false;
    }

    out
}

fn append_str(out: &mut String, value: &str, add_slash: bool) {
    if value.is_empty() {
        return;
    }
    out.push_str(value);
    if add_slash {
        out.push('/');
    }
}

fn format_account_item(out: &mut String, spec: char, account: &Account, add_slash: bool) {
    match spec {
        'i' => append_str(out, &account.id, add_slash),
        'n' => append_str(out, &account.name, add_slash),
        'N' => append_str(out, &get_display_fullname(account), add_slash),
        'u' => append_str(out, &account.username, add_slash),
        'p' => append_str(out, &account.password, add_slash),
        'm' => append_str(
            out,
            &format_timestamp(&account.last_modified_gmt, true),
            add_slash,
        ),
        'U' => append_str(
            out,
            &format_timestamp(&account.last_touch, false),
            add_slash,
        ),
        'g' => append_str(out, &account.group, add_slash),
        'l' => append_str(out, &account.url, add_slash),
        's' => append_str(out, account.share_name.as_deref().unwrap_or(""), add_slash),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_account() -> Account {
        Account {
            id: "0001".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: "test".to_string(),
            name_encrypted: None,
            group: "group".to_string(),
            group_encrypted: None,
            fullname: "group/test".to_string(),
            url: "https://example.com".to_string(),
            url_encrypted: None,
            username: "user".to_string(),
            username_encrypted: None,
            password: "pass".to_string(),
            password_encrypted: None,
            note: "".to_string(),
            note_encrypted: None,
            last_touch: "0".to_string(),
            last_modified_gmt: "0".to_string(),
            fav: false,
            pwprotect: false,
            attachkey: "".to_string(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        }
    }

    #[test]
    fn display_fullname_grouped() {
        let account = sample_account();
        assert_eq!(get_display_fullname(&account), "group/test");
    }

    #[test]
    fn display_fullname_none_group() {
        let mut account = sample_account();
        account.group.clear();
        account.fullname = "test".to_string();
        assert_eq!(get_display_fullname(&account), "(none)/test");
    }

    #[test]
    fn display_fullname_shared() {
        let mut account = sample_account();
        account.group.clear();
        account.share_name = Some("shared".to_string());
        account.fullname = "shared/test".to_string();
        assert_eq!(get_display_fullname(&account), "shared/test");
    }

    #[test]
    fn format_account_items() {
        let account = sample_account();
        let output = format_account("%ai %an %ag", &account);
        assert_eq!(output, "0001 test group");
    }

    #[test]
    fn format_field_items() {
        let account = sample_account();
        let output = format_field("%fn=%fv", &account, Some("Field"), Some("Value"));
        assert_eq!(output, "Field=Value");
    }

    #[test]
    fn format_add_slash() {
        let account = sample_account();
        let output = format_account("%/aN", &account);
        assert_eq!(output, "group/test/");
    }

    #[test]
    fn format_timestamp_handles_empty_invalid_and_zero_values() {
        assert_eq!(format_timestamp("", true), "");
        assert_eq!(format_timestamp("not-a-number", true), "");
        assert_eq!(format_timestamp("0", true), "");
    }

    #[test]
    fn format_timestamp_formats_valid_unix_seconds() {
        let utc = format_timestamp("1", true);
        assert!(!utc.is_empty());
        assert!(utc.contains('-'));
        assert!(utc.contains(':'));

        let local = format_timestamp("1", false);
        assert!(!local.is_empty());
    }

    #[test]
    fn format_field_handles_escape_and_unknown_specifiers() {
        let account = sample_account();
        assert_eq!(format_field("%%", &account, None, None), "%");
        assert_eq!(format_field("%x", &account, None, None), "%x");
        assert_eq!(format_field("%fZ", &account, None, None), "%fZ");
        assert_eq!(format_field("%aZ", &account, None, None), "");
        assert_eq!(format_field("%f", &account, None, None), "%f");
        assert_eq!(format_field("%a", &account, None, None), "%a");
    }

    #[test]
    fn format_account_supports_all_known_account_items() {
        let mut account = sample_account();
        account.share_name = Some("shared".to_string());
        account.last_touch = "1".to_string();
        account.last_modified_gmt = "1".to_string();
        let output = format_account("%ai|%an|%aN|%au|%ap|%am|%aU|%ag|%al|%as", &account);
        assert!(output.contains("0001|test|group/test|user|pass|"));
        assert!(output.contains("|group|https://example.com|shared"));
    }
}
