#![forbid(unsafe_code)]

use crate::blob::{Account, Field};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NoteType {
    None,
    Amex,
    Bank,
    Credit,
    Database,
    DriversLicense,
    Email,
    HealthInsurance,
    Im,
    Insurance,
    Mastercard,
    Membership,
    Passport,
    Server,
    SoftwareLicense,
    SshKey,
    Ssn,
    Visa,
    Wifi,
}

struct NoteTemplate {
    shortname: &'static str,
    name: &'static str,
    fields: &'static [&'static str],
}

const NOTE_TEMPLATES: &[NoteTemplate] = &[
    NoteTemplate {
        shortname: "amex",
        name: "American Express",
        fields: &[],
    },
    NoteTemplate {
        shortname: "bank",
        name: "Bank Account",
        fields: &[
            "Bank Name",
            "Account Type",
            "Routing Number",
            "Account Number",
            "SWIFT Code",
            "IBAN Number",
            "Pin",
            "Branch Address",
            "Branch Phone",
        ],
    },
    NoteTemplate {
        shortname: "credit-card",
        name: "Credit Card",
        fields: &[
            "Name on Card",
            "Type",
            "Number",
            "Security Code",
            "Start Date",
            "Expiration Date",
        ],
    },
    NoteTemplate {
        shortname: "database",
        name: "Database",
        fields: &[
            "Type", "Hostname", "Port", "Database", "Username", "Password", "SID", "Alias",
        ],
    },
    NoteTemplate {
        shortname: "drivers-license",
        name: "Driver's License",
        fields: &[
            "Number",
            "Expiration Date",
            "License Class",
            "Name",
            "Address",
            "City / Town",
            "State",
            "ZIP / Postal Code",
            "Country",
            "Date of Birth",
            "Sex",
            "Height",
        ],
    },
    NoteTemplate {
        shortname: "email",
        name: "Email Account",
        fields: &[
            "Username",
            "Password",
            "Server",
            "Port",
            "Type",
            "SMTP Server",
            "SMTP Port",
        ],
    },
    NoteTemplate {
        shortname: "health-insurance",
        name: "Health Insurance",
        fields: &[
            "Company",
            "Company Phone",
            "Policy Type",
            "Policy Number",
            "Group ID",
            "Member Name",
            "Member ID",
            "Physician Name",
            "Physician Phone",
            "Physician Address",
            "Co-pay",
        ],
    },
    NoteTemplate {
        shortname: "im",
        name: "Instant Messenger",
        fields: &["Type", "Username", "Password", "Server", "Port"],
    },
    NoteTemplate {
        shortname: "insurance",
        name: "Insurance",
        fields: &[
            "Company",
            "Policy Type",
            "Policy Number",
            "Expiration",
            "Agent Name",
            "Agent Phone",
            "URL",
        ],
    },
    NoteTemplate {
        shortname: "mastercard",
        name: "Mastercard",
        fields: &[],
    },
    NoteTemplate {
        shortname: "membership",
        name: "Membership",
        fields: &[
            "Organization",
            "Membership Number",
            "Member Name",
            "Start Date",
            "Expiration Date",
            "Website",
            "Telephone",
            "Password",
        ],
    },
    NoteTemplate {
        shortname: "passport",
        name: "Passport",
        fields: &[
            "Type",
            "Name",
            "Country",
            "Number",
            "Sex",
            "Nationality",
            "Date of Birth",
            "Issued Date",
            "Expiration Date",
        ],
    },
    NoteTemplate {
        shortname: "server",
        name: "Server",
        fields: &["Hostname", "Username", "Password"],
    },
    NoteTemplate {
        shortname: "software-license",
        name: "Software License",
        fields: &[
            "License Key",
            "Licensee",
            "Version",
            "Publisher",
            "Support Email",
            "Website",
            "Price",
            "Purchase Date",
            "Order Number",
            "Number of Licenses",
            "Order Total",
        ],
    },
    NoteTemplate {
        shortname: "ssh-key",
        name: "SSH Key",
        fields: &[
            "Bit Strength",
            "Format",
            "Passphrase",
            "Private Key",
            "Public Key",
            "Hostname",
            "Date",
        ],
    },
    NoteTemplate {
        shortname: "ssn",
        name: "Social Security",
        fields: &["Name", "Number"],
    },
    NoteTemplate {
        shortname: "visa",
        name: "VISA",
        fields: &[],
    },
    NoteTemplate {
        shortname: "wifi",
        name: "Wi-Fi Password",
        fields: &[
            "SSID",
            "Password",
            "Connection Type",
            "Connection Mode",
            "Authentication",
            "Encryption",
            "Use 802.1X",
            "FIPS Mode",
            "Key Type",
            "Protected",
            "Key Index",
        ],
    },
];

pub fn note_type_by_shortname(shortname: &str) -> NoteType {
    for (idx, template) in NOTE_TEMPLATES.iter().enumerate() {
        if shortname.eq_ignore_ascii_case(template.shortname) {
            return NoteType::from_index(idx);
        }
    }
    NoteType::None
}

pub fn note_type_display_name(note_type: NoteType) -> Option<&'static str> {
    let idx = note_type.to_index();
    if idx == usize::MAX {
        return None;
    }
    NOTE_TEMPLATES.get(idx).map(|template| template.name)
}

pub fn note_type_by_name(name: &str) -> NoteType {
    let trimmed = name.trim();
    for (idx, template) in NOTE_TEMPLATES.iter().enumerate() {
        if trimmed.eq_ignore_ascii_case(template.name) {
            return NoteType::from_index(idx);
        }
    }
    NoteType::None
}

pub fn note_has_field(note_type: NoteType, field: &str) -> bool {
    if note_type == NoteType::None {
        return true;
    }
    let idx = note_type.to_index();
    let Some(template) = NOTE_TEMPLATES.get(idx) else {
        return true;
    };
    template.fields.iter().any(|name| name == &field)
}

pub fn note_type_fields(note_type: NoteType) -> &'static [&'static str] {
    if note_type == NoteType::None {
        return &[];
    }
    let idx = note_type.to_index();
    NOTE_TEMPLATES
        .get(idx)
        .map(|template| template.fields)
        .unwrap_or(&[])
}

pub fn note_field_is_multiline(note_type: NoteType, field: &str) -> bool {
    note_type == NoteType::SshKey && field == "Private Key"
}

impl NoteType {
    fn to_index(self) -> usize {
        match self {
            NoteType::None => usize::MAX,
            NoteType::Amex => 0,
            NoteType::Bank => 1,
            NoteType::Credit => 2,
            NoteType::Database => 3,
            NoteType::DriversLicense => 4,
            NoteType::Email => 5,
            NoteType::HealthInsurance => 6,
            NoteType::Im => 7,
            NoteType::Insurance => 8,
            NoteType::Mastercard => 9,
            NoteType::Membership => 10,
            NoteType::Passport => 11,
            NoteType::Server => 12,
            NoteType::SoftwareLicense => 13,
            NoteType::SshKey => 14,
            NoteType::Ssn => 15,
            NoteType::Visa => 16,
            NoteType::Wifi => 17,
        }
    }

    fn from_index(idx: usize) -> NoteType {
        match idx {
            0 => NoteType::Amex,
            1 => NoteType::Bank,
            2 => NoteType::Credit,
            3 => NoteType::Database,
            4 => NoteType::DriversLicense,
            5 => NoteType::Email,
            6 => NoteType::HealthInsurance,
            7 => NoteType::Im,
            8 => NoteType::Insurance,
            9 => NoteType::Mastercard,
            10 => NoteType::Membership,
            11 => NoteType::Passport,
            12 => NoteType::Server,
            13 => NoteType::SoftwareLicense,
            14 => NoteType::SshKey,
            15 => NoteType::Ssn,
            16 => NoteType::Visa,
            17 => NoteType::Wifi,
            _ => NoteType::None,
        }
    }
}

pub fn note_type_usage() -> String {
    let mut out = String::from("--note-type=TYPE\n\nValid values for TYPE:\n");
    for (idx, template) in NOTE_TEMPLATES.iter().enumerate() {
        out.push('\t');
        out.push_str(template.shortname);
        if idx + 1 != NOTE_TEMPLATES.len() {
            out.push('\n');
        }
    }
    out
}

pub fn account_is_secure_note(account: &Account) -> bool {
    account.url == "http://sn"
}

pub fn expand_notes(account: &Account) -> Option<Account> {
    if !account_is_secure_note(account) {
        return None;
    }
    if !account.note.starts_with("NoteType:") {
        return None;
    }

    let mut expanded = Account {
        id: account.id.clone(),
        share_name: account.share_name.clone(),
        share_id: account.share_id.clone(),
        share_readonly: account.share_readonly,
        name: account.name.clone(),
        name_encrypted: account.name_encrypted.clone(),
        group: account.group.clone(),
        group_encrypted: account.group_encrypted.clone(),
        fullname: account.fullname.clone(),
        url: String::new(),
        url_encrypted: None,
        username: String::new(),
        username_encrypted: None,
        password: String::new(),
        password_encrypted: None,
        note: String::new(),
        note_encrypted: None,
        last_touch: account.last_touch.clone(),
        last_modified_gmt: account.last_modified_gmt.clone(),
        fav: account.fav,
        pwprotect: account.pwprotect,
        attachkey: account.attachkey.clone(),
        attachkey_encrypted: account.attachkey_encrypted.clone(),
        attachpresent: account.attachpresent,
        fields: Vec::new(),
    };

    let note_type = parse_note_type(&account.note);
    let bytes = account.note.as_bytes();
    let mut start = 0usize;
    let mut current_field: Option<usize> = None;

    while start <= bytes.len() {
        let mut end = start;
        while end < bytes.len() && bytes[end] != b'\n' {
            end += 1;
        }
        let line = &account.note[start..end];

        if line.is_empty() && current_field.is_none() {
            if end == bytes.len() {
                break;
            }
            start = end + 1;
            continue;
        }

        if let Some(colon_pos) = line.find(':') {
            let name = &line[..colon_pos];
            let value = &line[colon_pos + 1..];

            if !note_has_field(note_type, name)
                && current_field.is_some()
                && note_field_is_multiline(
                    note_type,
                    expanded.fields[current_field.unwrap()].name.as_str(),
                )
            {
                let field = &mut expanded.fields[current_field.unwrap()];
                field.value.push('\n');
                field.value.push_str(line);
            } else if name == "Username" {
                expanded.username = value.to_string();
            } else if name == "Password" {
                expanded.password = value.to_string();
            } else if name == "URL" {
                expanded.url = value.to_string();
            } else if name == "Notes" {
                let rest = &account.note[start..];
                let value_start = rest.find(':').unwrap_or(0) + 1;
                let mut note = rest[value_start..].to_string();
                if note.ends_with('\n') {
                    note.pop();
                }
                expanded.note = note;
                break;
            } else {
                let field = Field {
                    name: name.to_string(),
                    field_type: "text".to_string(),
                    value: value.to_string(),
                    value_encrypted: None,
                    checked: false,
                };
                expanded.fields.insert(0, field);
                current_field = Some(0);
            }
        } else if let Some(idx) = current_field {
            let field = &mut expanded.fields[idx];
            field.value.push('\n');
            field.value.push_str(line);
        }

        if end == bytes.len() {
            break;
        }
        start = end + 1;
    }

    if expanded.note.is_empty()
        && expanded.username.is_empty()
        && expanded.password.is_empty()
        && expanded.url.is_empty()
        && expanded.fields.is_empty()
    {
        expanded.note = account.note.clone();
    } else if expanded.note.is_empty() {
        expanded.note = String::new();
    }

    Some(expanded)
}

pub fn collapse_notes(account: &Account) -> Account {
    let mut lines: Vec<String> = Vec::new();
    let mut note_type_line: Option<String> = None;

    for field in &account.fields {
        let name = field.name.trim();
        let value = field.value.trim();
        let line = format!("{}:{}", name, value);
        if name == "NoteType" {
            note_type_line = Some(line);
        } else {
            lines.push(line);
        }
    }

    if let Some(line) = note_type_line {
        lines.insert(0, line);
    }

    if !account.username.is_empty() {
        lines.push(format!("Username:{}", account.username.trim()));
    }
    if !account.password.is_empty() {
        lines.push(format!("Password:{}", account.password.trim()));
    }
    if !account.url.is_empty() {
        lines.push(format!("URL:{}", account.url.trim()));
    }
    if !account.note.is_empty() {
        lines.push(format!("Notes:{}", account.note.trim()));
    }

    let note = lines.join("\n");

    Account {
        id: account.id.clone(),
        share_name: account.share_name.clone(),
        share_id: account.share_id.clone(),
        share_readonly: account.share_readonly,
        name: account.name.clone(),
        name_encrypted: account.name_encrypted.clone(),
        group: account.group.clone(),
        group_encrypted: account.group_encrypted.clone(),
        fullname: account.fullname.clone(),
        url: "http://sn".to_string(),
        url_encrypted: None,
        username: String::new(),
        username_encrypted: None,
        password: String::new(),
        password_encrypted: None,
        note,
        note_encrypted: None,
        last_touch: account.last_touch.clone(),
        last_modified_gmt: account.last_modified_gmt.clone(),
        fav: account.fav,
        pwprotect: account.pwprotect,
        attachkey: account.attachkey.clone(),
        attachkey_encrypted: account.attachkey_encrypted.clone(),
        attachpresent: account.attachpresent,
        fields: Vec::new(),
    }
}

fn parse_note_type(note: &str) -> NoteType {
    let Some(rest) = note.strip_prefix("NoteType:") else {
        return NoteType::None;
    };
    let line_end = rest.find('\n').unwrap_or(rest.len());
    let note_name = &rest[..line_end];
    note_type_by_name(note_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_secure_note(note: &str) -> Account {
        Account {
            id: "1".to_string(),
            share_name: None,
            share_id: None,
            share_readonly: false,
            name: "note".to_string(),
            name_encrypted: None,
            group: "".to_string(),
            group_encrypted: None,
            fullname: "note".to_string(),
            url: "http://sn".to_string(),
            url_encrypted: None,
            username: "".to_string(),
            username_encrypted: None,
            password: "".to_string(),
            password_encrypted: None,
            note: note.to_string(),
            note_encrypted: None,
            last_touch: "".to_string(),
            last_modified_gmt: "".to_string(),
            fav: false,
            pwprotect: false,
            attachkey: "".to_string(),
            attachkey_encrypted: None,
            attachpresent: false,
            fields: Vec::new(),
        }
    }

    #[test]
    fn expand_parses_fields() {
        let note = "NoteType: Server\nHostname: foo\nUsername: user\nPassword: pass";
        let account = base_secure_note(note);
        let expanded = expand_notes(&account).expect("expanded");
        assert_eq!(expanded.username, " user");
        assert_eq!(expanded.password, " pass");
        assert_eq!(expanded.fields.len(), 2);
        assert_eq!(expanded.fields[0].name, "Hostname");
        assert_eq!(expanded.fields[1].name, "NoteType");
    }

    #[test]
    fn expand_notes_field_consumes_rest() {
        let note = "NoteType: Secure\nNotes: line1\nline2\nUsername: ignored";
        let account = base_secure_note(note);
        let expanded = expand_notes(&account).expect("expanded");
        assert_eq!(expanded.note, " line1\nline2\nUsername: ignored");
    }

    #[test]
    fn collapse_includes_notetype_first() {
        let mut account = base_secure_note("");
        account.url = "http://sn".to_string();
        account.fields.push(Field {
            name: "NoteType".to_string(),
            field_type: "text".to_string(),
            value: " Server".to_string(),
            value_encrypted: None,
            checked: false,
        });
        account.fields.push(Field {
            name: "Hostname".to_string(),
            field_type: "text".to_string(),
            value: " foo".to_string(),
            value_encrypted: None,
            checked: false,
        });

        let collapsed = collapse_notes(&account);
        let lines: Vec<&str> = collapsed.note.lines().collect();
        assert_eq!(lines[0], "NoteType:Server");
        assert_eq!(lines[1], "Hostname:foo");
        assert_eq!(collapsed.url, "http://sn");
    }

    #[test]
    fn note_type_mappings_and_usage_are_consistent() {
        assert_eq!(note_type_by_shortname("server"), NoteType::Server);
        assert_eq!(note_type_by_shortname("SSH-KEY"), NoteType::SshKey);
        assert_eq!(note_type_by_shortname("unknown"), NoteType::None);

        assert_eq!(note_type_by_name("Server"), NoteType::Server);
        assert_eq!(note_type_by_name(" social security "), NoteType::Ssn);
        assert_eq!(note_type_by_name("missing"), NoteType::None);

        assert_eq!(
            note_type_display_name(NoteType::Wifi),
            Some("Wi-Fi Password")
        );
        assert_eq!(note_type_display_name(NoteType::None), None);

        let usage = note_type_usage();
        assert!(usage.contains("--note-type=TYPE"));
        assert!(usage.contains("server"));
        assert!(usage.contains("ssh-key"));
    }

    #[test]
    fn note_field_metadata_matches_templates() {
        assert!(note_has_field(NoteType::Server, "Hostname"));
        assert!(!note_has_field(NoteType::Server, "NotAField"));
        assert!(note_has_field(NoteType::None, "Anything"));

        assert!(note_field_is_multiline(NoteType::SshKey, "Private Key"));
        assert!(!note_field_is_multiline(NoteType::SshKey, "Public Key"));
        assert!(!note_field_is_multiline(NoteType::Server, "Private Key"));
    }

    #[test]
    fn secure_note_detection_and_passthrough_behavior() {
        let mut non_secure = base_secure_note("plain text");
        non_secure.url = "https://example.com".to_string();
        assert!(!account_is_secure_note(&non_secure));
        assert!(expand_notes(&non_secure).is_none());

        let secure_plain = base_secure_note("not prefixed");
        assert!(account_is_secure_note(&secure_plain));
        assert!(expand_notes(&secure_plain).is_none());
    }

    #[test]
    fn collapse_notes_includes_username_password_url_and_notes() {
        let mut account = base_secure_note("ignored");
        account.fields.push(Field {
            name: "Hostname".to_string(),
            field_type: "text".to_string(),
            value: " app.example.com ".to_string(),
            value_encrypted: None,
            checked: false,
        });
        account.username = " alice ".to_string();
        account.password = " secret ".to_string();
        account.url = " https://example.com ".to_string();
        account.note = " memo ".to_string();

        let collapsed = collapse_notes(&account);
        assert_eq!(collapsed.url, "http://sn");
        assert!(collapsed.note.contains("Hostname:app.example.com"));
        assert!(collapsed.note.contains("Username:alice"));
        assert!(collapsed.note.contains("Password:secret"));
        assert!(collapsed.note.contains("URL:https://example.com"));
        assert!(collapsed.note.contains("Notes:memo"));
    }

    #[test]
    fn note_type_fields_returns_empty_for_none() {
        assert!(note_type_fields(NoteType::None).is_empty());
        assert!(!note_type_fields(NoteType::Server).is_empty());
    }

    #[test]
    fn expand_notes_handles_blank_lines_and_multiline_fields() {
        let note = "NoteType: SSH Key\n\nPrivate Key: line1\nProc-Type: 4,ENCRYPTED\nline2\nNotes: note-body\ntrailing";
        let account = base_secure_note(note);
        let expanded = expand_notes(&account).expect("expanded");
        let private_key = expanded
            .fields
            .iter()
            .find(|field| field.name == "Private Key")
            .expect("private key");
        assert!(private_key.value.contains("line1"));
        assert!(private_key.value.contains("Proc-Type: 4,ENCRYPTED"));
        assert!(private_key.value.contains("line2"));
        assert!(private_key.value.contains("Notes: note-body"));
        assert!(expanded.note.is_empty());
    }

    #[test]
    fn expand_notes_falls_back_when_no_fields_present() {
        let note = "NoteType: Server\n";
        let account = base_secure_note(note);
        let expanded = expand_notes(&account).expect("expanded");
        assert!(expanded.note.is_empty());
        assert!(!expanded.fields.is_empty());
    }
}
