#![forbid(unsafe_code)]

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::session::Session;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PwChangeInfo {
    pub reencrypt_id: String,
    pub token: String,
    pub privkey_encrypted: String,
    pub new_privkey_encrypted: String,
    pub new_privkey_hash: String,
    pub new_key_hash: String,
    pub fields: Vec<PwChangeField>,
    pub su_keys: Vec<PwChangeSuKey>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PwChangeField {
    pub old_ctext: String,
    pub new_ctext: String,
    pub optional: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PwChangeSuKey {
    pub uid: String,
    pub sharing_key: Vec<u8>,
    pub new_enc_key: String,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PwChangeParseError {
    IncorrectPassword,
    Invalid,
}

pub fn parse_ok_session(xml: &str) -> Option<Session> {
    let attrs = parse_ok_attributes(xml)?;
    let uid = attrs.get("uid")?.to_string();
    let session_id = attrs.get("sessionid")?.to_string();
    let token = attrs.get("token")?.to_string();

    let mut session = Session {
        uid,
        session_id,
        token,
        url_encryption_enabled: parse_flag(&attrs, "url_encryption"),
        url_logging_enabled: parse_flag(&attrs, "url_logging"),
        server: None,
        private_key: None,
        private_key_enc: None,
    };

    if let Some(private_key_enc) = attrs
        .get("privatekeyenc")
        .or_else(|| attrs.get("privatekey"))
        .or_else(|| {
            attrs
                .iter()
                .find(|(name, _)| name.starts_with("privatekey"))
                .map(|(_, value)| value)
        })
    {
        session.set_private_key_enc(private_key_enc);
    }

    if session.is_valid() {
        Some(session)
    } else {
        None
    }
}

pub fn parse_login_check(xml: &str, session: &mut Session) -> Option<u64> {
    let attrs = parse_ok_attributes(xml)?;

    if let Some(uid) = attrs.get("uid") {
        session.uid = uid.to_string();
    }
    if let Some(session_id) = attrs.get("sessionid") {
        session.session_id = session_id.to_string();
    }
    if let Some(token) = attrs.get("token") {
        session.token = token.to_string();
    }
    if attrs.contains_key("url_encryption") {
        session.url_encryption_enabled = parse_flag(&attrs, "url_encryption");
    }
    if attrs.contains_key("url_logging") {
        session.url_logging_enabled = parse_flag(&attrs, "url_logging");
    }

    attrs
        .get("accts_version")
        .and_then(|val| val.parse::<u64>().ok())
}

pub fn parse_error_cause(xml: &str, attr_name: &str) -> Option<String> {
    parse_error_attribute(xml, attr_name)
}

pub fn parse_lastpass_api_ok(xml: &str) -> Option<bool> {
    let attrs = parse_element_attributes(xml, b"lastpass")?;
    Some(attrs.get("rc").map(String::as_str) == Some("OK"))
}

pub fn parse_pwchange(xml: &str) -> std::result::Result<PwChangeInfo, PwChangeParseError> {
    let root_attrs =
        parse_element_attributes(xml, b"lastpass").ok_or(PwChangeParseError::Invalid)?;
    if root_attrs.get("rc").map(String::as_str) != Some("OK") {
        return Err(PwChangeParseError::IncorrectPassword);
    }

    let data_attrs = parse_element_attributes(xml, b"data").ok_or(PwChangeParseError::Invalid)?;
    let data = data_attrs
        .get("xml")
        .ok_or(PwChangeParseError::Invalid)?
        .clone();
    let (reencrypt_id, privkey_encrypted, fields) = parse_pwchange_data(&data)?;

    Ok(PwChangeInfo {
        reencrypt_id,
        token: data_attrs.get("token").cloned().unwrap_or_default(),
        privkey_encrypted,
        new_privkey_encrypted: String::new(),
        new_privkey_hash: String::new(),
        new_key_hash: String::new(),
        fields,
        su_keys: parse_pwchange_su_keys(&data_attrs),
    })
}

fn parse_ok_attributes(xml: &str) -> Option<std::collections::HashMap<String, String>> {
    parse_element_attributes(xml, b"ok")
}

fn parse_error_attribute(xml: &str, attr_name: &str) -> Option<String> {
    let attrs = parse_element_attributes(xml, b"error")?;
    attrs.get(attr_name).cloned()
}

fn parse_flag(attrs: &std::collections::HashMap<String, String>, key: &str) -> bool {
    attrs.get(key).map(String::as_str) == Some("1")
}

fn parse_pwchange_data(
    data: &str,
) -> std::result::Result<(String, String, Vec<PwChangeField>), PwChangeParseError> {
    let Some((reencrypt_id, rest)) = split_pwchange_line(data) else {
        return Err(PwChangeParseError::Invalid);
    };
    let Some((privkey_encrypted, rest)) = split_pwchange_line(rest) else {
        return Err(PwChangeParseError::Invalid);
    };

    let mut fields = Vec::new();
    for token in rest.split('\n').filter(|line| !line.is_empty()) {
        if token.starts_with("endmarker") {
            break;
        }

        let (old_ctext, optional) = if let Some((value, suffix)) = token.split_once('\t') {
            (value.to_string(), suffix.starts_with('0'))
        } else {
            (token.to_string(), false)
        };

        fields.push(PwChangeField {
            old_ctext,
            new_ctext: String::new(),
            optional,
        });
    }

    Ok((reencrypt_id.to_string(), privkey_encrypted.to_string(), fields))
}

fn split_pwchange_line(data: &str) -> Option<(&str, &str)> {
    let newline = data.find('\n')?;
    Some((&data[..newline], &data[newline + 1..]))
}

fn parse_pwchange_su_keys(
    attrs: &std::collections::HashMap<String, String>,
) -> Vec<PwChangeSuKey> {
    let mut su_keys = Vec::new();
    for idx in 0.. {
        let sukey = format!("sukey{idx}");
        let suuid = format!("suuid{idx}");
        let Some(key_hex) = attrs.get(&sukey) else {
            break;
        };
        let Some(uid) = attrs.get(&suuid) else {
            break;
        };
        let Ok(sharing_key) = hex::decode(key_hex) else {
            break;
        };
        su_keys.push(PwChangeSuKey {
            uid: uid.clone(),
            sharing_key,
            new_enc_key: String::new(),
        });
    }
    su_keys
}

fn parse_element_attributes(
    xml: &str,
    element_name: &[u8],
) -> Option<std::collections::HashMap<String, String>> {
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                if e.name().as_ref() == element_name {
                    let mut attrs = std::collections::HashMap::new();
                    for attr in e.attributes().with_checks(false).flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        if let Ok(value) = attr.unescape_value() {
                            attrs.insert(key, value.to_string());
                        }
                    }
                    return Some(attrs);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ok_session_basic() {
        let xml = "<response><ok uid=\"57747756\" sessionid=\"1234\" token=\"abcd\"/></response>";
        let session = parse_ok_session(xml).expect("session");
        assert_eq!(session.uid, "57747756");
        assert_eq!(session.session_id, "1234");
        assert_eq!(session.token, "abcd");
    }

    #[test]
    fn parse_ok_session_privatekey_fallback() {
        let xml =
            "<response><ok uid=\"1\" sessionid=\"2\" token=\"3\" privatekey=\"enc\"/></response>";
        let session = parse_ok_session(xml).expect("session");
        assert_eq!(session.private_key_enc.as_deref(), Some("enc"));
    }

    #[test]
    fn parse_error_attribute_message() {
        let xml = "<response><error message=\"invalid password\"/></response>";
        let msg = parse_error_cause(xml, "message").expect("message");
        assert_eq!(msg, "invalid password");
    }

    #[test]
    fn parse_login_check_version() {
        let xml = "<response><ok uid=\"1\" sessionid=\"2\" token=\"3\" accts_version=\"123\" url_encryption=\"1\" url_logging=\"1\"/></response>";
        let mut session = Session::default();
        let version = parse_login_check(xml, &mut session).expect("version");
        assert_eq!(version, 123);
        assert_eq!(session.uid, "1");
        assert!(session.url_encryption_enabled);
        assert!(session.url_logging_enabled);
    }

    #[test]
    fn parse_ok_session_feature_flags() {
        let xml = "<response><ok uid=\"1\" sessionid=\"2\" token=\"3\" url_encryption=\"1\" url_logging=\"0\"/></response>";
        let session = parse_ok_session(xml).expect("session");
        assert!(session.url_encryption_enabled);
        assert!(!session.url_logging_enabled);
    }

    #[test]
    fn parse_ok_session_returns_none_for_missing_required_attributes() {
        assert!(parse_ok_session("<response><ok uid=\"1\" sessionid=\"2\"/></response>").is_none());
    }

    #[test]
    fn parse_lastpass_api_ok_status() {
        assert_eq!(
            parse_lastpass_api_ok("<lastpass rc=\"OK\"><ok/></lastpass>"),
            Some(true)
        );
        assert_eq!(
            parse_lastpass_api_ok("<lastpass rc=\"FAIL\"><error/></lastpass>"),
            Some(false)
        );
        assert_eq!(parse_lastpass_api_ok("<response/>"), None);
    }

    #[test]
    fn parse_error_cause_returns_none_for_malformed_xml() {
        assert_eq!(parse_error_cause("<response><error", "message"), None);
    }

    #[test]
    fn parse_pwchange_success() {
        let xml = "<lastpass rc=\"OK\"><data token=\"tok\" sukey0=\"0102\" suuid0=\"77\" xml=\"rid&#10;priv&#10;old-a&#10;old-b&#9;0&#10;endmarker&#10;\"/></lastpass>";
        let info = parse_pwchange(xml).expect("pwchange");
        assert_eq!(info.reencrypt_id, "rid");
        assert_eq!(info.token, "tok");
        assert_eq!(info.privkey_encrypted, "priv");
        assert_eq!(info.fields.len(), 2);
        assert!(!info.fields[0].optional);
        assert!(info.fields[1].optional);
        assert_eq!(info.su_keys.len(), 1);
        assert_eq!(info.su_keys[0].uid, "77");
        assert_eq!(info.su_keys[0].sharing_key, vec![1, 2]);
    }

    #[test]
    fn parse_pwchange_rejects_incorrect_password() {
        let err = parse_pwchange("<lastpass rc=\"FAIL\"><error/></lastpass>").expect_err("fail");
        assert_eq!(err, PwChangeParseError::IncorrectPassword);
    }

    #[test]
    fn parse_pwchange_rejects_invalid_payload() {
        let err = parse_pwchange("<lastpass rc=\"OK\"><data token=\"tok\" xml=\"rid\"/></lastpass>")
            .expect_err("invalid");
        assert_eq!(err, PwChangeParseError::Invalid);
    }

    #[test]
    fn parse_pwchange_stops_su_key_scan_on_invalid_hex() {
        let xml = "<lastpass rc=\"OK\"><data token=\"tok\" sukey0=\"not-hex\" suuid0=\"77\" sukey1=\"0102\" suuid1=\"88\" xml=\"rid&#10;priv&#10;endmarker&#10;\"/></lastpass>";
        let info = parse_pwchange(xml).expect("pwchange");
        assert!(info.su_keys.is_empty());
    }
}
