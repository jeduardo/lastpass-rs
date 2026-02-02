#![forbid(unsafe_code)]

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::session::Session;

pub fn parse_ok_session(xml: &str) -> Option<Session> {
    let attrs = parse_ok_attributes(xml)?;
    let uid = attrs.get("uid")?.to_string();
    let session_id = attrs.get("sessionid")?.to_string();
    let token = attrs.get("token")?.to_string();

    let mut session = Session {
        uid,
        session_id,
        token,
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

    attrs
        .get("accts_version")
        .and_then(|val| val.parse::<u64>().ok())
}

pub fn parse_error_cause(xml: &str, attr_name: &str) -> Option<String> {
    parse_error_attribute(xml, attr_name)
}

fn parse_ok_attributes(xml: &str) -> Option<std::collections::HashMap<String, String>> {
    parse_element_attributes(xml, b"ok")
}

fn parse_error_attribute(xml: &str, attr_name: &str) -> Option<String> {
    let attrs = parse_element_attributes(xml, b"error")?;
    attrs.get(attr_name).cloned()
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
                    for attr in e.attributes().with_checks(false) {
                        if let Ok(attr) = attr {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            if let Ok(value) = attr.unescape_value() {
                                attrs.insert(key, value.to_string());
                            }
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
        let xml = "<response><ok uid=\"1\" sessionid=\"2\" token=\"3\" accts_version=\"123\"/></response>";
        let mut session = Session::default();
        let version = parse_login_check(xml, &mut session).expect("version");
        assert_eq!(version, 123);
        assert_eq!(session.uid, "1");
    }
}
