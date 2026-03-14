#![forbid(unsafe_code)]

use std::fmt::{self, Display};

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::share::{ShareLimit, ShareLimitAid, ShareUser};
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ShareParseError {
    Invalid,
    NotFound,
}

impl Display for ShareParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => f.write_str("invalid share xml"),
            Self::NotFound => f.write_str("missing share record"),
        }
    }
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
    Some(
        parse_element_attributes(xml, b"lastpass")?
            .get("rc")
            .map(String::as_str)
            == Some("OK"),
    )
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

pub fn parse_share_getinfo(xml: &str) -> std::result::Result<Vec<ShareUser>, ShareParseError> {
    let root = parse_xml_tree(xml).ok_or(ShareParseError::Invalid)?;
    if root.name != "xmlresponse" {
        return Err(ShareParseError::Invalid);
    }
    let users = root
        .children
        .iter()
        .find(|child| child.name == "users")
        .ok_or(ShareParseError::Invalid)?;

    Ok(users
        .children
        .iter()
        .filter(|child| child.name == "item")
        .map(parse_share_user_item)
        .collect())
}

pub fn parse_share_getpubkeys(
    xml: &str,
) -> std::result::Result<Vec<ShareUser>, ShareParseError> {
    let root = parse_xml_tree(xml).ok_or(ShareParseError::Invalid)?;
    if root.name != "xmlresponse" {
        return Err(ShareParseError::Invalid);
    }

    let mut users = Vec::new();
    for idx in 0.. {
        let uid_key = format!("uid{idx}");
        let Some(uid) = child_text(&root, &uid_key) else {
            break;
        };
        let username = child_text(&root, &format!("username{idx}")).unwrap_or_default();
        let cgid = child_text(&root, &format!("cgid{idx}")).filter(|value| !value.is_empty());
        let sharing_key = child_text(&root, &format!("pubkey{idx}"))
            .and_then(|value| hex::decode(value).ok())
            .unwrap_or_default();
        users.push(ShareUser {
            uid,
            username,
            cgid,
            sharing_key,
            ..ShareUser::default()
        });
    }

    if users.is_empty() {
        Err(ShareParseError::NotFound)
    } else {
        Ok(users)
    }
}

pub fn parse_share_getpubkey(xml: &str) -> std::result::Result<ShareUser, ShareParseError> {
    parse_share_getpubkeys(xml)?
        .into_iter()
        .next()
        .ok_or(ShareParseError::NotFound)
}

pub fn parse_share_get_limits(xml: &str) -> std::result::Result<ShareLimit, ShareParseError> {
    let root = parse_xml_tree(xml).ok_or(ShareParseError::Invalid)?;
    if root.name != "xmlresponse" {
        return Err(ShareParseError::Invalid);
    }

    let mut limit = ShareLimit::default();
    for child in &root.children {
        match child.name.as_str() {
            "hidebydefault" => {
                limit.whitelist = parse_bool_text(&child.text);
            }
            "aids" => {
                limit.aids = child
                    .children
                    .iter()
                    .filter(|item| item.name.starts_with("aid"))
                    .filter_map(|item| {
                        let aid = item.text.trim();
                        (!aid.is_empty()).then(|| ShareLimitAid {
                            aid: aid.to_string(),
                        })
                    })
                    .collect();
            }
            _ => {}
        }
    }

    Ok(limit)
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

    Ok((
        reencrypt_id.to_string(),
        privkey_encrypted.to_string(),
        fields,
    ))
}

fn split_pwchange_line(data: &str) -> Option<(&str, &str)> {
    let newline = data.find('\n')?;
    Some((&data[..newline], &data[newline + 1..]))
}

fn parse_pwchange_su_keys(attrs: &std::collections::HashMap<String, String>) -> Vec<PwChangeSuKey> {
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

#[derive(Debug, Clone, Default)]
struct XmlNode {
    name: String,
    text: String,
    children: Vec<XmlNode>,
}

fn parse_xml_tree(xml: &str) -> Option<XmlNode> {
    let mut reader = Reader::from_str(xml);
    let mut buf = Vec::new();
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root: Option<XmlNode> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let node = XmlNode {
                    name: reader
                        .decoder()
                        .decode(e.name().as_ref())
                        .ok()?
                        .into_owned(),
                    text: String::new(),
                    children: Vec::new(),
                };
                if parse_attrs(&reader, e.attributes()).is_none() {
                    return None;
                }
                stack.push(node);
            }
            Ok(Event::Empty(e)) => {
                let node = XmlNode {
                    name: reader
                        .decoder()
                        .decode(e.name().as_ref())
                        .ok()?
                        .into_owned(),
                    text: String::new(),
                    children: Vec::new(),
                };
                if parse_attrs(&reader, e.attributes()).is_none() {
                    return None;
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.is_none() {
                    root = Some(node);
                } else {
                    return None;
                }
            }
            Ok(Event::Text(e)) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(e.xml_content().ok()?.as_ref());
                }
            }
            Ok(Event::CData(e)) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(e.decode().ok()?.as_ref());
                }
            }
            Ok(Event::End(_)) => {
                let node = stack.pop()?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.is_none() {
                    root = Some(node);
                } else {
                    return None;
                }
            }
            Ok(Event::Decl(_))
            | Ok(Event::PI(_))
            | Ok(Event::DocType(_))
            | Ok(Event::Comment(_))
            | Ok(Event::GeneralRef(_)) => {}
            Ok(Event::Eof) => break,
            Err(_) => return None,
        }
        buf.clear();
    }

    if stack.is_empty() { root } else { None }
}

fn parse_attrs(
    reader: &Reader<&[u8]>,
    mut attrs: quick_xml::events::attributes::Attributes<'_>,
) -> Option<std::collections::HashMap<String, String>> {
    let mut parsed = std::collections::HashMap::new();
    for attr in attrs.with_checks(false) {
        let attr = attr.ok()?;
        let key = reader.decoder().decode(attr.key.as_ref()).ok()?.into_owned();
        let value = attr
            .decode_and_unescape_value(reader.decoder())
            .ok()?
            .into_owned();
        parsed.insert(key, value);
    }
    Some(parsed)
}

fn child_text(node: &XmlNode, name: &str) -> Option<String> {
    node.children
        .iter()
        .find(|child| child.name == name)
        .map(|child| child.text.trim().to_string())
}

fn parse_share_user_item(item: &XmlNode) -> ShareUser {
    let mut user = ShareUser::default();

    for child in &item.children {
        match child.name.as_str() {
            "realname" => {
                let value = child.text.trim();
                if !value.is_empty() {
                    user.realname = Some(value.to_string());
                }
            }
            "username" => user.username = child.text.trim().to_string(),
            "uid" => user.uid = child.text.trim().to_string(),
            "group" => user.is_group = parse_bool_text(&child.text),
            "outsideenterprise" => user.outside_enterprise = parse_bool_text(&child.text),
            "accepted" => user.accepted = parse_bool_text(&child.text),
            "sharingkey" => {
                user.sharing_key = hex::decode(child.text.trim()).unwrap_or_default();
            }
            "permissions" => parse_share_permissions(child, &mut user),
            _ => {}
        }
    }

    user
}

fn parse_share_permissions(node: &XmlNode, user: &mut ShareUser) {
    for child in &node.children {
        match child.name.as_str() {
            "canadminister" => user.admin = parse_bool_text(&child.text),
            "readonly" => user.read_only = parse_bool_text(&child.text),
            "give" => user.hide_passwords = !parse_bool_text(&child.text),
            _ => {}
        }
    }
}

fn parse_bool_text(text: &str) -> bool {
    text.trim() == "1"
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
#[path = "xml_tests.rs"]
mod tests;
