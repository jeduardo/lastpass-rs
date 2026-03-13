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
    let xml = "<response><ok uid=\"1\" sessionid=\"2\" token=\"3\" privatekey=\"enc\"/></response>";
    let session = parse_ok_session(xml).expect("session");
    assert_eq!(session.private_key_enc.as_deref(), Some("enc"));
}

#[test]
fn parse_ok_session_returns_none_for_invalid_empty_values() {
    let xml = "<response><ok uid=\"\" sessionid=\"2\" token=\"3\"/></response>";
    assert!(parse_ok_session(xml).is_none());
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
fn parse_ok_session_returns_none_without_ok_element() {
    assert!(parse_ok_session("<response><error/></response>").is_none());
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
fn parse_lastpass_api_ok_returns_none_for_malformed_xml() {
    assert_eq!(parse_lastpass_api_ok("<lastpass"), None);
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
fn parse_pwchange_rejects_payload_without_private_key_line() {
    let err =
        parse_pwchange("<lastpass rc=\"OK\"><data token=\"tok\" xml=\"rid&#10;\"/></lastpass>")
            .expect_err("invalid");
    assert_eq!(err, PwChangeParseError::Invalid);
}

#[test]
fn parse_pwchange_stops_su_key_scan_on_invalid_hex() {
    let xml = "<lastpass rc=\"OK\"><data token=\"tok\" sukey0=\"not-hex\" suuid0=\"77\" sukey1=\"0102\" suuid1=\"88\" xml=\"rid&#10;priv&#10;endmarker&#10;\"/></lastpass>";
    let info = parse_pwchange(xml).expect("pwchange");
    assert!(info.su_keys.is_empty());
}

#[test]
fn parse_pwchange_stops_su_key_scan_when_uid_is_missing() {
    let xml = "<lastpass rc=\"OK\"><data token=\"tok\" sukey0=\"0102\" xml=\"rid&#10;priv&#10;endmarker&#10;\"/></lastpass>";
    let info = parse_pwchange(xml).expect("pwchange");
    assert!(info.su_keys.is_empty());
}
