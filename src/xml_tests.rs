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

#[test]
fn parse_share_getinfo_reads_users_and_groups() {
    let xml = "<xmlresponse><users>\
        <item>\
            <realname>Jane Doe</realname>\
            <uid>10</uid>\
            <group>0</group>\
            <username>jane@example.com</username>\
            <permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions>\
            <outsideenterprise>1</outsideenterprise>\
            <accepted>0</accepted>\
        </item>\
        <item>\
            <uid>11</uid>\
            <group>1</group>\
            <username>team-group</username>\
            <permissions><readonly>0</readonly><canadminister>1</canadminister><give>1</give></permissions>\
            <outsideenterprise>0</outsideenterprise>\
            <accepted>1</accepted>\
        </item>\
    </users></xmlresponse>";
    let users = parse_share_getinfo(xml).expect("share info");
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].realname.as_deref(), Some("Jane Doe"));
    assert_eq!(users[0].username, "jane@example.com");
    assert!(users[0].read_only);
    assert!(users[0].hide_passwords);
    assert!(users[0].outside_enterprise);
    assert!(!users[0].accepted);
    assert!(users[1].is_group);
    assert!(users[1].admin);
    assert!(!users[1].hide_passwords);
}

#[test]
fn parse_share_getinfo_rejects_invalid_xml() {
    let err = parse_share_getinfo("<xmlresponse><bad/></xmlresponse>").expect_err("invalid");
    assert_eq!(err, ShareParseError::Invalid);
}

#[test]
fn parse_share_getinfo_supports_attributes_cdata_and_unknown_children() {
    let xml = "<xmlresponse source=\"share\"><users kind=\"all\">\
        <item extra=\"1\">\
            <username><![CDATA[jane@example.com]]></username>\
            <uid>10</uid>\
            <group>0</group>\
            <sharingkey>0102</sharingkey>\
            <permissions mode=\"rw\"><readonly>0</readonly><canadminister>1</canadminister><give>1</give><ignored>1</ignored></permissions>\
            <ignored>value</ignored>\
        </item>\
    </users></xmlresponse>";
    let users = parse_share_getinfo(xml).expect("share info");
    assert_eq!(users[0].username, "jane@example.com");
    assert_eq!(users[0].sharing_key, vec![1, 2]);
    assert!(users[0].admin);
    assert!(!users[0].hide_passwords);
}

#[test]
fn parse_share_getinfo_rejects_wrong_root_name() {
    let err = parse_share_getinfo("<response><users/></response>").expect_err("invalid");
    assert_eq!(err, ShareParseError::Invalid);
}

#[test]
fn parse_share_getpubkeys_reads_entries_until_uid_is_missing() {
    let xml = "<xmlresponse>\
        <success>1</success>\
        <pubkey0>0102</pubkey0><uid0>10</uid0><username0>jane@example.com</username0>\
        <uid1>11</uid1><username1>group-team</username1><cgid1>cg-11</cgid1>\
    </xmlresponse>";
    let users = parse_share_getpubkeys(xml).expect("pubkeys");
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].uid, "10");
    assert_eq!(users[0].sharing_key, vec![1, 2]);
    assert_eq!(users[1].cgid.as_deref(), Some("cg-11"));
    assert!(users[1].sharing_key.is_empty());
}

#[test]
fn parse_share_getpubkeys_rejects_wrong_root_name() {
    let err = parse_share_getpubkeys("<response/>").expect_err("invalid");
    assert_eq!(err, ShareParseError::Invalid);
}

#[test]
fn parse_share_getpubkey_returns_first_entry_and_reports_missing() {
    let xml = "<xmlresponse><uid0>10</uid0><username0>jane@example.com</username0></xmlresponse>";
    let user = parse_share_getpubkey(xml).expect("pubkey");
    assert_eq!(user.uid, "10");

    let err = parse_share_getpubkey("<xmlresponse><success>0</success></xmlresponse>")
        .expect_err("missing");
    assert_eq!(err, ShareParseError::NotFound);
}

#[test]
fn parse_share_get_limits_reads_whitelist_and_aids() {
    let xml = "<xmlresponse><hidebydefault>1</hidebydefault><aids><aid0>100</aid0><aid1>200</aid1></aids></xmlresponse>";
    let limit = parse_share_get_limits(xml).expect("limits");
    assert!(limit.whitelist);
    assert_eq!(limit.aids.len(), 2);
    assert_eq!(limit.aids[0].aid, "100");
    assert_eq!(limit.aids[1].aid, "200");
}

#[test]
fn parse_share_get_limits_rejects_invalid_xml() {
    let err = parse_share_get_limits("<response/>").expect_err("invalid");
    assert_eq!(err, ShareParseError::Invalid);
}

#[test]
fn parse_share_get_limits_ignores_unknown_children() {
    let xml = "<xmlresponse><hidebydefault>0</hidebydefault><ignored>1</ignored><aids><aid0>100</aid0><blank></blank></aids></xmlresponse>";
    let limit = parse_share_get_limits(xml).expect("limits");
    assert!(!limit.whitelist);
    assert_eq!(limit.aids.len(), 1);
    assert_eq!(limit.aids[0].aid, "100");
}

#[test]
fn parse_xml_tree_covers_cdata_and_invalid_root_shapes() {
    let root =
        parse_xml_tree("<xmlresponse attr=\"1\"><value><![CDATA[text]]></value></xmlresponse>")
            .expect("tree");
    assert_eq!(root.name, "xmlresponse");
    assert_eq!(child_text(&root, "value").as_deref(), Some("text"));

    assert!(parse_xml_tree("<xmlresponse/><second/>").is_none());
    assert!(parse_xml_tree("<xmlresponse></xmlresponse><second></second>").is_none());
    assert!(parse_xml_tree("<xmlresponse><node attr=\"&bogus;\"/></xmlresponse>").is_none());
    assert!(parse_xml_tree("<xmlresponse><node attr=\"&bogus;\"></node></xmlresponse>").is_none());
    assert!(parse_xml_tree("ignored<xmlresponse/>").is_some());
    assert!(parse_xml_tree("<![CDATA[text]]><xmlresponse/>").is_some());
    assert!(parse_xml_tree("<xmlresponse><node></xmlresponse>").is_none());
}

#[test]
fn parse_xml_tree_ignores_general_entity_references() {
    let xml = "<!DOCTYPE xmlresponse [<!ENTITY foo \"bar\">]><xmlresponse>&foo;</xmlresponse>";
    let root = parse_xml_tree(xml).expect("tree");
    assert_eq!(root.name, "xmlresponse");
}
