use super::*;
use crate::blob::{Account, Blob, Share as BlobShare};
use crate::config::{ConfigEnv, config_write_buffer, config_write_encrypted_string, set_test_env};
use crate::http::HttpClient;
use crate::terminal::{self, ColorMode};
use crate::xml::ShareParseError;
use tempfile::TempDir;

fn run_inner_with<L, A>(
    args: &[String],
    client: &HttpClient,
    load_state: L,
    ask: A,
) -> Result<i32, CommandError>
where
    L: Fn(SyncMode) -> Result<CommandState, String>,
    A: FnMut(bool, &str) -> Result<bool, String>,
{
    let mut ask = ask;
    super::run_inner_with(args, client, &load_state, &mut ask)
}

fn run_with_client_result<L, A>(
    args: &[String],
    client_result: crate::error::Result<HttpClient>,
    load_state: L,
    ask: A,
) -> Result<i32, CommandError>
where
    L: Fn(SyncMode) -> Result<CommandState, String>,
    A: FnMut(bool, &str) -> Result<bool, String>,
{
    let mut ask = ask;
    super::run_with_client_result(args, client_result, &load_state, &mut ask)
}

fn ask_yes_no_with_reader_writer<R: std::io::BufRead, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    default_yes: bool,
    prompt: &str,
) -> Result<bool, String> {
    super::ask_yes_no_with_io(reader, writer, default_yes, prompt)
}

fn session() -> Session {
    Session {
        uid: "57747756".to_string(),
        session_id: "sess".to_string(),
        token: "tok".to_string(),
        url_encryption_enabled: false,
        url_logging_enabled: false,
        server: None,
        private_key: None,
        private_key_enc: None,
    }
}

fn share(name: &str, id: &str, readonly: bool, key: Option<[u8; KDF_HASH_LEN]>) -> BlobShare {
    BlobShare {
        id: id.to_string(),
        name: name.to_string(),
        readonly,
        key,
    }
}

fn shared_account(id: &str, name: &str, fullname: &str, share_id: &str) -> Account {
    Account {
        id: id.to_string(),
        share_name: Some("Team".to_string()),
        share_id: Some(share_id.to_string()),
        share_readonly: false,
        name: name.to_string(),
        name_encrypted: None,
        group: "apps".to_string(),
        group_encrypted: None,
        fullname: fullname.to_string(),
        url: String::new(),
        url_encrypted: None,
        username: String::new(),
        username_encrypted: None,
        password: String::new(),
        password_encrypted: None,
        note: String::new(),
        note_encrypted: None,
        last_touch: String::new(),
        last_modified_gmt: String::new(),
        fav: false,
        pwprotect: false,
        attachkey: String::new(),
        attachkey_encrypted: None,
        attachpresent: false,
        fields: Vec::new(),
    }
}

fn state_with_share() -> CommandState {
    CommandState {
        session: session(),
        blob: Blob {
            version: 1,
            local_version: false,
            shares: vec![share("Team", "77", false, Some([7u8; KDF_HASH_LEN]))],
            accounts: vec![
                shared_account("100", "alpha", "Team/alpha", "77"),
                shared_account("200", "beta", "Team/beta", "77"),
                shared_account("201", "beta", "Team/platform/beta", "77"),
                shared_account("300", "outside", "Other/outside", "88"),
                shared_account("0", "0", "Team/0", "77"),
            ],
            attachments: Vec::new(),
        },
    }
}

fn unreachable_session() -> Session {
    let mut session = session();
    session.server = Some("127.0.0.1:1".to_string());
    session
}

fn write_mock_blob(blob: &Blob) {
    let json = serde_json::to_vec(blob).expect("blob json");
    config_write_buffer("blob", &json).expect("blob write");
}

fn write_plaintext_key(key: &[u8; KDF_HASH_LEN]) {
    config_write_buffer("plaintext_key", key).expect("plaintext key");
    config_write_encrypted_string("verify", "`lpass` was written by LastPass.\n", key)
        .expect("verify");
}

#[test]
fn parse_args_handles_help_usage_and_flags() {
    assert!(matches!(parse_args(&[]), Err(CommandError::Help)));
    assert!(matches!(
        parse_args(&["unknown".to_string(), "Team".to_string()]),
        Err(CommandError::Help)
    ));

    let err = match parse_args(&["userls".to_string()]) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, SHARE_USERLS_USAGE);

    let err = match parse_args(&[
        "--bogus".to_string(),
        "useradd".to_string(),
        "Team".to_string(),
        "user".to_string(),
    ]) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, SHARE_USERADD_USAGE);

    let parsed = parse_args(&[
        "--sync=no".to_string(),
        "--color=never".to_string(),
        "--read-only=false".to_string(),
        "--hidden=true".to_string(),
        "--admin".to_string(),
        "false".to_string(),
        "usermod".to_string(),
        "Team".to_string(),
        "user@example.com".to_string(),
    ])
    .expect("parse");
    assert_eq!(parsed.sync_mode, SyncMode::No);
    assert_eq!(parsed.subcommand, Subcommand::UserMod);
    assert!(!parsed.read_only);
    assert!(parsed.set_read_only);
    assert!(parsed.hide_passwords);
    assert!(parsed.set_hide_passwords);
    assert!(!parsed.admin);
    assert!(parsed.set_admin);

    let parsed = parse_args(&[
        "--allow".to_string(),
        "--rm".to_string(),
        "limit".to_string(),
        "Team".to_string(),
        "user@example.com".to_string(),
        "Team/alpha".to_string(),
    ])
    .expect("parse");
    assert!(parsed.specified_limit_type);
    assert!(parsed.whitelist);
    assert!(!parsed.add);
    assert!(parsed.remove);
    assert!(!parsed.clear);
}

#[test]
fn parse_args_covers_remaining_option_forms() {
    let parsed = parse_args(&[
        "--color".to_string(),
        "always".to_string(),
        "--read-only".to_string(),
        "false".to_string(),
        "--hidden".to_string(),
        "false".to_string(),
        "--admin=true".to_string(),
        "--deny".to_string(),
        "--clear".to_string(),
        "limit".to_string(),
        "Team".to_string(),
        "user@example.com".to_string(),
        "Team/alpha".to_string(),
    ])
    .expect("parse");
    assert_eq!(parsed.subcommand, Subcommand::Limit);
    assert!(parsed.specified_limit_type);
    assert!(!parsed.whitelist);
    assert!(!parsed.read_only);
    assert!(parsed.set_read_only);
    assert!(!parsed.hide_passwords);
    assert!(parsed.set_hide_passwords);
    assert!(parsed.admin);
    assert!(parsed.set_admin);
    assert!(!parsed.add);
    assert!(!parsed.remove);
    assert!(parsed.clear);

    for (args, usage) in [
        (
            vec![
                "userls".to_string(),
                "Team".to_string(),
                "--sync=invalid".to_string(),
            ],
            SHARE_USERLS_USAGE,
        ),
        (
            vec!["userls".to_string(), "Team".to_string(), "--color".to_string()],
            SHARE_USERLS_USAGE,
        ),
        (
            vec![
                "userls".to_string(),
                "Team".to_string(),
                "--color".to_string(),
                "bogus".to_string(),
            ],
            SHARE_USERLS_USAGE,
        ),
        (
            vec![
                "userls".to_string(),
                "Team".to_string(),
                "--color=bogus".to_string(),
            ],
            SHARE_USERLS_USAGE,
        ),
        (
            vec![
                "useradd".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
                "--read-only".to_string(),
            ],
            SHARE_USERADD_USAGE,
        ),
        (
            vec![
                "useradd".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
                "--hidden".to_string(),
            ],
            SHARE_USERADD_USAGE,
        ),
        (
            vec![
                "usermod".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
                "--admin".to_string(),
            ],
            SHARE_USERMOD_USAGE,
        ),
    ] {
        let err = match parse_args(&args) {
            Err(CommandError::Message(err)) => err,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(err, usage);
    }

    terminal::set_color_mode(ColorMode::Auto);
}

#[test]
fn find_unique_share_is_case_insensitive() {
    let shares = vec![share("Team Shared", "77", false, None)];
    assert_eq!(
        find_unique_share(&shares, "team shared").map(|item| item.id.as_str()),
        Some("77")
    );
    assert!(find_unique_share(&shares, "missing").is_none());
}

#[test]
fn find_matching_accounts_for_share_prefers_id_and_dedupes_matches() {
    let state = state_with_share();
    let share = &state.blob.shares[0];
    let matches = find_matching_accounts_for_share(
        &state.blob.accounts,
        share,
        &[
            "200".to_string(),
            "beta".to_string(),
            "beta".to_string(),
            "0".to_string(),
        ],
    );
    let ids = matches.iter().map(|account| account.id.as_str()).collect::<Vec<_>>();
    assert_eq!(ids, vec!["200", "201", "0"]);
}

#[test]
fn dedupe_limit_aids_keeps_first_occurrence() {
    let mut limit = ShareLimit {
        whitelist: false,
        aids: vec![
            ShareLimitAid {
                aid: "100".to_string(),
            },
            ShareLimitAid {
                aid: "100".to_string(),
            },
            ShareLimitAid {
                aid: "200".to_string(),
            },
        ],
    };
    dedupe_limit_aids(&mut limit);
    assert_eq!(limit.aids.len(), 2);
    assert_eq!(limit.aids[0].aid, "100");
    assert_eq!(limit.aids[1].aid, "200");
}

#[test]
fn formatting_helpers_match_upstream_markers() {
    let user = ShareUser {
        username: "jane@example.com".to_string(),
        realname: Some("Jane Doe".to_string()),
        read_only: true,
        hide_passwords: true,
        admin: false,
        outside_enterprise: true,
        accepted: false,
        ..ShareUser::default()
    };
    let line = format_share_user_line(&user);
    assert!(line.contains("Jane Doe <jane@example.com>"));
    assert!(line.contains(" x"));
    assert!(line.contains(" _"));

    let group = ShareUser {
        uid: "11".to_string(),
        username: "group-team".to_string(),
        is_group: true,
        admin: true,
        ..ShareUser::default()
    };
    let group_line = format_share_group_line(&group);
    assert!(group_line.contains("group-team"));
    assert!(group_line.contains("x"));
    assert_eq!(group.user_id(), "group:11");

    let fallback = format_share_user_line(&ShareUser {
        username: "solo@example.com".to_string(),
        ..ShareUser::default()
    });
    assert!(fallback.contains("solo@example.com"));
}

#[test]
fn ask_yes_no_with_reader_writer_handles_defaults_retry_and_eof() {
    let mut reader = std::io::Cursor::new(b"\n".to_vec());
    let mut output = Vec::new();
    assert!(ask_yes_no_with_reader_writer(&mut reader, &mut output, true, "Prompt").expect("yes"));

    let mut reader = std::io::Cursor::new(b"maybe\nn\n".to_vec());
    let mut output = Vec::new();
    assert!(
        !ask_yes_no_with_reader_writer(&mut reader, &mut output, false, "Prompt").expect("no")
    );
    let rendered = String::from_utf8_lossy(&output);
    assert!(rendered.contains("Response not understood"));

    let mut reader = std::io::Cursor::new(Vec::<u8>::new());
    let mut output = Vec::new();
    let err = ask_yes_no_with_reader_writer(&mut reader, &mut output, false, "Prompt")
        .expect_err("eof");
    assert!(err.contains("aborted response"));
}

#[test]
fn share_endpoint_helpers_follow_mock_transport_paths() {
    let client = HttpClient::mock();
    let session = session();
    let share = share("Team", "77", false, Some([7u8; KDF_HASH_LEN]));

    let users = share_getinfo_with_client(&client, &session, &share.id).expect("users");
    assert_eq!(users[0].username, "user@example.com");

    let pubkeys = share_getpubkeys_with_client(&client, &session, "new@example.com").expect("keys");
    assert_eq!(pubkeys[0].username, "new@example.com");
    assert!(!pubkeys[0].sharing_key.is_empty());

    let owner = share_getpubkey_with_client(&client, &session, &session.uid).expect("owner");
    assert_eq!(owner.username, "user@example.com");

    share_user_add_with_client(
        &client,
        &session,
        &share,
        &ShareUser {
            username: "new@example.com".to_string(),
            read_only: true,
            hide_passwords: true,
            admin: false,
            ..ShareUser::default()
        },
    )
    .expect("user add");

    share_user_add_with_client(
        &client,
        &session,
        &share,
        &ShareUser {
            username: "group-team".to_string(),
            read_only: false,
            hide_passwords: false,
            admin: true,
            ..ShareUser::default()
        },
    )
    .expect("group add");

    let mut found = get_user_from_share(&client, &session, &share, "user@example.com").expect("found");
    found.admin = true;
    share_user_mod_with_client(&client, &session, &share, &found).expect("mod");
    share_user_del_with_client(&client, &session, &share, &found).expect("del");

    let limit = share_get_limits_with_client(&client, &session, &share, &found).expect("limits");
    assert_eq!(limit.aids.len(), 1);
    share_set_limits_with_client(&client, &session, &share, &found, &limit).expect("set limits");

    share_create_with_client(&client, &session, "Shared-Blue Team").expect("create");
    share_delete_with_client(&client, &session, &share).expect("delete");
}

#[test]
fn share_endpoint_helpers_map_invalid_xml_payloads() {
    let client = HttpClient::mock_with_overrides(&[
        ("share.php", 200, "<not-xml-response/>"),
        ("share.php", 200, "<not-xml-response/>"),
        ("share.php", 200, "<not-xml-response/>"),
        ("share.php", 200, "<not-xml-response/>"),
    ]);
    let session = session();
    let share = share("Team", "77", false, Some([7u8; KDF_HASH_LEN]));

    assert_eq!(
        share_getinfo_with_client(&client, &session, &share.id).expect_err("invalid getinfo xml"),
        "invalid share xml"
    );
    assert_eq!(
        share_getpubkeys_with_client(&client, &session, "user@example.com")
            .expect_err("invalid getpubkeys xml"),
        "invalid share xml"
    );
    assert_eq!(
        share_getpubkey_with_client(&client, &session, &session.uid).expect_err("invalid getpubkey xml"),
        "invalid share xml"
    );

    let user = ShareUser {
        uid: "57747756".to_string(),
        ..ShareUser::default()
    };
    assert_eq!(
        share_get_limits_with_client(&client, &session, &share, &user).expect_err("invalid limits xml"),
        "invalid share xml"
    );
}

#[test]
fn run_inner_with_handles_userls_create_rm_and_missing_share() {
    let client = HttpClient::mock();
    let state = state_with_share();

    assert_eq!(
        run_inner_with(
            &["userls".to_string(), "Team".to_string()],
            &client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("userls"),
        0
    );

    assert_eq!(
        run_inner_with(
            &["create".to_string(), "Shared-Team".to_string()],
            &client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("create"),
        0
    );

    assert_eq!(
        run_inner_with(
            &["rm".to_string(), "Team".to_string()],
            &client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("rm"),
        0
    );

    let err = match run_inner_with(
        &["userls".to_string(), "Missing".to_string()],
        &client,
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "Share Missing not found.");
}

#[test]
fn run_inner_with_covers_usermod_userdel_and_usage_errors() {
    let client = HttpClient::mock();
    let state = state_with_share();

    assert_eq!(
        run_inner_with(
            &[
                "--read-only=false".to_string(),
                "--hidden=true".to_string(),
                "--admin=false".to_string(),
                "usermod".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
            ],
            &client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("usermod"),
        0
    );

    assert_eq!(
        run_inner_with(
            &[
                "userdel".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
            ],
            &client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("userdel"),
        0
    );

    for (args, usage) in [
        (
            vec!["userls".to_string(), "Team".to_string(), "extra".to_string()],
            SHARE_USERLS_USAGE,
        ),
        (
            vec!["useradd".to_string(), "Team".to_string()],
            SHARE_USERADD_USAGE,
        ),
        (
            vec!["usermod".to_string(), "Team".to_string()],
            SHARE_USERMOD_USAGE,
        ),
        (
            vec!["userdel".to_string(), "Team".to_string()],
            SHARE_USERDEL_USAGE,
        ),
        (
            vec!["create".to_string(), "Team".to_string(), "extra".to_string()],
            SHARE_CREATE_USAGE,
        ),
        (vec!["rm".to_string(), "Team".to_string(), "extra".to_string()], SHARE_RM_USAGE),
        (vec!["limit".to_string(), "Team".to_string()], SHARE_LIMIT_USAGE),
    ] {
        let err = match run_inner_with(&args, &client, |_| Ok(state.clone()), |_, _| Ok(true)) {
            Err(CommandError::Message(err)) => err,
            other => panic!("unexpected result: {other:?}"),
        };
        assert_eq!(err, usage);
    }

    let create_client = HttpClient::mock_with_overrides(&[(
        "share.php",
        500,
        "<xmlresponse><error message=\"denied\"/></xmlresponse>",
    )]);
    let err = match run_inner_with(
        &["create".to_string(), "Denied".to_string()],
        &create_client,
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "No permission to create share");
}

#[test]
fn run_inner_with_limit_covers_show_abort_and_update_paths() {
    let state = state_with_share();

    let show_client = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0></aids></xmlresponse>",
        ),
    ]);
    assert_eq!(
        run_inner_with(
            &["limit".to_string(), "Team".to_string(), "user@example.com".to_string()],
            &show_client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("show limits"),
        0
    );

    let abort_client = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0></aids></xmlresponse>",
        ),
    ]);
    let err = match run_inner_with(
        &[
            "limit".to_string(),
            "--allow".to_string(),
            "Team".to_string(),
            "user@example.com".to_string(),
        ],
        &abort_client,
        |_| Ok(state.clone()),
        |_, _| Ok(false),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "Aborted.");

    let update_client = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0></aids></xmlresponse>",
        ),
        ("share.php", 200, "<xmlresponse><success>1</success></xmlresponse>"),
    ]);
    assert_eq!(
        run_inner_with(
            &[
                "limit".to_string(),
                "--allow".to_string(),
                "--add".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
                "Team/beta".to_string(),
            ],
            &update_client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("update limits"),
        0
    );
}

#[test]
fn run_inner_with_limit_covers_deny_clear_and_remove_paths() {
    let state = state_with_share();

    let deny_client = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>1</hidebydefault><aids><aid0>100</aid0></aids></xmlresponse>",
        ),
        ("share.php", 200, "<xmlresponse><success>1</success></xmlresponse>"),
    ]);
    assert_eq!(
        run_inner_with(
            &[
                "limit".to_string(),
                "--deny".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
            ],
            &deny_client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("deny"),
        0
    );

    let clear_client = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0><aid1>200</aid1></aids></xmlresponse>",
        ),
        ("share.php", 200, "<xmlresponse><success>1</success></xmlresponse>"),
    ]);
    assert_eq!(
        run_inner_with(
            &[
                "limit".to_string(),
                "--clear".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
                "Team/beta".to_string(),
            ],
            &clear_client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("clear"),
        0
    );

    let remove_client = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0><aid1>200</aid1></aids></xmlresponse>",
        ),
        ("share.php", 200, "<xmlresponse><success>1</success></xmlresponse>"),
    ]);
    assert_eq!(
        run_inner_with(
            &[
                "limit".to_string(),
                "--rm".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
                "Team/alpha".to_string(),
            ],
            &remove_client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("remove"),
        0
    );
}

#[test]
fn helper_text_and_hash_functions_cover_edge_cases() {
    assert!(share_help_text().contains("share subcommand sharename ..."));
    assert_eq!(normalized_share_name("Shared-Team"), ("Team", false));
    assert_eq!(normalized_share_name("Team"), ("Team", true));
    assert_eq!(checkmark(true), "x");
    assert_eq!(checkmark(false), "_");
    assert_eq!(bool_str(true), "1");
    assert_eq!(bool_str(false), "0");
    assert_eq!(
        multi_sha256_hex(&["abc", "def"]),
        "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
    );
    let encoded = encrypt_and_base64(b"value", &[3u8; KDF_HASH_LEN]);
    assert!(!encoded.is_empty());
    assert_eq!(program_name_from_arg(None), "lpass");
    assert_eq!(
        program_name_from_arg(Some("/usr/local/bin/lpass".to_string())),
        "lpass"
    );
}

#[test]
fn helper_and_endpoint_error_paths_are_covered() {
    let session = session();
    let share = share("Team", "77", false, Some([7u8; KDF_HASH_LEN]));

    let getinfo_client =
        HttpClient::mock_with_overrides(&[("share.php", 500, "<xmlresponse/>")]);
    assert_eq!(
        share_getinfo_with_client(&getinfo_client, &session, &share.id).expect_err("getinfo"),
        "share getinfo failed"
    );

    let getpubkeys_client =
        HttpClient::mock_with_overrides(&[("share.php", 500, "<xmlresponse/>")]);
    assert_eq!(
        share_getpubkeys_with_client(&getpubkeys_client, &session, "user@example.com")
            .expect_err("getpubkeys"),
        "share getpubkey failed"
    );

    let getpubkey_client =
        HttpClient::mock_with_overrides(&[("share.php", 500, "<xmlresponse/>")]);
    assert_eq!(
        share_getpubkey_with_client(&getpubkey_client, &session, "57747756")
            .expect_err("getpubkey"),
        "share getpubkey failed"
    );

    let getlimits_client =
        HttpClient::mock_with_overrides(&[("share.php", 500, "<xmlresponse/>")]);
    assert_eq!(
        share_get_limits_with_client(
            &getlimits_client,
            &session,
            &share,
            &ShareUser {
                uid: "10".to_string(),
                username: "user@example.com".to_string(),
                ..ShareUser::default()
            },
        )
        .expect_err("limits"),
        "share get limits failed"
    );

    let request_client =
        HttpClient::mock_with_overrides(&[("share.php", 500, "<xmlresponse/>")]);
    assert_eq!(
        post_share_params(
            &request_client,
            &session,
            vec![("token".to_string(), session.token.clone())],
        )
        .expect_err("request"),
        "share request failed"
    );

    let owner_without_key = HttpClient::mock_with_overrides(&[(
        "share.php",
        200,
        "<xmlresponse><success>1</success><uid0>57747756</uid0><username0>user@example.com</username0></xmlresponse>",
    )]);
    assert_eq!(
        share_create_with_client(&owner_without_key, &session, "Shared-Team")
            .expect_err("missing owner pubkey"),
        "Unable to get pubkey for your user"
    );

    print_share_users(&[ShareUser {
        username: "solo@example.com".to_string(),
        read_only: true,
        ..ShareUser::default()
    }]);

    assert_eq!(
        map_decryption_key_error(LpassError::Crypto("missing verify")),
        "Could not find decryption key. Perhaps you need to login with `lpass login`."
    );
    assert_eq!(
        map_decryption_key_error(LpassError::Crypto("other")),
        "crypto error: other"
    );
    assert_eq!(format!("{}", ShareParseError::Invalid), "invalid share xml");
    assert_eq!(format!("{}", ShareParseError::NotFound), "missing share record");
}

#[test]
fn load_command_state_reports_missing_session() {
    let _override_guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");

    let temp = TempDir::new().expect("tempdir");
    let _config_guard = set_test_env(ConfigEnv {
        lpass_home: Some(temp.path().to_path_buf()),
        ..ConfigEnv::default()
    });
    write_mock_blob(&state_with_share().blob);
    write_plaintext_key(&[7u8; KDF_HASH_LEN]);

    let err = load_command_state(SyncMode::No).expect_err("missing session");
    assert_eq!(
        err,
        "Could not find session. Perhaps you need to login with `lpass login`."
    );
}

#[test]
fn run_inner_and_helpers_cover_remaining_error_conversions() {
    let client = HttpClient::mock();
    let state = state_with_share();

    let err = match run_inner_with(
        &["userls".to_string(), "Team".to_string()],
        &client,
        |_| Err("load failed".to_string()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "load failed");

    let real_client = HttpClient::real().expect("real client");
    let unreachable_state = CommandState {
        session: unreachable_session(),
        ..state.clone()
    };
    let err = match run_inner_with(
        &["userls".to_string(), "Team".to_string()],
        &real_client,
        |_| Ok(unreachable_state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert!(err.contains("IO error while http post"));

    let err = match run_inner_with(
        &["useradd".to_string(), "Team".to_string(), "user@example.com".to_string()],
        &client,
        |_| {
            let mut state = state.clone();
            state.blob.shares[0].key = None;
            Ok(state)
        },
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "Missing share key for Team");

    let err = match run_inner_with(
        &["usermod".to_string(), "Team".to_string(), "missing@example.com".to_string()],
        &client,
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "Unable to find user missing@example.com in the user list");

    assert_eq!(
        run_inner_with(
            &[
                "usermod".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
            ],
            &client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("usermod defaults"),
        0
    );

    let usermod_post_error = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        ("share.php", 500, "<xmlresponse/>"),
    ]);
    let err = match run_inner_with(
        &[
            "usermod".to_string(),
            "Team".to_string(),
            "user@example.com".to_string(),
        ],
        &usermod_post_error,
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "share request failed");

    let userdel_post_error = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        ("share.php", 500, "<xmlresponse/>"),
    ]);
    let err = match run_inner_with(
        &[
            "userdel".to_string(),
            "Team".to_string(),
            "user@example.com".to_string(),
        ],
        &userdel_post_error,
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "share request failed");

    assert_eq!(
        run_inner_with(
            &["create".to_string(), "Team".to_string()],
            &client,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("create team"),
        0
    );

    let rm_post_error = HttpClient::mock_with_overrides(&[("share.php", 500, "<xmlresponse/>")]);
    let err = match run_inner_with(
        &["rm".to_string(), "Team".to_string()],
        &rm_post_error,
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "share request failed");

    let err = match run_with_client_result(
        &["userls".to_string(), "Team".to_string()],
        Err(LpassError::Crypto("factory failed")),
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "crypto error: factory failed");
}

#[test]
fn run_limit_covers_remaining_error_and_noop_paths() {
    let state = state_with_share();

    let err = match run_inner_with(
        &[
            "limit".to_string(),
            "Team".to_string(),
            "missing@example.com".to_string(),
        ],
        &HttpClient::mock(),
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "Unable to find user missing@example.com in the user list");

    let limits_error = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        ("share.php", 500, "<xmlresponse/>"),
    ]);
    let err = match run_inner_with(
        &[
            "limit".to_string(),
            "Team".to_string(),
            "user@example.com".to_string(),
            "Team/alpha".to_string(),
        ],
        &limits_error,
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "share get limits failed");

    let ask_error = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0></aids></xmlresponse>",
        ),
    ]);
    let err = match run_inner_with(
        &[
            "limit".to_string(),
            "--allow".to_string(),
            "Team".to_string(),
            "user@example.com".to_string(),
        ],
        &ask_error,
        |_| Ok(state.clone()),
        |_, _| Err("prompt failed".to_string()),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "prompt failed");

    let noop_add = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0></aids></xmlresponse>",
        ),
        ("share.php", 200, "<xmlresponse><success>1</success></xmlresponse>"),
    ]);
    assert_eq!(
        run_inner_with(
            &[
                "limit".to_string(),
                "Team".to_string(),
                "user@example.com".to_string(),
                "Team/alpha".to_string(),
            ],
            &noop_add,
            |_| Ok(state.clone()),
            |_, _| Ok(true),
        )
        .expect("noop add"),
        0
    );

    let set_error = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><users><item><uid>10</uid><group>0</group><username>user@example.com</username><permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions></item></users></xmlresponse>",
        ),
        (
            "share.php",
            200,
            "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0></aids></xmlresponse>",
        ),
        ("share.php", 500, "<xmlresponse/>"),
    ]);
    let err = match run_inner_with(
        &[
            "limit".to_string(),
            "--add".to_string(),
            "Team".to_string(),
            "user@example.com".to_string(),
            "Team/beta".to_string(),
        ],
        &set_error,
        |_| Ok(state.clone()),
        |_, _| Ok(true),
    ) {
        Err(CommandError::Message(err)) => err,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(err, "share request failed");
}

#[test]
fn share_transport_and_prompt_helpers_cover_remaining_error_paths() {
    let real_client = HttpClient::real().expect("real client");
    let bad_session = unreachable_session();
    let share = share("Team", "77", false, Some([7u8; KDF_HASH_LEN]));
    let user = ShareUser {
        uid: "10".to_string(),
        username: "user@example.com".to_string(),
        hide_passwords: true,
        ..ShareUser::default()
    };

    assert!(share_getinfo_with_client(&real_client, &bad_session, &share.id)
        .expect_err("getinfo")
        .contains("IO error while http post"));
    assert!(share_getpubkeys_with_client(&real_client, &bad_session, &user.username)
        .expect_err("getpubkeys")
        .contains("IO error while http post"));
    assert!(share_getpubkey_with_client(&real_client, &bad_session, &bad_session.uid)
        .expect_err("getpubkey")
        .contains("IO error while http post"));
    assert!(share_get_limits_with_client(&real_client, &bad_session, &share, &user)
        .expect_err("getlimits")
        .contains("IO error while http post"));
    assert!(post_share_params(
        &real_client,
        &bad_session,
        vec![("token".to_string(), bad_session.token.clone())],
    )
    .expect_err("post")
    .contains("IO error while http post"));
    assert!(get_user_from_share(&real_client, &bad_session, &share, &user.username)
        .expect_err("user")
        .contains("Unable to access user list for share Team"));

    assert_eq!(
        share_user_add_with_client(
            &real_client,
            &bad_session,
            &share,
            &ShareUser {
                username: "unreachable@example.com".to_string(),
                ..ShareUser::default()
            },
        )
        .expect_err("lookup error"),
        "Unable to lookup user unreachable@example.com."
    );

    let add_bad_pubkey = HttpClient::mock_with_overrides(&[(
        "share.php",
        200,
        "<xmlresponse><success>1</success><pubkey0>0102</pubkey0><uid0>10</uid0><username0>bad@example.com</username0></xmlresponse>",
    )]);
    assert!(share_user_add_with_client(
        &add_bad_pubkey,
        &session(),
        &share,
        &ShareUser {
            username: "bad@example.com".to_string(),
            ..ShareUser::default()
        },
    )
    .expect_err("bad pubkey")
    .contains("crypto error"));

    let add_post_error = HttpClient::mock_with_overrides(&[
        (
            "share.php",
            200,
            "<xmlresponse><success>1</success><pubkey0>30819f300d06092a864886f70d010101050003818d0030818902818100a1a227a8887870284bd831eb4a16dbba04c1092ce93e821b1523dcac45c84e34ea07139bee3a21b703fe78a3765995944c6646f4820341486a0f1c4472050110099b28b410d89d9fe2ebc2af752e95efdbaa9393a70dd09024719ea4fbb98c4498f7feced228a29462239f955ae0d028bb0cc5a641bdedc66f67fd2b5b4514d50203010001</pubkey0><uid0>10</uid0><username0>bad@example.com</username0></xmlresponse>",
        ),
        ("share.php", 500, "<xmlresponse/>"),
    ]);
    assert_eq!(
        share_user_add_with_client(
            &add_post_error,
            &session(),
            &share,
            &ShareUser {
                username: "bad@example.com".to_string(),
                ..ShareUser::default()
            },
        )
        .expect_err("add post"),
        "share request failed"
    );

    let create_bad_pubkey = HttpClient::mock_with_overrides(&[(
        "share.php",
        200,
        "<xmlresponse><success>1</success><pubkey0>0102</pubkey0><uid0>57747756</uid0><username0>user@example.com</username0></xmlresponse>",
    )]);
    assert!(share_create_with_client(&create_bad_pubkey, &session(), "Shared-Team")
        .expect_err("create bad pubkey")
        .contains("crypto error"));

    share_user_mod_with_client(
        &HttpClient::mock(),
        &session(),
        &share,
        &ShareUser {
            uid: "10".to_string(),
            username: "user@example.com".to_string(),
            read_only: false,
            hide_passwords: false,
            admin: false,
            ..ShareUser::default()
        },
    )
    .expect("mod");

    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("write failed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FailingFlushWriter;
    impl std::io::Write for FailingFlushWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush failed"))
        }
    }

    struct FailingReader;
    impl std::io::Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("read failed"))
        }
    }
    impl std::io::BufRead for FailingReader {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            Err(std::io::Error::other("fill buf failed"))
        }
        fn consume(&mut self, _: usize) {}
    }

    struct FailingRetryWriter {
        writes: usize,
    }
    impl std::io::Write for FailingRetryWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if self.writes > 1 {
                return Err(std::io::Error::other("retry write failed"));
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FailingRetryFlushWriter {
        flushes: usize,
    }
    impl std::io::Write for FailingRetryFlushWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            if self.flushes > 1 {
                return Err(std::io::Error::other("retry flush failed"));
            }
            Ok(())
        }
    }

    let mut reader = std::io::Cursor::new(b"y\n".to_vec());
    let err = ask_yes_no_with_reader_writer(&mut reader, &mut FailingWriter, true, "Prompt")
        .expect_err("write error");
    assert!(err.contains("write failed"));

    let mut reader = std::io::Cursor::new(b"y\n".to_vec());
    let err =
        ask_yes_no_with_reader_writer(&mut reader, &mut FailingFlushWriter, true, "Prompt")
            .expect_err("flush error");
    assert!(err.contains("flush failed"));

    let err = ask_yes_no_with_reader_writer(&mut FailingReader, &mut Vec::new(), true, "Prompt")
        .expect_err("read error");
    assert!(err.contains("fill buf failed"));

    let mut reader = std::io::Cursor::new(b"maybe\n".to_vec());
    let err = ask_yes_no_with_reader_writer(
        &mut reader,
        &mut FailingRetryWriter { writes: 0 },
        true,
        "Prompt",
    )
    .expect_err("retry write error");
    assert!(err.contains("retry write failed"));

    let mut reader = std::io::Cursor::new(b"maybe\n".to_vec());
    let err = ask_yes_no_with_reader_writer(
        &mut reader,
        &mut FailingRetryFlushWriter { flushes: 0 },
        true,
        "Prompt",
    )
    .expect_err("retry flush error");
    assert!(err.contains("retry flush failed"));
}

#[test]
fn load_command_state_maps_blob_key_and_session_read_errors() {
    let temp = TempDir::new().expect("tempdir");
    let _config_guard = set_test_env(ConfigEnv {
        lpass_home: Some(temp.path().to_path_buf()),
        ..ConfigEnv::default()
    });

    {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let err = load_command_state(SyncMode::No).expect_err("blob error");
        assert!(err.contains("Could not find decryption key"));
    }

    {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        let err = load_command_state(SyncMode::No).expect_err("key error");
        assert_eq!(
            err,
            "Could not find decryption key. Perhaps you need to login with `lpass login`."
        );
    }

    {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        write_mock_blob(&state_with_share().blob);
        write_plaintext_key(&[7u8; KDF_HASH_LEN]);
        config_write_buffer("session_uid", b"bad").expect("bad session uid");
        let err = load_command_state(SyncMode::No).expect_err("session read error");
        assert!(err.contains("IO error") || err.contains("crypto error"));
    }
}
