#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use super::argparse::{parse_bool_arg_string, parse_sync_option};
use super::data::{SyncMode, load_blob};
use crate::agent::agent_get_decryption_key;
use crate::blob::{Account, Blob, Share as BlobShare};
use crate::crypto::{aes_encrypt_lastpass, base64_lastpass_encode, rsa_encrypt_oaep};
use crate::error::LpassError;
use crate::http::HttpClient;
use crate::kdf::KDF_HASH_LEN;
use crate::session::{Session, session_load};
use crate::share::{ShareLimit, ShareLimitAid, ShareUser};
use crate::terminal::{self, BOLD, FG_GREEN, FG_RED, FG_YELLOW, NO_BOLD, RESET};
use crate::xml::{
    parse_share_get_limits, parse_share_getinfo, parse_share_getpubkey, parse_share_getpubkeys,
};

const SHARE_USERLS_USAGE: &str = "usage: share userls SHARE";
const SHARE_USERADD_USAGE: &str = "usage: share useradd [--read-only=[true|false] --hidden=[true|false] --admin=[true|false] SHARE USERNAME";
const SHARE_USERMOD_USAGE: &str = "usage: share usermod [--read-only=[true|false] --hidden=[true|false] --admin=[true|false] SHARE USERNAME";
const SHARE_USERDEL_USAGE: &str = "usage: share userdel SHARE USERNAME";
const SHARE_CREATE_USAGE: &str = "usage: share create SHARE";
const SHARE_LIMIT_USAGE: &str =
    "usage: share limit [--deny|--allow] [--add|--rm|--clear] SHARE USERNAME [sites]";
const SHARE_RM_USAGE: &str = "usage: share rm SHARE";

#[derive(Debug, Clone)]
struct CommandState {
    session: Session,
    blob: Blob,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Subcommand {
    UserLs,
    UserAdd,
    UserMod,
    UserDel,
    Create,
    Limit,
    Rm,
}

impl Subcommand {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "userls" => Some(Self::UserLs),
            "useradd" => Some(Self::UserAdd),
            "usermod" => Some(Self::UserMod),
            "userdel" => Some(Self::UserDel),
            "create" => Some(Self::Create),
            "limit" => Some(Self::Limit),
            "rm" => Some(Self::Rm),
            _ => None,
        }
    }

    fn usage(self) -> &'static str {
        match self {
            Self::UserLs => SHARE_USERLS_USAGE,
            Self::UserAdd => SHARE_USERADD_USAGE,
            Self::UserMod => SHARE_USERMOD_USAGE,
            Self::UserDel => SHARE_USERDEL_USAGE,
            Self::Create => SHARE_CREATE_USAGE,
            Self::Limit => SHARE_LIMIT_USAGE,
            Self::Rm => SHARE_RM_USAGE,
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedArgs {
    sync_mode: SyncMode,
    subcommand: Subcommand,
    share_name: String,
    tail: Vec<String>,
    read_only: bool,
    set_read_only: bool,
    admin: bool,
    set_admin: bool,
    hide_passwords: bool,
    set_hide_passwords: bool,
    specified_limit_type: bool,
    whitelist: bool,
    add: bool,
    remove: bool,
    clear: bool,
}

#[derive(Debug)]
enum CommandError {
    Help,
    Message(String),
}

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(CommandError::Help) => {
            eprint!("{}", terminal::render_stderr(&share_help_text()));
            1
        }
        Err(CommandError::Message(err)) => {
            eprintln!("{}", terminal::cli_failure_text(&err));
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<i32, CommandError> {
    let mut ask = ask_yes_no;
    run_with_client_result(args, HttpClient::from_env(), &load_command_state, &mut ask)
}

fn run_with_client_result(
    args: &[String],
    client_result: crate::error::Result<HttpClient>,
    load_state: &dyn Fn(SyncMode) -> Result<CommandState, String>,
    ask: &mut dyn FnMut(bool, &str) -> Result<bool, String>,
) -> Result<i32, CommandError> {
    let client = client_result.map_err(|err| CommandError::Message(err.to_string()))?;
    run_inner_with(args, &client, load_state, ask)
}

fn run_inner_with(
    args: &[String],
    client: &HttpClient,
    load_state: &dyn Fn(SyncMode) -> Result<CommandState, String>,
    ask: &mut dyn FnMut(bool, &str) -> Result<bool, String>,
) -> Result<i32, CommandError> {
    let parsed = parse_args(args)?;
    let state = load_state(parsed.sync_mode).map_err(CommandError::Message)?;
    let share = if parsed.subcommand == Subcommand::Create {
        None
    } else {
        Some(
            find_unique_share(&state.blob.shares, &parsed.share_name).ok_or_else(|| {
                CommandError::Message(format!("Share {} not found.", parsed.share_name))
            })?,
        )
    };

    match parsed.subcommand {
        Subcommand::UserLs => {
            let share = share.expect("share required");
            if !parsed.tail.is_empty() {
                return Err(CommandError::Message(parsed.subcommand.usage().to_string()));
            }
            let users = share_getinfo_with_client(client, &state.session, &share.id)
                .map_err(CommandError::Message)?;
            print_share_users(&users);
        }
        Subcommand::UserAdd => {
            let share = share.expect("share required");
            if parsed.tail.len() != 1 {
                return Err(CommandError::Message(parsed.subcommand.usage().to_string()));
            }
            let user = ShareUser {
                username: parsed.tail[0].clone(),
                read_only: parsed.read_only,
                hide_passwords: parsed.hide_passwords,
                admin: parsed.admin,
                ..ShareUser::default()
            };
            share_user_add_with_client(client, &state.session, share, &user)
                .map_err(CommandError::Message)?;
        }
        Subcommand::UserMod => {
            let share = share.expect("share required");
            if parsed.tail.len() != 1 {
                return Err(CommandError::Message(parsed.subcommand.usage().to_string()));
            }
            let mut user = get_user_from_share(client, &state.session, share, &parsed.tail[0])
                .map_err(CommandError::Message)?;
            if parsed.set_read_only {
                user.read_only = parsed.read_only;
            }
            if parsed.set_hide_passwords {
                user.hide_passwords = parsed.hide_passwords;
            }
            if parsed.set_admin {
                user.admin = parsed.admin;
            }
            share_user_mod_with_client(client, &state.session, share, &user)
                .map_err(CommandError::Message)?;
        }
        Subcommand::UserDel => {
            let share = share.expect("share required");
            if parsed.tail.len() != 1 {
                return Err(CommandError::Message(parsed.subcommand.usage().to_string()));
            }
            let user = get_user_from_share(client, &state.session, share, &parsed.tail[0])
                .map_err(CommandError::Message)?;
            share_user_del_with_client(client, &state.session, share, &user)
                .map_err(CommandError::Message)?;
        }
        Subcommand::Create => {
            if !parsed.tail.is_empty() {
                return Err(CommandError::Message(parsed.subcommand.usage().to_string()));
            }
            share_create_with_client(client, &state.session, &parsed.share_name)
                .map_err(|_| CommandError::Message("No permission to create share".to_string()))?;
            let prepend_share = !parsed.share_name.starts_with("Shared-");
            println!(
                "{}",
                terminal::render_stdout(&format!(
                    "Folder {}{} created.",
                    if prepend_share { "Shared-" } else { "" },
                    parsed.share_name
                ))
            );
        }
        Subcommand::Rm => {
            let share = share.expect("share required");
            if !parsed.tail.is_empty() {
                return Err(CommandError::Message(parsed.subcommand.usage().to_string()));
            }
            share_delete_with_client(client, &state.session, share)
                .map_err(CommandError::Message)?;
        }
        Subcommand::Limit => {
            let share = share.expect("share required");
            run_limit_impl(&parsed, &state, client, share, ask).map_err(CommandError::Message)?;
        }
    }

    Ok(0)
}

fn run_limit_impl(
    parsed: &ParsedArgs,
    state: &CommandState,
    client: &HttpClient,
    share: &BlobShare,
    ask: &mut dyn FnMut(bool, &str) -> Result<bool, String>,
) -> Result<(), String> {
    if parsed.tail.is_empty() {
        return Err(parsed.subcommand.usage().to_string());
    }

    let user = get_user_from_share(client, &state.session, share, &parsed.tail[0])?;
    let mut limit = share_get_limits_with_client(client, &state.session, share, &user)?;
    let requested_sites = &parsed.tail[1..];
    let whitelist = if parsed.specified_limit_type {
        parsed.whitelist
    } else {
        limit.whitelist
    };

    let changed_list_type = whitelist != limit.whitelist && !limit.aids.is_empty();
    if requested_sites.is_empty() && !changed_list_type {
        print_share_limits(&state.blob, share, &limit);
        return Ok(());
    }

    if changed_list_type {
        let prompt = format!(
            "Supplied limit type ({}) doesn't match existing list ({}).\nContinue and switch?",
            if whitelist {
                "default deny"
            } else {
                "default allow"
            },
            if limit.whitelist {
                "default deny"
            } else {
                "default allow"
            }
        );
        if !ask(false, &prompt)? {
            return Err("Aborted.".to_string());
        }
    }

    let matches = find_matching_accounts_for_share(&state.blob.accounts, share, requested_sites);
    if parsed.clear {
        limit.aids.clear();
    }

    for account in matches {
        let in_list = limit.aids.iter().any(|aid| aid.aid == account.id);
        if (!in_list && parsed.add) || parsed.clear {
            limit.aids.push(ShareLimitAid {
                aid: account.id.clone(),
            });
        } else if in_list && parsed.remove {
            limit.aids.retain(|aid| aid.aid != account.id);
        }
    }

    limit.whitelist = whitelist;
    dedupe_limit_aids(&mut limit);

    share_set_limits_with_client(client, &state.session, share, &user, &limit)?;
    print_share_limits(&state.blob, share, &limit);
    Ok(())
}

fn parse_args(args: &[String]) -> Result<ParsedArgs, CommandError> {
    let mut sync_mode = SyncMode::Auto;
    let mut read_only = true;
    let mut set_read_only = false;
    let mut admin = false;
    let mut set_admin = false;
    let mut hide_passwords = true;
    let mut set_hide_passwords = false;
    let mut specified_limit_type = false;
    let mut whitelist = false;
    let mut add = true;
    let mut remove = false;
    let mut clear = false;
    let mut invalid = false;
    let mut positionals = Vec::new();

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match parse_sync_option(arg, &mut iter, SHARE_RM_USAGE) {
            Ok(Some(mode)) => {
                sync_mode = mode;
                continue;
            }
            Ok(None) => {}
            Err(_) => {
                invalid = true;
                break;
            }
        }
        if arg == "--color" {
            let Some(value) = iter.next() else {
                invalid = true;
                break;
            };
            let Some(mode) = terminal::parse_color_mode(value) else {
                invalid = true;
                break;
            };
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let Some(mode) = terminal::parse_color_mode(value) else {
                invalid = true;
                break;
            };
            terminal::set_color_mode(mode);
            continue;
        }
        if arg == "--read-only" {
            let Some(value) = iter.next() else {
                invalid = true;
                break;
            };
            read_only = parse_bool_arg_string(Some(value));
            set_read_only = true;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--read-only=") {
            read_only = parse_bool_arg_string(Some(value));
            set_read_only = true;
            continue;
        }
        if arg == "--hidden" {
            let Some(value) = iter.next() else {
                invalid = true;
                break;
            };
            hide_passwords = parse_bool_arg_string(Some(value));
            set_hide_passwords = true;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--hidden=") {
            hide_passwords = parse_bool_arg_string(Some(value));
            set_hide_passwords = true;
            continue;
        }
        if arg == "--admin" {
            let Some(value) = iter.next() else {
                invalid = true;
                break;
            };
            admin = parse_bool_arg_string(Some(value));
            set_admin = true;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--admin=") {
            admin = parse_bool_arg_string(Some(value));
            set_admin = true;
            continue;
        }
        if arg == "--deny" {
            whitelist = false;
            specified_limit_type = true;
            continue;
        }
        if arg == "--allow" {
            whitelist = true;
            specified_limit_type = true;
            continue;
        }
        if arg == "--add" {
            add = true;
            remove = false;
            clear = false;
            continue;
        }
        if arg == "--rm" {
            remove = true;
            add = false;
            clear = false;
            continue;
        }
        if arg == "--clear" {
            clear = true;
            add = false;
            remove = false;
            continue;
        }
        if arg.starts_with('-') {
            invalid = true;
            continue;
        }
        positionals.push(arg.clone());
    }

    if positionals.is_empty() {
        return Err(CommandError::Help);
    }

    let Some(subcommand) = Subcommand::parse(&positionals[0]) else {
        return Err(CommandError::Help);
    };
    if invalid || positionals.len() < 2 {
        return Err(CommandError::Message(subcommand.usage().to_string()));
    }

    Ok(ParsedArgs {
        sync_mode,
        subcommand,
        share_name: positionals[1].clone(),
        tail: positionals[2..].to_vec(),
        read_only,
        set_read_only,
        admin,
        set_admin,
        hide_passwords,
        set_hide_passwords,
        specified_limit_type,
        whitelist,
        add,
        remove,
        clear,
    })
}

fn load_command_state(sync_mode: SyncMode) -> Result<CommandState, String> {
    let blob = load_blob(sync_mode).map_err(|err| err.to_string())?;
    let key = agent_get_decryption_key().map_err(map_decryption_key_error)?;
    let session = session_load(&key)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| {
            "Could not find session. Perhaps you need to login with `lpass login`.".to_string()
        })?;
    Ok(CommandState { session, blob })
}

fn share_getinfo_with_client(
    client: &HttpClient,
    session: &Session,
    share_id: &str,
) -> Result<Vec<ShareUser>, String> {
    let response = client
        .post_lastpass(
            None,
            "share.php",
            Some(session),
            &[
                ("sharejs", "1"),
                ("getinfo", "1"),
                ("id", share_id),
                ("xmlr", "1"),
            ],
        )
        .map_err(|err| err.to_string())?;
    if response.status >= 400 {
        return Err("share getinfo failed".to_string());
    }
    parse_share_getinfo(&response.body).map_err(|err| err.to_string())
}

fn share_getpubkeys_with_client(
    client: &HttpClient,
    session: &Session,
    username: &str,
) -> Result<Vec<ShareUser>, String> {
    let uid = format!("{{\"{username}\":{{}}}}");
    let response = client
        .post_lastpass(
            None,
            "share.php",
            Some(session),
            &[
                ("token", &session.token),
                ("getpubkey", "1"),
                ("uid", &uid),
                ("xmlr", "1"),
            ],
        )
        .map_err(|err| err.to_string())?;
    if response.status >= 400 {
        return Err("share getpubkey failed".to_string());
    }
    parse_share_getpubkeys(&response.body).map_err(|err| err.to_string())
}

fn share_getpubkey_with_client(
    client: &HttpClient,
    session: &Session,
    uid: &str,
) -> Result<ShareUser, String> {
    let uid_param = format!("{{\"{uid}\":{{}}}}");
    let response = client
        .post_lastpass(
            None,
            "share.php",
            Some(session),
            &[
                ("token", &session.token),
                ("getpubkey", "1"),
                ("uid", &uid_param),
                ("xmlr", "1"),
            ],
        )
        .map_err(|err| err.to_string())?;
    if response.status >= 400 {
        return Err("share getpubkey failed".to_string());
    }
    parse_share_getpubkey(&response.body).map_err(|err| err.to_string())
}

fn share_user_add_with_client(
    client: &HttpClient,
    session: &Session,
    share: &BlobShare,
    user: &ShareUser,
) -> Result<(), String> {
    let share_key = share
        .key
        .ok_or_else(|| format!("Missing share key for {}", share.name))?;
    let found_users = share_getpubkeys_with_client(client, session, &user.username)
        .map_err(|_| format!("Unable to lookup user {}.", user.username))?;
    let enc_share_name = encrypt_and_base64(share.name.as_bytes(), &share_key);
    let hex_share_key = hex::encode(share_key);

    for found in found_users {
        let mut params = vec![
            ("token".to_string(), session.token.clone()),
            ("id".to_string(), share.id.clone()),
            ("update".to_string(), "1".to_string()),
            ("add".to_string(), "1".to_string()),
            ("notify".to_string(), "1".to_string()),
            ("sharename".to_string(), enc_share_name.clone()),
            ("name".to_string(), share.name.clone()),
            ("readonly".to_string(), bool_str(user.read_only).to_string()),
            (
                "give".to_string(),
                bool_str(!user.hide_passwords).to_string(),
            ),
            (
                "canadminister".to_string(),
                bool_str(user.admin).to_string(),
            ),
            ("xmlr".to_string(), "1".to_string()),
        ];

        if found.sharing_key.is_empty() {
            params.push(("msfusername0".to_string(), found.username.clone()));
            params.push((
                "msfcgid0".to_string(),
                found.cgid.clone().unwrap_or_default(),
            ));
            params.push((
                "msfreadonly0".to_string(),
                bool_str(user.read_only).to_string(),
            ));
            params.push((
                "msfcanadminister0".to_string(),
                bool_str(user.admin).to_string(),
            ));
            params.push((
                "msfgive0".to_string(),
                bool_str(!user.hide_passwords).to_string(),
            ));
        } else {
            let encrypted_share_key =
                rsa_encrypt_oaep(&found.sharing_key, hex_share_key.as_bytes())
                    .map_err(|err| err.to_string())?;
            params.push(("username0".to_string(), found.username.clone()));
            params.push(("cgid0".to_string(), found.cgid.clone().unwrap_or_default()));
            params.push(("sharekey0".to_string(), hex::encode(encrypted_share_key)));
        }

        post_share_params(client, session, params)?;
    }

    Ok(())
}

fn share_user_mod_with_client(
    client: &HttpClient,
    session: &Session,
    share: &BlobShare,
    user: &ShareUser,
) -> Result<(), String> {
    post_share_params(
        client,
        session,
        vec![
            ("token".to_string(), session.token.clone()),
            ("id".to_string(), share.id.clone()),
            ("up".to_string(), "1".to_string()),
            ("edituser".to_string(), "1".to_string()),
            ("uid".to_string(), user.user_id()),
            (
                "readonly".to_string(),
                if user.read_only { "on" } else { "" }.to_string(),
            ),
            (
                "give".to_string(),
                if !user.hide_passwords { "on" } else { "" }.to_string(),
            ),
            (
                "canadminister".to_string(),
                if user.admin { "on" } else { "" }.to_string(),
            ),
            ("xmlr".to_string(), "1".to_string()),
        ],
    )
}

fn share_user_del_with_client(
    client: &HttpClient,
    session: &Session,
    share: &BlobShare,
    user: &ShareUser,
) -> Result<(), String> {
    post_share_params(
        client,
        session,
        vec![
            ("token".to_string(), session.token.clone()),
            ("id".to_string(), share.id.clone()),
            ("update".to_string(), "1".to_string()),
            ("delete".to_string(), "1".to_string()),
            ("uid".to_string(), user.user_id()),
            ("xmlr".to_string(), "1".to_string()),
        ],
    )
}

fn share_create_with_client(
    client: &HttpClient,
    session: &Session,
    share_name: &str,
) -> Result<(), String> {
    let owner = share_getpubkey_with_client(client, session, &session.uid)
        .map_err(|_| "Unable to get pubkey for your user".to_string())?;
    if owner.sharing_key.is_empty() {
        return Err("Unable to get pubkey for your user".to_string());
    }

    let (normalized_name, _) = normalized_share_name(share_name);
    let full_name = format!("Shared-{normalized_name}");
    let mut sf_username = format!("{}-{full_name}", owner.username);
    sf_username = sf_username.replace(' ', "_");

    let mut share_key = [0u8; KDF_HASH_LEN];
    OsRng.fill_bytes(&mut share_key);
    let hex_share_key = hex::encode(share_key);
    let mut hex_hash = multi_sha256_hex(&[&sf_username.to_ascii_lowercase(), &hex_share_key]);
    hex_hash = multi_sha256_hex(&[&hex_hash, &hex_share_key]);

    let encrypted_share_key = rsa_encrypt_oaep(&owner.sharing_key, hex_share_key.as_bytes())
        .map_err(|err| err.to_string())?;
    let enc_share_name = encrypt_and_base64(full_name.as_bytes(), &share_key);

    post_share_params(
        client,
        session,
        vec![
            ("token".to_string(), session.token.clone()),
            ("id".to_string(), "0".to_string()),
            ("update".to_string(), "1".to_string()),
            ("newusername".to_string(), sf_username),
            ("newhash".to_string(), hex_hash),
            ("sharekey".to_string(), hex::encode(encrypted_share_key)),
            ("name".to_string(), full_name),
            ("sharename".to_string(), enc_share_name),
            ("xmlr".to_string(), "1".to_string()),
        ],
    )
}

fn share_delete_with_client(
    client: &HttpClient,
    session: &Session,
    share: &BlobShare,
) -> Result<(), String> {
    post_share_params(
        client,
        session,
        vec![
            ("token".to_string(), session.token.clone()),
            ("id".to_string(), share.id.clone()),
            ("delete".to_string(), "1".to_string()),
            ("xmlr".to_string(), "1".to_string()),
        ],
    )
}

fn share_get_limits_with_client(
    client: &HttpClient,
    session: &Session,
    share: &BlobShare,
    user: &ShareUser,
) -> Result<ShareLimit, String> {
    let response = client
        .post_lastpass(
            None,
            "share.php",
            Some(session),
            &[
                ("token", &session.token),
                ("id", &share.id),
                ("limit", "1"),
                ("uid", &user.uid),
                ("xmlr", "1"),
            ],
        )
        .map_err(|err| err.to_string())?;
    if response.status >= 400 {
        return Err("share get limits failed".to_string());
    }
    parse_share_get_limits(&response.body).map_err(|err| err.to_string())
}

fn share_set_limits_with_client(
    client: &HttpClient,
    session: &Session,
    share: &BlobShare,
    user: &ShareUser,
    limit: &ShareLimit,
) -> Result<(), String> {
    let aids = limit
        .aids
        .iter()
        .map(|aid| aid.aid.as_str())
        .collect::<Vec<_>>()
        .join(",");
    post_share_params(
        client,
        session,
        vec![
            ("token".to_string(), session.token.clone()),
            ("id".to_string(), share.id.clone()),
            ("limit".to_string(), "1".to_string()),
            ("edit".to_string(), "1".to_string()),
            ("uid".to_string(), user.uid.clone()),
            ("numaids".to_string(), limit.aids.len().to_string()),
            (
                "hidebydefault".to_string(),
                bool_str(limit.whitelist).to_string(),
            ),
            ("aids".to_string(), aids),
            ("xmlr".to_string(), "1".to_string()),
        ],
    )
}

fn post_share_params(
    client: &HttpClient,
    session: &Session,
    params: Vec<(String, String)>,
) -> Result<(), String> {
    let borrowed = params
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let response = client
        .post_lastpass(None, "share.php", Some(session), &borrowed)
        .map_err(|err| err.to_string())?;
    if response.status >= 400 {
        return Err("share request failed".to_string());
    }
    Ok(())
}

fn get_user_from_share(
    client: &HttpClient,
    session: &Session,
    share: &BlobShare,
    username: &str,
) -> Result<ShareUser, String> {
    let users = share_getinfo_with_client(client, session, &share.id)
        .map_err(|_| format!("Unable to access user list for share {}", share.name))?;
    users
        .into_iter()
        .find(|user| user.username == username)
        .ok_or_else(|| format!("Unable to find user {} in the user list", username))
}

fn find_unique_share<'a>(shares: &'a [BlobShare], name: &str) -> Option<&'a BlobShare> {
    shares
        .iter()
        .find(|share| share.name.eq_ignore_ascii_case(name))
}

fn find_matching_accounts_for_share<'a>(
    accounts: &'a [Account],
    share: &BlobShare,
    selectors: &[String],
) -> Vec<&'a Account> {
    let mut remaining = accounts
        .iter()
        .filter(|account| account.share_id.as_deref() == Some(share.id.as_str()))
        .collect::<Vec<_>>();
    let mut matches = Vec::new();

    for selector in selectors {
        if selector != "0"
            && let Some(idx) = remaining
                .iter()
                .position(|account| account.id.eq_ignore_ascii_case(selector))
        {
            matches.push(remaining.remove(idx));
            continue;
        }

        let mut idx = 0usize;
        while idx < remaining.len() {
            let account = remaining[idx];
            if account.fullname == *selector || account.name == *selector {
                matches.push(remaining.remove(idx));
            } else {
                idx += 1;
            }
        }
    }

    matches
}

fn dedupe_limit_aids(limit: &mut ShareLimit) {
    let mut seen = std::collections::HashSet::new();
    limit.aids.retain(|aid| seen.insert(aid.aid.clone()));
}

fn print_share_users(users: &[ShareUser]) {
    println!(
        "{}",
        terminal::render_stdout(&format!(
            "{FG_YELLOW}{BOLD}{:<40} {:>6} {:>6} {:>6} {:>6} {:>6}{RESET}",
            "User", "RO", "Admin", "Hide", "OutEnt", "Accept"
        ))
    );

    let mut has_groups = false;
    for user in users {
        if user.is_group {
            has_groups = true;
            continue;
        }
        println!("{}", terminal::render_stdout(&format_share_user_line(user)));
    }

    if !has_groups {
        return;
    }

    println!(
        "{}",
        terminal::render_stdout(&format!(
            "{FG_YELLOW}{BOLD}{:<40} {:>6} {:>6} {:>6} {:>6} {:>6}{RESET}",
            "Group", "RO", "Admin", "Hide", "OutEnt", "Accept"
        ))
    );
    for user in users {
        if user.is_group {
            println!(
                "{}",
                terminal::render_stdout(&format_share_group_line(user))
            );
        }
    }
}

fn format_share_user_line(user: &ShareUser) -> String {
    let name = if let Some(realname) = user.realname.as_deref() {
        format!("{realname} <{}>", user.username)
    } else {
        user.username.clone()
    };
    format_share_columns(&name, user)
}

fn format_share_group_line(user: &ShareUser) -> String {
    format_share_columns(&user.username, user)
}

fn format_share_columns(name: &str, user: &ShareUser) -> String {
    format!(
        "{:<40} {:>6} {:>6} {:>6} {:>6} {:>6}",
        name,
        checkmark(user.read_only),
        checkmark(user.admin),
        checkmark(user.hide_passwords),
        checkmark(user.outside_enterprise),
        checkmark(user.accepted),
    )
}

fn print_share_limits(blob: &Blob, share: &BlobShare, limit: &ShareLimit) {
    println!(
        "{}",
        terminal::render_stdout(&format!(
            "{FG_YELLOW}{BOLD}{:<60} {:>7} {:>5}{RESET}",
            "Site", "Unavail", "Avail"
        ))
    );

    for account in &blob.accounts {
        if account.share_id.as_deref() != Some(share.id.as_str()) {
            continue;
        }

        let in_list = limit.aids.iter().any(|aid| aid.aid == account.id);
        let avail = (in_list && limit.whitelist) || (!in_list && !limit.whitelist);
        let sitename = format!("{BOLD}{:.30}{NO_BOLD} [id: {}]", account.name, account.id);
        println!(
            "{}",
            terminal::render_stdout(&format!(
                "{FG_GREEN}{:<66}{RESET} {:>8} {:>5}",
                sitename,
                checkmark(!avail),
                checkmark(avail)
            ))
        );
    }
}

fn ask_yes_no(default_yes: bool, prompt: &str) -> Result<bool, String> {
    let mut reader = io::stdin().lock();
    let mut writer = io::stderr().lock();
    ask_yes_no_with_io(&mut reader, &mut writer, default_yes, prompt)
}

fn ask_yes_no_with_io(
    reader: &mut dyn BufRead,
    writer: &mut dyn Write,
    default_yes: bool,
    prompt: &str,
) -> Result<bool, String> {
    let options_colored = if default_yes {
        format!("{BOLD}Y{RESET}/n")
    } else {
        format!("y/{BOLD}N{RESET}")
    };
    loop {
        writer
            .write_all(
                terminal::render_stderr(&format!(
                    "{FG_YELLOW}{prompt}{RESET} [{options_colored}] "
                ))
                .as_bytes(),
            )
            .map_err(|err| err.to_string())?;
        writer.flush().map_err(|err| err.to_string())?;

        let mut response = String::new();
        let read = reader
            .read_line(&mut response)
            .map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("aborted response.".to_string());
        }

        if let Some(value) = parse_yes_no_response(response.trim(), default_yes) {
            return Ok(value);
        }

        let msg = format!("{FG_RED}{BOLD}Error{RESET}: Response not understood.");
        writer
            .write_all(format!("{}\n", terminal::render_stderr(&msg)).as_bytes())
            .map_err(|err| err.to_string())?;
        writer.flush().map_err(|err| err.to_string())?;
    }
}

fn parse_yes_no_response(input: &str, default_yes: bool) -> Option<bool> {
    if input.is_empty() {
        return Some(default_yes);
    }
    let first = input.as_bytes()[0] as char;
    if first.eq_ignore_ascii_case(&'y') {
        Some(true)
    } else if first.eq_ignore_ascii_case(&'n') {
        Some(false)
    } else {
        None
    }
}

fn share_help_text() -> String {
    let program = program_name();
    format!(
        "Usage: {program} share subcommand sharename ...\n  {program} share userls SHARE\n  {program} share useradd [--read-only=[true|false] --hidden=[true|false] --admin=[true|false] SHARE USERNAME\n  {program} share usermod [--read-only=[true|false] --hidden=[true|false] --admin=[true|false] SHARE USERNAME\n  {program} share userdel SHARE USERNAME\n  {program} share create SHARE\n  {program} share rm SHARE\n  {program} share limit [--deny|--allow] [--add|--rm|--clear] SHARE USERNAME [sites]\n"
    )
}

fn program_name() -> String {
    program_name_from_arg(std::env::args().next())
}

fn normalized_share_name(share_name: &str) -> (&str, bool) {
    if let Some(value) = share_name.strip_prefix("Shared-") {
        (value, false)
    } else {
        (share_name, true)
    }
}

fn multi_sha256_hex(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn program_name_from_arg(path: Option<String>) -> String {
    let Some(path) = path else {
        return "lpass".to_string();
    };
    std::path::Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .unwrap_or("lpass".to_string())
}

fn encrypt_and_base64(bytes: &[u8], key: &[u8; KDF_HASH_LEN]) -> String {
    let encrypted = aes_encrypt_lastpass(bytes, key)
        .expect("AES encryption with owned padding buffer cannot fail");
    base64_lastpass_encode(&encrypted)
}

fn bool_str(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn checkmark(value: bool) -> &'static str {
    if value { "x" } else { "_" }
}

fn map_decryption_key_error(err: LpassError) -> String {
    match err {
        LpassError::Crypto("missing iterations")
        | LpassError::Crypto("missing username")
        | LpassError::Crypto("missing verify") => {
            "Could not find decryption key. Perhaps you need to login with `lpass login`."
                .to_string()
        }
        _ => err.to_string(),
    }
}

#[cfg(test)]
#[path = "share_tests.rs"]
mod tests;
