#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::agent::agent_save;
use crate::config::config_unlink;
use crate::config::{ConfigStore, config_write_buffer, config_write_string};
use crate::crypto::decrypt_private_key;
use crate::error::Result;
use crate::http::HttpClient;
use crate::kdf::{KDF_HASH_LEN, kdf_decryption_key, kdf_login_key};
use crate::password::{prompt_password, prompt_password_with_description};
use crate::session::{Session, session_save};
use crate::terminal::{self, BOLD, FG_GREEN, FG_YELLOW, RESET, UNDERLINE};
use crate::xml::{parse_error_cause, parse_ok_session};
use rand::Rng;
use zeroize::Zeroize;

#[derive(Debug, Clone, Eq, PartialEq)]
struct LoginArgs {
    trust: bool,
    plaintext_key: bool,
    force: bool,
    username: String,
}

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{}", terminal::cli_failure_text(&err));
            1
        }
    }
}

fn run_inner(args: &[String]) -> std::result::Result<i32, String> {
    let parsed = parse_login_args(args)?;

    if parsed.plaintext_key
        && !parsed.force
        && !ask_yes_no(
            false,
            "You have used the --plaintext-key option. This option will greatly reduce the security of your passwords. You are advised, instead, to use the agent, whose timeout can be disabled by setting LPASS_AGENT_TIMEOUT=0. Are you sure you would like to do this?",
        )
        .map_err(|err| err.to_string())?
    {
        return Err("Login aborted. Try again without --plaintext-key.".to_string());
    }

    let iterations = fetch_iterations(&parsed.username).map_err(|err| format!("{err}"))?;
    ensure_nonzero_iterations(iterations)?;

    let trusted_id = calculate_trust_id(parsed.trust).map_err(|err| format!("{err}"))?;
    let trust_label = if parsed.trust {
        Some(calculate_trust_label().map_err(|err| err.to_string())?)
    } else {
        None
    };

    let (mut session, key) = loop {
        let mut password = prompt_password(&parsed.username).map_err(|err| format!("{err}"))?;
        let login_hash = kdf_login_key(&parsed.username, &password, iterations)
            .map_err(|err| format!("{err}"))?;
        let key = kdf_decryption_key(&parsed.username, &password, iterations)
            .map_err(|err| format!("{err}"))?;
        password.zeroize();

        match lastpass_login(
            &parsed.username,
            &login_hash,
            iterations,
            trusted_id.as_deref(),
            trust_label.as_deref(),
        ) {
            Ok(session) => break (session, key),
            Err(message) => {
                eprintln!("Error: {message}");
                continue;
            }
        }
    };

    maybe_attach_private_key(&mut session, &key);

    session_save(&session, &key).map_err(|err| format!("{err}"))?;

    config_write_string("username", &parsed.username).map_err(|err| format!("{err}"))?;
    config_write_string("iterations", &iterations.to_string()).map_err(|err| format!("{err}"))?;

    let _ = config_unlink("plaintext_key");
    if parsed.plaintext_key {
        config_write_buffer("plaintext_key", &key).map_err(|err| format!("{err}"))?;
    }

    agent_save(&parsed.username, iterations, &key).map_err(|err| format!("{err}"))?;

    persist_blob_after_login(&session, &key)?;

    if parsed.trust {
        let _ = post_trust(&session, trusted_id.as_deref(), trust_label.as_deref());
    }

    let message = format!(
        "{FG_GREEN}{BOLD}Success{RESET}: Logged in as {UNDERLINE}{}{RESET}.",
        parsed.username
    );
    println!("{}", terminal::render_stdout(&message));
    Ok(0)
}

fn parse_login_args(args: &[String]) -> std::result::Result<LoginArgs, String> {
    let usage = "usage: login [--trust] [--plaintext-key [--force, -f]] [--color=auto|never|always] USERNAME";
    let mut trust = false;
    let mut plaintext_key = false;
    let mut force = false;
    let mut username: Option<String> = None;

    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--trust" {
            trust = true;
            continue;
        }
        if arg == "--plaintext-key" {
            plaintext_key = true;
            continue;
        }
        if arg == "--force" || arg == "-f" {
            force = true;
            continue;
        }
        if arg == "--color" {
            let value = iter.next().ok_or_else(|| usage.to_string())?;
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let mode = terminal::parse_color_mode(value).ok_or_else(|| usage.to_string())?;
            terminal::set_color_mode(mode);
            continue;
        }
        if arg.starts_with('-') {
            return Err(usage.to_string());
        }
        if username.is_some() {
            return Err(usage.to_string());
        }
        username = Some(arg.clone());
    }

    let username = username.ok_or_else(|| usage.to_string())?;
    Ok(LoginArgs {
        trust,
        plaintext_key,
        force,
        username,
    })
}

fn ensure_nonzero_iterations(iterations: u32) -> std::result::Result<(), String> {
    if iterations == 0 {
        Err("Unable to fetch iteration count.".to_string())
    } else {
        Ok(())
    }
}

fn maybe_attach_private_key(session: &mut Session, key: &[u8; KDF_HASH_LEN]) {
    if session.private_key.is_some() {
        return;
    }
    let Some(private_key_enc) = session.private_key_enc.clone() else {
        return;
    };
    if let Ok(private_key) = decrypt_private_key(&private_key_enc, key) {
        session.private_key = Some(private_key);
    }
}

fn fetch_iterations(username: &str) -> Result<u32> {
    let client = HttpClient::from_env()?;
    fetch_iterations_with_client(&client, username)
}

fn fetch_iterations_with_client(client: &HttpClient, username: &str) -> Result<u32> {
    let user_lower = username.to_ascii_lowercase();
    let response = client.post_lastpass(None, "iterations.php", None, &[("email", &user_lower)])?;
    response
        .body
        .trim()
        .parse::<u32>()
        .map_err(|_| crate::error::LpassError::Crypto("invalid iterations"))
}

fn lastpass_login(
    username: &str,
    hash: &str,
    iterations: u32,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
) -> std::result::Result<Session, String> {
    let client = HttpClient::from_env().map_err(|err| format!("{err}"))?;
    lastpass_login_with_client(&client, username, hash, iterations, trusted_id, trust_label)
        .map_err(|err| format!("{err}"))
}

#[cfg(test)]
fn lastpass_login_with_client_basic(
    client: &HttpClient,
    username: &str,
    hash: &str,
    iterations: u32,
) -> Result<Session> {
    lastpass_login_with_client(client, username, hash, iterations, None, None)
}

fn lastpass_login_with_client(
    client: &HttpClient,
    username: &str,
    hash: &str,
    iterations: u32,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
) -> Result<Session> {
    lastpass_login_with_client_and_prompt(
        client,
        username,
        hash,
        iterations,
        trusted_id,
        trust_label,
        &mut |prompt, error, description| {
            prompt_password_with_description(prompt, error, description)
        },
    )
}

#[derive(Debug, Clone)]
enum LoginResponse {
    Session(Session),
    Challenge(LoginChallenge),
    Failure(&'static str),
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct LoginChallenge {
    cause: String,
    message: Option<String>,
    server: Option<String>,
    outofband_name: Option<String>,
    capabilities: Option<String>,
    retry_id: Option<String>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct MultifactorType {
    name: &'static str,
    failure_cause: &'static str,
    post_param: &'static str,
}

#[derive(Debug)]
enum OutOfBandResult {
    Session(Session),
    Passcode(String),
}

fn lastpass_login_with_client_and_prompt<F>(
    client: &HttpClient,
    username: &str,
    hash: &str,
    iterations: u32,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
    prompt: &mut F,
) -> Result<Session>
where
    F: FnMut(&str, Option<&str>, &str) -> Result<String>,
{
    let user_lower = username.to_ascii_lowercase();
    let iterations_str = iterations.to_string();
    let mut params = vec![
        ("xml".to_string(), "2".to_string()),
        ("username".to_string(), user_lower.clone()),
        ("hash".to_string(), hash.to_string()),
        ("iterations".to_string(), iterations_str),
        ("includeprivatekeyenc".to_string(), "1".to_string()),
        ("method".to_string(), "cli".to_string()),
        ("outofbandsupported".to_string(), "1".to_string()),
    ];
    if let Some(uuid) = trusted_id {
        set_login_param(&mut params, "uuid", uuid.to_string());
    }

    let mut server = crate::http::LASTPASS_SERVER.to_string();
    let mut response = post_login_form(client, &server, &params)?;
    if let LoginResponse::Challenge(challenge) = &response
        && challenge.server.as_deref() == Some("lastpass.eu")
        && server != "lastpass.eu"
    {
        server = "lastpass.eu".to_string();
        response = post_login_form(client, &server, &params)?;
    }

    if let Some(label) = trust_label
        && !matches!(response, LoginResponse::Session(_))
    {
        set_login_param(&mut params, "trustlabel", label.to_string());
    }

    match response {
        LoginResponse::Session(session) => Ok(session),
        LoginResponse::Failure(message) => Err(crate::error::LpassError::User(message)),
        LoginResponse::Challenge(challenge) => {
            let response = if challenge.cause == "outofbandrequired" {
                match outofband_login(client, &server, &mut params, &challenge)? {
                    OutOfBandResult::Session(session) => return Ok(session),
                    OutOfBandResult::Passcode(name) => LoginChallenge {
                        outofband_name: Some(name),
                        ..challenge
                    },
                }
            } else {
                challenge
            };
            let Some(multifactor) = multifactor_type(&response.cause) else {
                let message = response
                    .message
                    .as_deref()
                    .map(filter_error_message)
                    .unwrap_or("login failed");
                return Err(crate::error::LpassError::User(message));
            };
            otp_login(
                client,
                &server,
                &mut params,
                &user_lower,
                response.outofband_name.as_deref(),
                multifactor,
                prompt,
            )
        }
    }
}

fn post_login_form(
    client: &HttpClient,
    server: &str,
    params: &[(String, String)],
) -> Result<LoginResponse> {
    let form = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let response = client.post_lastpass(Some(server), "login.php", None, &form)?;
    Ok(parse_login_response(&response.body, server))
}

fn set_login_param(params: &mut Vec<(String, String)>, name: &str, value: String) {
    if let Some((_, existing_value)) = params.iter_mut().find(|(key, _)| key == name) {
        *existing_value = value;
    } else {
        params.push((name.to_string(), value));
    }
}

fn parse_login_response(body: &str, server: &str) -> LoginResponse {
    if let Some(mut session) = parse_ok_session(body) {
        session.server = Some(server.to_string());
        return LoginResponse::Session(session);
    }

    let cause = parse_error_cause(body, "cause");
    let server_redirect = parse_error_cause(body, "server");
    if cause.is_some() || server_redirect.is_some() {
        return LoginResponse::Challenge(LoginChallenge {
            cause: cause.unwrap_or_default(),
            message: parse_error_cause(body, "message"),
            server: server_redirect,
            outofband_name: parse_error_cause(body, "outofbandname"),
            capabilities: parse_error_cause(body, "capabilities"),
            retry_id: parse_error_cause(body, "retryid"),
        });
    }

    if let Some(message) = parse_error_cause(body, "message") {
        return LoginResponse::Failure(filter_error_message(&message));
    }

    LoginResponse::Failure("login failed")
}

fn multifactor_type(cause: &str) -> Option<MultifactorType> {
    match cause {
        "googleauthrequired" => Some(MultifactorType {
            name: "Google Authenticator Code",
            failure_cause: "googleauthfailed",
            post_param: "otp",
        }),
        "otprequired" => Some(MultifactorType {
            name: "YubiKey OTP",
            failure_cause: "otpfailed",
            post_param: "otp",
        }),
        "sesameotprequired" => Some(MultifactorType {
            name: "Sesame OTP",
            failure_cause: "sesameotpfailed",
            post_param: "sesameotp",
        }),
        "outofbandrequired" => Some(MultifactorType {
            name: "Out-of-Band OTP",
            failure_cause: "multifactorresponsefailed",
            post_param: "otp",
        }),
        "microsoftauthrequired" => Some(MultifactorType {
            name: "Microsoft Authenticator Code",
            failure_cause: "microsoftauthfailed",
            post_param: "otp",
        }),
        _ => None,
    }
}

fn otp_login<F>(
    client: &HttpClient,
    server: &str,
    params: &mut Vec<(String, String)>,
    username: &str,
    outofband_name: Option<&str>,
    multifactor: MultifactorType,
    prompt: &mut F,
) -> Result<Session>
where
    F: FnMut(&str, Option<&str>, &str) -> Result<String>,
{
    let mut prompt_error: Option<String> = None;
    loop {
        let prompt_name = outofband_name.unwrap_or(multifactor.name);
        let description = format!(
            "Please enter your {prompt_name} for \
             <{username}>."
        );
        let code = prompt("Code", prompt_error.as_deref(), &description)?;
        set_login_param(params, multifactor.post_param, code);

        match post_login_form(client, server, params)? {
            LoginResponse::Session(session) => return Ok(session),
            LoginResponse::Challenge(challenge) if challenge.cause == multifactor.failure_cause => {
                prompt_error = Some("Invalid multifactor code; please try again.".to_string());
            }
            LoginResponse::Challenge(challenge) => {
                let message = challenge
                    .message
                    .as_deref()
                    .map(filter_error_message)
                    .unwrap_or("Multifactor authentication failed");
                return Err(crate::error::LpassError::User(message));
            }
            LoginResponse::Failure(message) => {
                return Err(crate::error::LpassError::User(message));
            }
        }
    }
}

fn outofband_login(
    client: &HttpClient,
    server: &str,
    params: &mut Vec<(String, String)>,
    challenge: &LoginChallenge,
) -> Result<OutOfBandResult> {
    let interrupt = challenge
        .capabilities
        .as_deref()
        .filter(|capabilities| {
            let capabilities = capabilities.split(',').collect::<Vec<_>>();
            capabilities.contains(&"outofband") && capabilities.contains(&"passcode")
        })
        .map(|_| SigintFlag::new())
        .transpose()
        .map_err(|error| crate::error::LpassError::io("registering Ctrl+C handler", error))?;

    outofband_login_with_interrupt_check(client, server, params, challenge, || {
        interrupt.as_ref().is_some_and(SigintFlag::is_interrupted)
    })
}

fn outofband_login_with_interrupt_check<F>(
    client: &HttpClient,
    server: &str,
    params: &mut Vec<(String, String)>,
    challenge: &LoginChallenge,
    mut was_interrupted: F,
) -> Result<OutOfBandResult>
where
    F: FnMut() -> bool,
{
    let Some(name) = challenge.outofband_name.as_deref() else {
        return Err(crate::error::LpassError::User(
            "Could not determine out-of-band type.",
        ));
    };
    let Some(capabilities) = challenge.capabilities.as_deref() else {
        return Err(crate::error::LpassError::User(
            "Could not determine out-of-band type.",
        ));
    };
    let capabilities = capabilities.split(',').collect::<Vec<_>>();
    let can_use_passcode = capabilities.contains(&"passcode");
    if can_use_passcode && !capabilities.contains(&"outofband") {
        return Ok(OutOfBandResult::Passcode(format!("{name} OTP")));
    }

    eprint!(
        "{}",
        terminal::render_stderr(&format!(
            "{FG_YELLOW}{BOLD}Waiting for approval of out-of-band \
             {name} login{}{RESET}...",
            if can_use_passcode {
                ", or press Ctrl+C to enter a passcode"
            } else {
                ""
            }
        ))
    );
    set_login_param(params, "outofbandrequest", "1".to_string());
    loop {
        if can_use_passcode && was_interrupted() {
            eprintln!();
            return Ok(oob_passcode_fallback(params, name));
        }
        let response = post_login_form(client, server, params);
        if can_use_passcode && was_interrupted() {
            eprintln!();
            return Ok(oob_passcode_fallback(params, name));
        }
        match response {
            Err(_) if can_use_passcode => {
                eprintln!();
                return Ok(oob_passcode_fallback(params, name));
            }
            Err(error) => {
                eprintln!();
                return Err(error);
            }
            Ok(LoginResponse::Session(session)) => {
                eprintln!();
                return Ok(OutOfBandResult::Session(session));
            }
            Ok(LoginResponse::Challenge(response)) if response.cause == "outofbandrequired" => {
                let retry_id = response.retry_id.unwrap_or_default();
                set_login_param(params, "outofbandretry", "1".to_string());
                set_login_param(params, "outofbandretryid", retry_id.clone());
                eprint!(".");
            }
            Ok(LoginResponse::Challenge(response)) => {
                eprintln!();
                let message = response
                    .message
                    .as_deref()
                    .map(filter_error_message)
                    .unwrap_or("login failed");
                return Err(crate::error::LpassError::User(message));
            }
            Ok(LoginResponse::Failure(message)) => {
                eprintln!();
                return Err(crate::error::LpassError::User(message));
            }
        }
    }
}

fn oob_passcode_fallback(params: &mut Vec<(String, String)>, name: &str) -> OutOfBandResult {
    set_login_param(params, "outofbandrequest", "0".to_string());
    set_login_param(params, "outofbandretry", "0".to_string());
    set_login_param(params, "outofbandretryid", String::new());
    OutOfBandResult::Passcode(format!("{name} OTP"))
}

struct SigintFlag {
    interrupted: Arc<AtomicBool>,
    signal_id: signal_hook::SigId,
}

impl SigintFlag {
    fn new() -> io::Result<Self> {
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal_id =
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupted))?;
        Ok(Self {
            interrupted,
            signal_id,
        })
    }

    fn is_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Relaxed)
    }
}

impl Drop for SigintFlag {
    fn drop(&mut self) {
        signal_hook::low_level::unregister(self.signal_id);
    }
}

fn filter_error_message(message: &str) -> &'static str {
    if message.contains("invalid password") {
        return "Invalid password";
    }
    if message.contains("multifactor") {
        return "Multifactor authentication failed";
    }
    "login failed"
}

fn fetch_blob(session: &Session) -> std::result::Result<Vec<u8>, String> {
    let client = HttpClient::from_env().map_err(|err| format!("{err}"))?;
    fetch_blob_with_client(&client, session)
}

fn fetch_blob_with_client(
    client: &HttpClient,
    session: &Session,
) -> std::result::Result<Vec<u8>, String> {
    let params = [
        ("mobile", "1"),
        ("requestsrc", "cli"),
        ("hasplugin", crate::version::generated_version()),
    ];
    let response = client
        .post_lastpass_bytes(None, "getaccts.php", Some(session), &params)
        .map_err(|err| format!("{err}"))?;
    ensure_non_empty_blob_response(response.body)
}

fn ensure_non_empty_blob_response(blob: Vec<u8>) -> std::result::Result<Vec<u8>, String> {
    if blob.is_empty() {
        return Err("empty blob response".to_string());
    }
    Ok(blob)
}

fn persist_blob_after_login(
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
) -> std::result::Result<(), String> {
    let store = ConfigStore::from_current();
    persist_blob_after_login_with_fetch(&store, session, key, fetch_blob)
}

fn persist_blob_after_login_with_fetch<F>(
    store: &ConfigStore,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
    fetch_blob_fn: F,
) -> std::result::Result<(), String>
where
    F: Fn(&Session) -> std::result::Result<Vec<u8>, String>,
{
    let blob = fetch_blob_fn(session)?;
    store
        .write_encrypted_buffer("blob", &blob, key)
        .map_err(|err| format!("{err}"))?;
    let _ = store.unlink("blob.json");
    Ok(())
}

fn ask_yes_no(default_yes: bool, prompt: &str) -> std::result::Result<bool, String> {
    let mut reader = io::stdin().lock();
    let mut writer = io::stderr().lock();
    ask_yes_no_with_reader_writer(&mut reader, &mut writer, default_yes, prompt)
}

fn ask_yes_no_with_reader_writer<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    default_yes: bool,
    prompt: &str,
) -> std::result::Result<bool, String> {
    let options = if default_yes { "Y/n" } else { "y/N" };
    loop {
        writer
            .write_all(terminal::render_stderr(&format!("{prompt} [{options}] ")).as_bytes())
            .map_err(|err| format!("write: {err}"))?;
        writer.flush().map_err(|err| format!("flush: {err}"))?;

        let mut response = String::new();
        let read = reader
            .read_line(&mut response)
            .map_err(|err| format!("read: {err}"))?;
        if read == 0 {
            return Err("aborted response.".to_string());
        }
        if let Some(value) = parse_yes_no_response(response.trim(), default_yes) {
            return Ok(value);
        }
        writer
            .write_all(
                format!(
                    "{}\n",
                    terminal::render_stderr(&format!(
                        "{BOLD}Error{RESET}: Response not understood."
                    ))
                )
                .as_bytes(),
            )
            .map_err(|err| format!("write: {err}"))?;
        writer.flush().map_err(|err| format!("flush: {err}"))?;
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

fn generate_trusted_id() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

fn calculate_trust_id(force: bool) -> Result<Option<String>> {
    calculate_trust_id_with_store(&ConfigStore::from_current(), force)
}

fn calculate_trust_id_with_store(store: &ConfigStore, force: bool) -> Result<Option<String>> {
    let current = store.read_string("trusted_id")?;
    if current.is_some() || !force {
        return Ok(current);
    }
    let trusted_id = generate_trusted_id();
    store.write_string("trusted_id", &trusted_id)?;
    Ok(Some(trusted_id))
}

fn calculate_trust_label() -> std::result::Result<String, String> {
    #[cfg(unix)]
    {
        let uts =
            nix::sys::utsname::uname().map_err(|_| "Failed to determine uname.".to_string())?;
        let nodename = uts.nodename().to_string_lossy();
        let sysname = uts.sysname().to_string_lossy();
        let release = uts.release().to_string_lossy();
        Ok(format!("{nodename} - {sysname} {release}"))
    }

    #[cfg(not(unix))]
    {
        let hostname = crate::lpenv::var("HOSTNAME")
            .or_else(|_| crate::lpenv::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown-host".to_string());
        let sysname = crate::lpenv::var("OS").unwrap_or_else(|_| "UnknownOS".to_string());
        let release =
            crate::lpenv::var("OS_VERSION").unwrap_or_else(|_| "unknown-release".to_string());
        Ok(format!("{hostname} - {sysname} {release}"))
    }
}

fn post_trust(
    session: &Session,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
) -> Result<()> {
    if trusted_id.is_none() || trust_label.is_none() {
        return Ok(());
    }
    let client = HttpClient::from_env()?;
    post_trust_with_client(&client, session, trusted_id, trust_label)
}

fn post_trust_with_client(
    client: &HttpClient,
    session: &Session,
    trusted_id: Option<&str>,
    trust_label: Option<&str>,
) -> Result<()> {
    let (Some(uuid), Some(label)) = (trusted_id, trust_label) else {
        return Ok(());
    };
    let _ = client.post_lastpass(
        None,
        "trust.php",
        Some(session),
        &[
            ("token", &session.token),
            ("uuid", uuid),
            ("trustlabel", label),
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigEnv;
    use crate::crypto::{aes_encrypt_lastpass, base64_lastpass_encode};
    use crate::http::HttpClient;
    use crate::kdf::{kdf_decryption_key, kdf_login_key};
    use tempfile::TempDir;

    #[test]
    fn run_inner_requires_username() {
        let err = run_inner(&[]).expect_err("missing username must fail");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn run_inner_rejects_unknown_flags() {
        let err = run_inner(&["--nope".to_string()]).expect_err("unknown flag must fail");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn run_inner_rejects_extra_positional_args() {
        let err = run_inner(&["a@example.com".to_string(), "extra".to_string()])
            .expect_err("extra positional must fail");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn run_inner_rejects_invalid_color_mode() {
        let err = run_inner(&["--color=rainbow".to_string(), "a@example.com".to_string()])
            .expect_err("invalid color mode must fail");
        assert!(err.contains("usage: login"));
    }

    #[cfg(unix)]
    #[test]
    fn run_inner_completes_trusted_plaintext_key_login_in_mock_mode() {
        use std::os::unix::fs::PermissionsExt;

        let _env_guard = crate::lpenv::begin_test_overrides();
        let home = TempDir::new().expect("temp home");
        let _config_guard = crate::config::set_test_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let askpass = home.path().join("askpass");
        std::fs::write(&askpass, "#!/bin/sh\nprintf '123456\\n'\n").expect("write askpass");
        let mut permissions = std::fs::metadata(&askpass)
            .expect("askpass metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&askpass, permissions).expect("chmod askpass");
        crate::lpenv::set_override_for_tests("LPASS_ASKPASS", askpass.to_string_lossy().as_ref());
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        crate::lpenv::set_override_for_tests("LPASS_AGENT_DISABLE", "1");

        let result = run_inner(&[
            "--trust".to_string(),
            "--plaintext-key".to_string(),
            "--force".to_string(),
            "user@example.com".to_string(),
        ])
        .expect("login succeeds");

        assert_eq!(result, 0);
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(home.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        assert_eq!(
            store
                .read_string("username")
                .expect("read username")
                .as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            store
                .read_buffer("plaintext_key")
                .expect("read key")
                .expect("plaintext key was saved")
                .len(),
            KDF_HASH_LEN
        );
        assert!(
            store
                .read_string("trusted_id")
                .expect("trusted id")
                .is_some()
        );
        let key = kdf_decryption_key("user@example.com", "123456", 1000).expect("key");
        assert!(
            store
                .read_encrypted_buffer("blob", &key)
                .expect("read blob")
                .is_some()
        );
    }

    #[test]
    fn parse_login_args_supports_space_separated_color() {
        let parsed = parse_login_args(&[
            "--color".to_string(),
            "always".to_string(),
            "user@example.com".to_string(),
        ])
        .expect("args parse");
        assert_eq!(
            parsed,
            LoginArgs {
                trust: false,
                plaintext_key: false,
                force: false,
                username: "user@example.com".to_string(),
            }
        );
        terminal::set_color_mode(terminal::ColorMode::Auto);
    }

    #[test]
    fn parse_login_args_rejects_color_without_value() {
        let err = parse_login_args(&["--color".to_string()]).expect_err("missing value");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn parse_login_args_rejects_invalid_space_separated_color() {
        let err = parse_login_args(&[
            "--color".to_string(),
            "rainbow".to_string(),
            "user@example.com".to_string(),
        ])
        .expect_err("invalid color");
        assert!(err.contains("usage: login"));
    }

    #[test]
    fn fetch_iterations_uses_mock_client() {
        let client = HttpClient::mock();
        let iterations = fetch_iterations_with_client(&client, "USER@example.com").expect("iters");
        assert_eq!(iterations, 1000);
    }

    #[test]
    fn lastpass_login_with_mock_client_supports_success_and_failure() {
        let client = HttpClient::mock();
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let session = lastpass_login_with_client_basic(&client, "USER@example.com", &hash, 1000)
            .expect("login");
        assert_eq!(session.uid, "57747756");
        assert_eq!(session.session_id, "1234");
        assert_eq!(session.token, "abcd");
        assert_eq!(
            session.server.as_deref(),
            Some(crate::http::LASTPASS_SERVER)
        );

        let err = lastpass_login_with_client_basic(&client, "user@example.com", "bad", 1000)
            .expect_err("bad login must fail");
        assert!(matches!(err, crate::error::LpassError::User(_)));
    }

    #[cfg(unix)]
    #[test]
    fn lastpass_login_submits_google_auth_code_after_challenge() {
        use std::os::unix::fs::PermissionsExt;

        let _env_guard = crate::lpenv::begin_test_overrides();
        let temp = TempDir::new().expect("tempdir");
        let askpass = temp.path().join("askpass");
        let prompt_log = temp.path().join("prompts");
        std::fs::write(
            &askpass,
            format!(
                concat!(
                    "#!/bin/sh\n",
                    "printf '%s\\n' \"$1\" >> '{}'\n",
                    "printf '123456\\n'\n",
                ),
                prompt_log.display()
            ),
        )
        .expect("write askpass");
        let mut permissions = std::fs::metadata(&askpass)
            .expect("askpass metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&askpass, permissions).expect("chmod askpass");
        crate::lpenv::set_override_for_tests("LPASS_ASKPASS", askpass.to_string_lossy().as_ref());

        let client = HttpClient::mock_with_overrides(&[(
            "login.php",
            200,
            "<response><error cause=\"googleauthrequired\"/></response>",
        )]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let session = lastpass_login_with_client_basic(&client, "user@example.com", &hash, 1000)
            .expect("login succeeds after OTP");

        assert_eq!(session.uid, "57747756");
        assert_eq!(
            std::fs::read_to_string(prompt_log).expect("prompt log"),
            "Code\n"
        );
        let login_requests = client
            .mock_requests()
            .expect("mock requests")
            .into_iter()
            .filter(|request| request.page == "login.php")
            .collect::<Vec<_>>();
        assert_eq!(login_requests.len(), 2);
        assert_eq!(
            login_requests[1].params.get("otp").map(String::as_str),
            Some("123456")
        );
    }

    #[test]
    fn lastpass_login_retries_google_auth_code_after_invalid_code() {
        let client = HttpClient::mock_with_overrides(&[
            (
                "login.php",
                200,
                "<response><error cause=\"googleauthrequired\"/></response>",
            ),
            (
                "login.php",
                200,
                "<response><error cause=\"googleauthfailed\"/></response>",
            ),
        ]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompts = Vec::new();
        let mut prompt = |name: &str, error: Option<&str>, _description: &str| {
            prompts.push((name.to_string(), error.map(str::to_string)));
            Ok("654321".to_string())
        };

        let session = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect("valid second OTP succeeds");

        assert_eq!(session.uid, "57747756");
        assert_eq!(
            prompts,
            vec![
                ("Code".to_string(), None),
                (
                    "Code".to_string(),
                    Some("Invalid multifactor code; please try again.".to_string(),),
                ),
            ]
        );
        let requests = client.mock_requests().expect("mock requests");
        let otp_requests = requests
            .iter()
            .filter(|request| request.page == "login.php")
            .collect::<Vec<_>>();
        assert_eq!(otp_requests.len(), 3);
        assert_eq!(
            otp_requests[1].params.get("otp").map(String::as_str),
            Some("654321")
        );
        assert_eq!(
            otp_requests[2].params.get("otp").map(String::as_str),
            Some("654321")
        );
    }

    #[test]
    fn lastpass_login_polls_out_of_band_approval() {
        let client = HttpClient::mock_with_overrides(&[
            (
                "login.php",
                200,
                concat!(
                    "<response><error cause=\"outofbandrequired\" ",
                    "outofbandname=\"LastPass Authenticator\" ",
                    "capabilities=\"outofband,passcode\"/></response>"
                ),
            ),
            (
                "login.php",
                200,
                concat!(
                    "<response><error cause=\"outofbandrequired\" ",
                    "retryid=\"retry-2\"/></response>"
                ),
            ),
        ]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt = |_name: &str, _error: Option<&str>, _description: &str| {
            panic!("out-of-band approval should not prompt for a code");
        };

        let session = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect("approval succeeds");

        assert_eq!(session.uid, "57747756");
        let requests = client.mock_requests().expect("mock requests");
        let login_requests = requests
            .iter()
            .filter(|request| request.page == "login.php")
            .collect::<Vec<_>>();
        assert_eq!(login_requests.len(), 3);
        assert_eq!(
            login_requests[1]
                .params
                .get("outofbandrequest")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            login_requests[2]
                .params
                .get("outofbandretry")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            login_requests[2]
                .params
                .get("outofbandretryid")
                .map(String::as_str),
            Some("retry-2")
        );
    }

    #[test]
    fn lastpass_login_uses_passcode_when_out_of_band_is_unavailable() {
        let client = HttpClient::mock_with_overrides(&[(
            "login.php",
            200,
            concat!(
                "<response><error cause=\"outofbandrequired\" ",
                "outofbandname=\"Email\" capabilities=\"passcode\"/>",
                "</response>"
            ),
        )]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt_details = None;
        let mut prompt = |name: &str, _error: Option<&str>, description: &str| {
            prompt_details = Some((name.to_string(), description.to_string()));
            Ok("654321".to_string())
        };

        let session = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect("passcode succeeds");

        assert_eq!(session.uid, "57747756");
        assert_eq!(
            prompt_details,
            Some((
                "Code".to_string(),
                concat!("Please enter your Email OTP for ", "<user@example.com>.").to_string(),
            ))
        );
        let login_requests = client
            .mock_requests()
            .expect("mock requests")
            .into_iter()
            .filter(|request| request.page == "login.php")
            .collect::<Vec<_>>();
        assert_eq!(login_requests.len(), 2);
        assert_eq!(
            login_requests[1].params.get("otp").map(String::as_str),
            Some("654321")
        );
    }

    #[test]
    fn lastpass_login_falls_back_to_passcode_when_polling_fails() {
        let client = HttpClient::mock_with_overrides_and_failure(
            &[(
                "login.php",
                200,
                concat!(
                    "<response><error cause=\"outofbandrequired\" ",
                    "outofbandname=\"Email\" ",
                    "capabilities=\"outofband,passcode\"/></response>"
                ),
            )],
            "login.php",
            2,
        );
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt_description = None;
        let mut prompt = |_name: &str, _error: Option<&str>, description: &str| {
            prompt_description = Some(description.to_string());
            Ok("654321".to_string())
        };

        lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect("passcode fallback succeeds");

        assert_eq!(
            prompt_description.as_deref(),
            Some("Please enter your Email OTP for <user@example.com>.")
        );
        let requests = client.mock_requests().expect("mock requests");
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2]
                .params
                .get("outofbandrequest")
                .map(String::as_str),
            Some("0")
        );
        assert_eq!(
            requests[2].params.get("outofbandretry").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            requests[2].params.get("outofbandretryid"),
            Some(&String::new())
        );
        assert_eq!(
            requests[2].params.get("otp").map(String::as_str),
            Some("654321")
        );
    }

    #[test]
    fn outofband_login_falls_back_to_passcode_when_poll_is_interrupted() {
        let client = HttpClient::mock();
        let challenge = LoginChallenge {
            cause: "outofbandrequired".to_string(),
            message: None,
            server: None,
            outofband_name: Some("Email".to_string()),
            capabilities: Some("outofband,passcode".to_string()),
            retry_id: None,
        };
        let mut params = vec![("username".to_string(), "user@example.com".to_string())];
        let mut checks = 0;

        let result = outofband_login_with_interrupt_check(
            &client,
            "lastpass.com",
            &mut params,
            &challenge,
            || {
                checks += 1;
                checks == 2
            },
        )
        .expect("interrupt should select passcode fallback");

        assert!(matches!(result, OutOfBandResult::Passcode(ref name) if name == "Email OTP"));
        assert_eq!(
            params.iter().find(|(key, _)| key == "outofbandrequest"),
            Some(&("outofbandrequest".to_string(), "0".to_string()))
        );
        assert_eq!(
            params.iter().find(|(key, _)| key == "outofbandretry"),
            Some(&("outofbandretry".to_string(), "0".to_string()))
        );
        assert_eq!(
            params.iter().find(|(key, _)| key == "outofbandretryid"),
            Some(&("outofbandretryid".to_string(), String::new()))
        );
        assert_eq!(client.mock_requests().expect("mock requests").len(), 1);
    }

    #[test]
    fn sigint_flag_records_ctrl_c() {
        let interrupt = SigintFlag::new().expect("register SIGINT handler");

        signal_hook::low_level::raise(signal_hook::consts::SIGINT).expect("raise SIGINT");

        assert!(interrupt.is_interrupted());
    }

    #[test]
    fn lastpass_login_propagates_out_of_band_poll_failure_without_passcode() {
        let client = HttpClient::mock_with_overrides_and_failure(
            &[(
                "login.php",
                200,
                concat!(
                    "<response><error cause=\"outofbandrequired\" ",
                    "outofbandname=\"LastPass Authenticator\" ",
                    "capabilities=\"outofband\"/></response>"
                ),
            )],
            "login.php",
            2,
        );
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt = |_name: &str, _error: Option<&str>, _description: &str| {
            panic!("a poll failure without passcode support must not prompt");
        };

        let err = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect_err("polling failure should be returned");

        assert!(format!("{err}").contains("mock request failed"));
        assert_eq!(client.mock_requests().expect("mock requests").len(), 2);
    }

    #[test]
    fn lastpass_login_rejects_out_of_band_challenges_missing_metadata() {
        for challenge in [
            concat!(
                "<response><error cause=\"outofbandrequired\" ",
                "capabilities=\"passcode\"/></response>"
            ),
            concat!(
                "<response><error cause=\"outofbandrequired\" ",
                "outofbandname=\"Email\"/></response>"
            ),
        ] {
            let client = HttpClient::mock_with_overrides(&[("login.php", 200, challenge)]);
            let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
            let mut prompt =
                |_name: &str, _error: Option<&str>, _description: &str| Ok("654321".to_string());

            let error = lastpass_login_with_client_and_prompt(
                &client,
                "user@example.com",
                &hash,
                1000,
                None,
                None,
                &mut prompt,
            )
            .expect_err("incomplete out-of-band challenge must fail");

            assert_eq!(error.to_string(), "Could not determine out-of-band type.");
        }
    }

    #[test]
    fn lastpass_login_propagates_otp_prompt_errors() {
        let client = HttpClient::mock_with_overrides(&[(
            "login.php",
            200,
            "<response><error cause=\"googleauthrequired\"/></response>",
        )]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt = |_name: &str, _error: Option<&str>, _description: &str| {
            Err(crate::error::LpassError::User("prompt cancelled"))
        };

        let error = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect_err("prompt error should stop MFA login");

        assert_eq!(error.to_string(), "prompt cancelled");
        assert_eq!(client.mock_requests().expect("mock requests").len(), 1);
    }

    #[test]
    fn lastpass_login_reports_non_retryable_mfa_failure() {
        let client = HttpClient::mock_with_overrides(&[
            (
                "login.php",
                200,
                "<response><error cause=\"googleauthrequired\"/></response>",
            ),
            (
                "login.php",
                200,
                concat!(
                    "<response><error cause=\"authfailed\" ",
                    "message=\"invalid password\"/></response>"
                ),
            ),
        ]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt =
            |_name: &str, _error: Option<&str>, _description: &str| Ok("654321".to_string());

        let error = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect_err("non-retryable MFA failure should stop login");

        assert_eq!(error.to_string(), "Invalid password");
        assert_eq!(client.mock_requests().expect("mock requests").len(), 2);
    }

    #[test]
    fn lastpass_login_submits_each_non_google_mfa_factor() {
        let cases = [
            ("<response><error cause=\"otprequired\"/></response>", "otp"),
            (
                "<response><error cause=\"sesameotprequired\"/></response>",
                "sesameotp",
            ),
            (
                "<response><error cause=\"microsoftauthrequired\"/></response>",
                "otp",
            ),
            (
                concat!(
                    "<response><error cause=\"outofbandrequired\" ",
                    "outofbandname=\"Email\" capabilities=\"passcode\"/>",
                    "</response>"
                ),
                "otp",
            ),
        ];

        for (challenge, expected_param) in cases {
            let client = HttpClient::mock_with_overrides(&[("login.php", 200, challenge)]);
            let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
            let mut prompt =
                |_name: &str, _error: Option<&str>, _description: &str| Ok("654321".to_string());

            lastpass_login_with_client_and_prompt(
                &client,
                "user@example.com",
                &hash,
                1000,
                None,
                Some("trusted-label"),
                &mut prompt,
            )
            .expect("MFA login succeeds");

            let requests = client.mock_requests().expect("mock requests");
            assert_eq!(requests.len(), 2);
            assert_eq!(
                requests[0].params.get("trustlabel"),
                None,
                "trust label is added after the initial challenge"
            );
            assert_eq!(
                requests[1].params.get("trustlabel").map(String::as_str),
                Some("trusted-label")
            );
            assert_eq!(
                requests[1].params.get(expected_param).map(String::as_str),
                Some("654321")
            );
        }
    }

    #[test]
    fn lastpass_login_rejects_unrecognized_mfa_challenge() {
        let client = HttpClient::mock_with_overrides(&[(
            "login.php",
            200,
            concat!(
                "<response><error cause=\"unknownfactorrequired\" ",
                "message=\"multifactor denied\"/></response>"
            ),
        )]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt = |_name: &str, _error: Option<&str>, _description: &str| {
            panic!("unsupported MFA factor should not prompt");
        };

        let error = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect_err("unknown MFA factor must fail");

        assert_eq!(error.to_string(), "Multifactor authentication failed");
    }

    #[test]
    fn lastpass_login_reports_mfa_response_without_challenge_cause() {
        let client = HttpClient::mock_with_overrides(&[
            (
                "login.php",
                200,
                "<response><error cause=\"googleauthrequired\"/></response>",
            ),
            (
                "login.php",
                200,
                "<response><error message=\"multifactor denied\"/></response>",
            ),
        ]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt =
            |_name: &str, _error: Option<&str>, _description: &str| Ok("654321".to_string());

        let error = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect_err("MFA failure response must stop login");

        assert_eq!(error.to_string(), "Multifactor authentication failed");
    }

    #[test]
    fn lastpass_login_reports_out_of_band_denial_without_passcode_support() {
        let client = HttpClient::mock_with_overrides(&[
            (
                "login.php",
                200,
                concat!(
                    "<response><error cause=\"outofbandrequired\" ",
                    "outofbandname=\"Authenticator\" ",
                    "capabilities=\"outofband\"/></response>"
                ),
            ),
            (
                "login.php",
                200,
                concat!(
                    "<response><error cause=\"outofbandfailed\" ",
                    "message=\"multifactor denied\"/></response>"
                ),
            ),
        ]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt = |_name: &str, _error: Option<&str>, _description: &str| {
            panic!("denied push should not prompt for a code");
        };

        let error = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect_err("out-of-band denial should fail login");

        assert_eq!(error.to_string(), "Multifactor authentication failed");
        assert_eq!(client.mock_requests().expect("mock requests").len(), 2);
    }

    #[test]
    fn lastpass_login_reports_out_of_band_failure_without_challenge_cause() {
        let client = HttpClient::mock_with_overrides(&[
            (
                "login.php",
                200,
                concat!(
                    "<response><error cause=\"outofbandrequired\" ",
                    "outofbandname=\"Authenticator\" ",
                    "capabilities=\"outofband\"/></response>"
                ),
            ),
            (
                "login.php",
                200,
                "<response><error message=\"multifactor denied\"/></response>",
            ),
        ]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let mut prompt = |_name: &str, _error: Option<&str>, _description: &str| {
            panic!("failed push should not prompt for a code");
        };

        let error = lastpass_login_with_client_and_prompt(
            &client,
            "user@example.com",
            &hash,
            1000,
            None,
            None,
            &mut prompt,
        )
        .expect_err("out-of-band failure must stop login");

        assert_eq!(error.to_string(), "Multifactor authentication failed");
    }

    #[test]
    fn lastpass_login_redirects_to_lastpass_eu() {
        let client = HttpClient::mock_with_overrides(&[(
            "login.php",
            200,
            concat!("<response><error ", "server=\"lastpass.eu\"/></response>"),
        )]);
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");

        let session = lastpass_login_with_client_basic(&client, "user@example.com", &hash, 1000)
            .expect("redirected login");

        assert_eq!(session.server.as_deref(), Some("lastpass.eu"));
        assert_eq!(
            client
                .mock_requests()
                .expect("mock requests")
                .iter()
                .filter(|request| request.page == "login.php")
                .count(),
            2
        );
    }

    #[test]
    fn multifactor_types_match_upstream_post_fields() {
        let cases = [
            ("googleauthrequired", "googleauthfailed", "otp"),
            ("otprequired", "otpfailed", "otp"),
            ("sesameotprequired", "sesameotpfailed", "sesameotp"),
            ("outofbandrequired", "multifactorresponsefailed", "otp"),
            ("microsoftauthrequired", "microsoftauthfailed", "otp"),
        ];
        for (cause, failure_cause, post_param) in cases {
            let multifactor = multifactor_type(cause).expect("supported MFA cause");
            assert_eq!(multifactor.failure_cause, failure_cause);
            assert_eq!(multifactor.post_param, post_param);
        }
        assert!(multifactor_type("unrecognized").is_none());
    }

    #[test]
    fn fetch_blob_with_mock_client_returns_blob_bytes() {
        let client = HttpClient::mock();
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let blob = fetch_blob_with_client(&client, &session).expect("mock blob");
        assert!(blob.starts_with(b"LPAV"), "blob bytes: {blob:?}");
    }

    #[test]
    fn fetch_blob_with_real_client_propagates_http_error() {
        let client = HttpClient::real().expect("real client");
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: Some("127.0.0.1:1".to_string()),
            private_key: None,
            private_key_enc: None,
        };
        let err = fetch_blob_with_client(&client, &session).expect_err("network error");
        assert!(err.contains("http post"));
    }

    #[test]
    fn fetch_blob_covers_wrapper_path() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let _ = fetch_blob(&session);
    }

    #[test]
    fn ensure_non_empty_blob_response_returns_input_when_non_empty() {
        let blob = ensure_non_empty_blob_response(vec![1, 2, 3]).expect("non-empty blob");
        assert_eq!(blob, vec![1, 2, 3]);
    }

    #[test]
    fn persist_blob_after_login_with_fetch_persists_blob() {
        fn sample_blob(_session: &Session) -> std::result::Result<Vec<u8>, String> {
            Ok(vec![7, 8, 9])
        }

        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [5u8; KDF_HASH_LEN];
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        persist_blob_after_login_with_fetch(&store, &session, &key, sample_blob)
            .expect("persist blob");

        let stored = store
            .read_encrypted_buffer("blob", &key)
            .expect("read blob")
            .expect("blob present");
        assert_eq!(stored, vec![7, 8, 9]);
    }

    #[test]
    fn persist_blob_after_login_with_fetch_propagates_fetch_and_write_errors() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [5u8; KDF_HASH_LEN];

        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let err = persist_blob_after_login_with_fetch(&store, &session, &key, |_session| {
            Err("fetch failed".to_string())
        })
        .expect_err("fetch error");
        assert_eq!(err, "fetch failed");

        let file_home = temp.path().join("not-a-dir");
        std::fs::write(&file_home, b"x").expect("write file");
        let invalid_home = file_home.join("child");
        let bad_store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(invalid_home),
            ..ConfigEnv::default()
        });
        let err = persist_blob_after_login_with_fetch(&bad_store, &session, &key, |_session| {
            Ok(vec![1, 2, 3])
        })
        .expect_err("write error");
        assert!(err.contains("IO error while"));
    }

    #[test]
    fn persist_blob_after_login_covers_wrapper_path() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        let key = [8u8; KDF_HASH_LEN];
        let _ = persist_blob_after_login(&session, &key);
    }

    #[test]
    fn parse_yes_no_response_matches_expected_inputs() {
        assert_eq!(parse_yes_no_response("", false), Some(false));
        assert_eq!(parse_yes_no_response("y", false), Some(true));
        assert_eq!(parse_yes_no_response("n", true), Some(false));
        assert_eq!(parse_yes_no_response("maybe", true), None);
    }

    #[test]
    fn ask_yes_no_with_reader_writer_handles_retry_and_eof() {
        let mut output = Vec::new();
        let mut reader = io::Cursor::new(b"maybe\ny\n".to_vec());
        let value = ask_yes_no_with_reader_writer(&mut reader, &mut output, false, "Prompt")
            .expect("valid answer after retry");
        assert!(value);
        let rendered = String::from_utf8_lossy(&output);
        assert!(rendered.contains("Response not understood."));

        let mut output = Vec::new();
        let mut reader = io::Cursor::new(Vec::<u8>::new());
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut output, true, "Prompt")
            .expect_err("EOF should abort");
        assert_eq!(err, "aborted response.");
    }

    #[test]
    fn ask_yes_no_with_reader_writer_propagates_io_errors() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("write failed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct FailingFlushWriter;
        impl Write for FailingFlushWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("flush failed"))
            }
        }

        struct FailingReader;
        impl BufRead for FailingReader {
            fn fill_buf(&mut self) -> io::Result<&[u8]> {
                Err(io::Error::other("read failed"))
            }
            fn consume(&mut self, _amt: usize) {}
        }
        impl io::Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }

        let mut reader = io::Cursor::new(b"y\n".to_vec());
        let mut writer = FailingWriter;
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, false, "Prompt")
            .expect_err("write error");
        assert!(err.contains("write failed"));

        let mut reader = io::Cursor::new(b"y\n".to_vec());
        let mut writer = FailingFlushWriter;
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, false, "Prompt")
            .expect_err("flush error");
        assert!(err.contains("flush failed"));

        let mut reader = FailingReader;
        let mut writer = Vec::new();
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, false, "Prompt")
            .expect_err("read error");
        assert!(err.contains("read failed"));

        let mut writer = FailingWriter;
        writer.flush().expect("explicit flush path");

        let mut reader = FailingReader;
        reader.consume(0);
        let mut buf = [0u8; 1];
        let err = io::Read::read(&mut reader, &mut buf).expect_err("read path");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn generate_trusted_id_has_expected_shape() {
        let trusted_id = generate_trusted_id();
        assert_eq!(trusted_id.len(), 32);
        assert!(trusted_id.chars().all(|ch| {
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$".contains(ch)
        }));
    }

    #[test]
    fn calculate_trust_id_with_store_respects_force_and_persistence() {
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let id_none = calculate_trust_id_with_store(&store, false).expect("read");
        assert!(id_none.is_none());

        let first = calculate_trust_id_with_store(&store, true)
            .expect("create")
            .expect("created");
        assert_eq!(first.len(), 32);

        let second = calculate_trust_id_with_store(&store, false)
            .expect("read existing")
            .expect("existing");
        assert_eq!(first, second);
    }

    #[test]
    fn calculate_trust_label_is_non_empty() {
        let label = calculate_trust_label().expect("label");
        assert!(label.contains(" - "));
    }

    #[test]
    fn ensure_nonzero_iterations_rejects_zero() {
        let err = ensure_nonzero_iterations(0).expect_err("zero iterations must fail");
        assert_eq!(err, "Unable to fetch iteration count.");
        ensure_nonzero_iterations(1000).expect("non-zero iterations");
    }

    #[test]
    fn maybe_attach_private_key_covers_guard_and_success_paths() {
        let key = [7u8; KDF_HASH_LEN];
        let mut session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: Some(vec![1]),
            private_key_enc: Some("ignored".to_string()),
        };
        maybe_attach_private_key(&mut session, &key);
        assert_eq!(session.private_key.as_deref(), Some(&[1][..]));

        let payload = b"LastPassPrivateKey<4142>LastPassPrivateKey";
        let encrypted = aes_encrypt_lastpass(payload, &key).expect("encrypt");
        let private_key_enc = base64_lastpass_encode(&encrypted);
        let mut session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: Some(private_key_enc),
        };
        maybe_attach_private_key(&mut session, &key);
        assert_eq!(session.private_key.as_deref(), Some(&[0x41, 0x42][..]));

        let mut session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: Some("not-a-valid-key".to_string()),
        };
        maybe_attach_private_key(&mut session, &key);
        assert!(session.private_key.is_none());

        // Cover the early return when private_key_enc is None (line 175)
        let mut session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        maybe_attach_private_key(&mut session, &key);
        assert!(session.private_key.is_none());
    }

    #[test]
    fn parse_login_response_reports_generic_error_when_message_is_missing() {
        assert!(matches!(
            parse_login_response(
                "<response><error/></response>",
                crate::http::LASTPASS_SERVER
            ),
            LoginResponse::Failure("login failed")
        ));
    }

    #[test]
    fn parse_login_response_identifies_google_auth_challenge() {
        let response = parse_login_response(
            "<response><error cause=\"googleauthrequired\"/></response>",
            crate::http::LASTPASS_SERVER,
        );
        let LoginResponse::Challenge(challenge) = response else {
            panic!("MFA response should be parsed as a challenge");
        };
        assert_eq!(challenge.cause, "googleauthrequired");
    }

    #[test]
    fn post_trust_covers_none_and_mock_paths() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        post_trust(&session, None, None).expect("missing trust data is ignored");
        let client = HttpClient::mock();
        post_trust_with_client(&client, &session, None, None).expect("none trust post");
        post_trust_with_client(&client, &session, Some("uuid"), Some("label"))
            .expect("mock trust post");

        let real = HttpClient::real().expect("real client");
        let mut bad_server = session.clone();
        bad_server.server = Some("127.0.0.1:1".to_string());
        let err = post_trust_with_client(&real, &bad_server, Some("uuid"), Some("label"))
            .expect_err("network failure");
        assert!(format!("{err}").contains("http post"));
    }

    #[test]
    fn lastpass_login_with_client_accepts_trust_metadata() {
        let client = HttpClient::mock();
        let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
        let session = lastpass_login_with_client(
            &client,
            "user@example.com",
            &hash,
            1000,
            Some("trusted-id"),
            Some("trusted-label"),
        )
        .expect("login");
        assert_eq!(session.uid, "57747756");
    }

    #[test]
    fn filter_error_message_normalizes_known_messages() {
        assert_eq!(filter_error_message("invalid password"), "Invalid password");
        assert_eq!(
            filter_error_message("multifactorresponsefailed"),
            "Multifactor authentication failed"
        );
        assert_eq!(filter_error_message("something else"), "login failed");
    }
}
