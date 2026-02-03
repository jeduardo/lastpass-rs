#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use crate::agent::agent_try_ask_decryption_key;
use crate::http::HttpClient;
use crate::kdf::KDF_HASH_LEN;
use crate::session::{Session, session_kill, session_load};
use crate::terminal::{self, BOLD, FG_RED, FG_YELLOW, RESET};
use zeroize::Zeroize;

#[derive(Debug, Clone, Eq, PartialEq)]
struct LogoutArgs {
    force: bool,
}

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<i32, String> {
    run_inner_with(
        args,
        try_agent_key,
        load_session_for_logout,
        logout_session_remote,
        kill_session_for_logout,
        ask_yes_no,
    )
}

fn run_inner_with<T, L, O, K, A>(
    args: &[String],
    try_key: T,
    load_session: L,
    logout_remote: O,
    kill_session: K,
    ask: A,
) -> Result<i32, String>
where
    T: Fn() -> Option<[u8; KDF_HASH_LEN]>,
    L: Fn(&[u8; KDF_HASH_LEN]) -> Result<Option<Session>, String>,
    O: Fn(&Session),
    K: Fn() -> Result<(), String>,
    A: Fn(bool, &str) -> Result<bool, String>,
{
    let parsed = parse_logout_args(args)?;

    if !parsed.force && !ask(true, "Are you sure you would like to log out?")? {
        let message = format!("{FG_YELLOW}{BOLD}Log out{RESET}: aborted.");
        println!("{}", terminal::render_stdout(&message));
        return Ok(1);
    }

    maybe_remote_logout(try_key, load_session, logout_remote)?;

    kill_session()?;

    let message = format!("{FG_YELLOW}{BOLD}Log out{RESET}: complete.");
    println!("{}", terminal::render_stdout(&message));
    Ok(0)
}

fn parse_logout_args(args: &[String]) -> Result<LogoutArgs, String> {
    let usage = "usage: logout [--force, -f] [--color=auto|never|always]";
    let mut force = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--force" || arg == "-f" {
            force = true;
            continue;
        }
        if arg == "--color" {
            let Some(value) = iter.next() else {
                return Err(usage.to_string());
            };
            let Some(mode) = terminal::parse_color_mode(value) else {
                return Err(usage.to_string());
            };
            terminal::set_color_mode(mode);
            continue;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            let Some(mode) = terminal::parse_color_mode(value) else {
                return Err(usage.to_string());
            };
            terminal::set_color_mode(mode);
            continue;
        }
        return Err(usage.to_string());
    }
    Ok(LogoutArgs { force })
}

fn try_agent_key() -> Option<[u8; KDF_HASH_LEN]> {
    agent_try_ask_decryption_key().ok()
}

fn load_session_for_logout(key: &[u8; KDF_HASH_LEN]) -> Result<Option<Session>, String> {
    session_load(key).map_err(display_to_string)
}

fn logout_session_remote(session: &Session) {
    lastpass_logout(&session.token, Some(session));
}

fn kill_session_for_logout() -> Result<(), String> {
    session_kill().map_err(display_to_string)
}

fn display_to_string<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

fn maybe_remote_logout<T, L, O>(try_key: T, load_session: L, logout: O) -> Result<(), String>
where
    T: FnOnce() -> Option<[u8; KDF_HASH_LEN]>,
    L: FnOnce(&[u8; KDF_HASH_LEN]) -> Result<Option<Session>, String>,
    O: FnOnce(&Session),
{
    if let Some(mut key) = try_key() {
        let session = load_session(&key)?.ok_or_else(|| {
            "Could not find session. Perhaps you need to login with `lpass login`.".to_string()
        })?;
        logout(&session);
        key.zeroize();
    }
    Ok(())
}

fn lastpass_logout(token: &str, session: Option<&Session>) {
    lastpass_logout_with_factory(token, session, HttpClient::from_env);
}

fn lastpass_logout_with_factory<F>(token: &str, session: Option<&Session>, client_factory: F)
where
    F: FnOnce() -> crate::error::Result<HttpClient>,
{
    let Ok(client) = client_factory() else {
        return;
    };
    lastpass_logout_with_client(&client, token, session);
}

fn lastpass_logout_with_client(client: &HttpClient, token: &str, session: Option<&Session>) {
    let _ = client.post_lastpass(
        None,
        "logout.php",
        session,
        &[("method", "cli"), ("noredirect", "1"), ("token", token)],
    );
}

fn ask_yes_no(default_yes: bool, prompt: &str) -> Result<bool, String> {
    let mut reader = io::stdin().lock();
    let mut writer = io::stderr().lock();
    ask_yes_no_with_reader_writer(&mut reader, &mut writer, default_yes, prompt)
}

fn ask_yes_no_with_reader_writer<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
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
            .map_err(display_to_string)?;
        writer.flush().map_err(display_to_string)?;

        let mut response = String::new();
        let read = reader.read_line(&mut response).map_err(display_to_string)?;
        if read == 0 {
            return Err("aborted response.".to_string());
        }

        if let Some(value) = parse_yes_no_response(response.trim(), default_yes) {
            return Ok(value);
        }

        let msg = format!("{FG_RED}{BOLD}Error{RESET}: Response not understood.");
        writer
            .write_all(format!("{}\n", terminal::render_stderr(&msg)).as_bytes())
            .map_err(display_to_string)?;
        writer.flush().map_err(display_to_string)?;
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

#[cfg(test)]
mod tests {
    use super::{
        ask_yes_no_with_reader_writer, lastpass_logout, lastpass_logout_with_client,
        lastpass_logout_with_factory, load_session_for_logout, logout_session_remote,
        maybe_remote_logout, parse_logout_args, parse_yes_no_response, run_inner, run_inner_with,
    };
    use crate::http::HttpClient;
    use crate::kdf::KDF_HASH_LEN;
    use crate::session::Session;
    use std::cell::Cell;
    use std::io::{self, BufRead, Write};

    fn noop_load_session(_key: &[u8; KDF_HASH_LEN]) -> Result<Option<Session>, String> {
        Ok(None)
    }

    fn noop_logout(_session: &Session) {}

    fn ok_kill() -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn parse_yes_no_accepts_yes_variants() {
        assert_eq!(parse_yes_no_response("y", true), Some(true));
        assert_eq!(parse_yes_no_response("yes", false), Some(true));
        assert_eq!(parse_yes_no_response("yellow", false), Some(true));
    }

    #[test]
    fn parse_yes_no_accepts_no_variants() {
        assert_eq!(parse_yes_no_response("n", true), Some(false));
        assert_eq!(parse_yes_no_response("no", true), Some(false));
        assert_eq!(parse_yes_no_response("never", true), Some(false));
    }

    #[test]
    fn parse_yes_no_uses_default_on_empty_response() {
        assert_eq!(parse_yes_no_response("", true), Some(true));
        assert_eq!(parse_yes_no_response("", false), Some(false));
    }

    #[test]
    fn parse_yes_no_rejects_unknown_response() {
        assert_eq!(parse_yes_no_response("maybe", true), None);
    }

    #[test]
    fn run_inner_rejects_unknown_options() {
        let err = run_inner(&["--bogus".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: logout"));
    }

    #[test]
    fn run_inner_rejects_missing_color_value() {
        let err = run_inner(&["--color".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: logout"));
    }

    #[test]
    fn run_inner_rejects_invalid_color_value() {
        let err = run_inner(&["--color=rainbow".to_string()]).expect_err("must fail");
        assert!(err.contains("usage: logout"));
    }

    #[test]
    fn parse_logout_args_accepts_color_modes() {
        let args = parse_logout_args(&[
            "--color".to_string(),
            "always".to_string(),
            "-f".to_string(),
        ])
        .expect("args");
        assert!(args.force);

        let args = parse_logout_args(&["--color=never".to_string()]).expect("args");
        assert!(!args.force);
    }

    #[test]
    fn run_inner_accepts_valid_color_values() {
        let code = run_inner(&[
            "--force".to_string(),
            "--color".to_string(),
            "always".to_string(),
        ])
        .expect("run");
        assert_eq!(code, 0);

        let code = run_inner(&["--force".to_string(), "--color=auto".to_string()]).expect("run");
        assert_eq!(code, 0);
    }

    #[test]
    fn maybe_remote_logout_handles_all_key_paths() {
        maybe_remote_logout(|| None, noop_load_session, noop_logout).expect("no key");
        let _ = noop_load_session(&[0u8; KDF_HASH_LEN]).expect("noop");
        let noop_session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: None,
            private_key: None,
            private_key_enc: None,
        };
        noop_logout(&noop_session);

        let err = maybe_remote_logout(
            || Some([7u8; KDF_HASH_LEN]),
            |_key| Err("load failed".to_string()),
            noop_logout,
        )
        .expect_err("load error");
        assert_eq!(err, "load failed");

        let err = maybe_remote_logout(|| Some([7u8; KDF_HASH_LEN]), |_key| Ok(None), noop_logout)
            .expect_err("missing session");
        assert!(err.contains("Could not find session"));

        let called = Cell::new(false);
        maybe_remote_logout(
            || Some([7u8; KDF_HASH_LEN]),
            |_key| {
                Ok(Some(Session {
                    uid: "u".to_string(),
                    session_id: "s".to_string(),
                    token: "t".to_string(),
                    server: None,
                    private_key: None,
                    private_key_enc: None,
                }))
            },
            |_session| called.set(true),
        )
        .expect("success");
        assert!(called.get());
    }

    #[test]
    fn lastpass_logout_helpers_ignore_client_errors() {
        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: Some("127.0.0.1:1".to_string()),
            private_key: None,
            private_key_enc: None,
        };

        let real = HttpClient::real().expect("client");
        lastpass_logout_with_client(&real, "token", Some(&session));
        lastpass_logout("token", Some(&session));

        lastpass_logout_with_factory("token", Some(&session), || {
            Err(crate::error::LpassError::Crypto("factory failed"))
        });
        lastpass_logout_with_factory("token", Some(&session), || Ok(HttpClient::mock()));
    }

    #[test]
    fn run_inner_with_covers_error_paths() {
        let ask_err = run_inner_with(
            &[],
            || None,
            noop_load_session,
            noop_logout,
            ok_kill,
            |_default_yes, _prompt| Err("ask failed".to_string()),
        )
        .expect_err("ask error");
        assert_eq!(ask_err, "ask failed");

        let remote_err = run_inner_with(
            &["--force".to_string()],
            || Some([1u8; KDF_HASH_LEN]),
            |_key| Err("load failed".to_string()),
            noop_logout,
            ok_kill,
            |_default_yes, _prompt| Ok(true),
        )
        .expect_err("remote error");
        assert_eq!(remote_err, "load failed");

        let kill_err = run_inner_with(
            &["--force".to_string()],
            || None,
            noop_load_session,
            noop_logout,
            || Err("kill failed".to_string()),
            |_default_yes, _prompt| Ok(true),
        )
        .expect_err("kill error");
        assert_eq!(kill_err, "kill failed");

        let called = Cell::new(false);
        let code = run_inner_with(
            &["--force".to_string()],
            || Some([2u8; KDF_HASH_LEN]),
            |_key| {
                Ok(Some(Session {
                    uid: "u".to_string(),
                    session_id: "s".to_string(),
                    token: "t".to_string(),
                    server: Some("127.0.0.1:1".to_string()),
                    private_key: None,
                    private_key_enc: None,
                }))
            },
            |_session| called.set(true),
            || Ok(()),
            |_default_yes, _prompt| Ok(true),
        )
        .expect("success");
        assert_eq!(code, 0);
        assert!(called.get());
    }

    #[test]
    fn parse_logout_args_rejects_invalid_space_color_value() {
        let err = parse_logout_args(&["--color".to_string(), "rainbow".to_string()])
            .expect_err("invalid color");
        assert!(err.contains("usage: logout"));
    }

    #[test]
    fn logout_session_helpers_are_callable() {
        let key = [9u8; KDF_HASH_LEN];
        let _ = load_session_for_logout(&key);

        let session = Session {
            uid: "u".to_string(),
            session_id: "s".to_string(),
            token: "t".to_string(),
            server: Some("127.0.0.1:1".to_string()),
            private_key: None,
            private_key_enc: None,
        };
        logout_session_remote(&session);
    }

    #[test]
    fn ask_yes_no_with_reader_writer_covers_default_and_errors() {
        let mut output = Vec::new();
        let mut reader = io::Cursor::new(b"n\n".to_vec());
        let value = ask_yes_no_with_reader_writer(&mut reader, &mut output, false, "Prompt")
            .expect("answer");
        assert!(!value);

        let mut output = Vec::new();
        let mut reader = io::Cursor::new(Vec::<u8>::new());
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut output, true, "Prompt")
            .expect_err("EOF");
        assert_eq!(err, "aborted response.");

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
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, true, "Prompt")
            .expect_err("write error");
        assert!(err.contains("write failed"));

        let mut reader = io::Cursor::new(b"y\n".to_vec());
        let mut writer = FailingFlushWriter;
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, true, "Prompt")
            .expect_err("flush error");
        assert!(err.contains("flush failed"));

        struct FailingSecondWrite {
            writes: usize,
        }
        impl Write for FailingSecondWrite {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                if self.writes == 2 {
                    Err(io::Error::other("write second failed"))
                } else {
                    Ok(buf.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct FailingSecondFlush {
            flushes: usize,
        }
        impl Write for FailingSecondFlush {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                if self.flushes == 2 {
                    Err(io::Error::other("flush second failed"))
                } else {
                    Ok(())
                }
            }
        }

        let mut reader = io::Cursor::new(b"maybe\n".to_vec());
        let mut writer = FailingSecondWrite { writes: 0 };
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, true, "Prompt")
            .expect_err("write second error");
        assert!(err.contains("write second failed"));

        let mut reader = io::Cursor::new(b"maybe\n".to_vec());
        let mut writer = FailingSecondFlush { flushes: 0 };
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, true, "Prompt")
            .expect_err("flush second error");
        assert!(err.contains("flush second failed"));

        let mut reader = FailingReader;
        let mut writer = Vec::new();
        let err = ask_yes_no_with_reader_writer(&mut reader, &mut writer, true, "Prompt")
            .expect_err("read error");
        assert!(err.contains("read failed"));

        let mut writer = FailingWriter;
        writer.flush().expect("flush success");

        let mut reader = FailingReader;
        reader.consume(0);
        let mut buf = [0u8; 1];
        let err = io::Read::read(&mut reader, &mut buf).expect_err("read");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }
}
