#![forbid(unsafe_code)]

use std::env;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{
    config_exists, config_path, config_read_buffer, config_read_encrypted_string,
    config_read_string, config_unlink, config_write_encrypted_string, config_write_string,
};
use crate::error::{LpassError, Result};
use crate::kdf::{KDF_HASH_LEN, kdf_decryption_key};
use crate::password::prompt_password;
use zeroize::Zeroize;

const AGENT_ARG: &str = "__agent";
const VERIFY_STRING: &str = "`lpass` was written by LastPass.\n";

pub fn maybe_run_agent(args: &[String]) -> Option<i32> {
    let Some(arg) = args.get(1) else {
        return None;
    };
    if arg != AGENT_ARG {
        return None;
    }

    match read_key_from_stdin().and_then(|key| run_agent(&key)) {
        Ok(()) => Some(0),
        Err(err) => {
            eprintln!("error: {err}");
            Some(1)
        }
    }
}

pub fn agent_get_decryption_key() -> Result<[u8; KDF_HASH_LEN]> {
    if let Some(buffer) = config_read_buffer("plaintext_key")? {
        if buffer.len() == KDF_HASH_LEN {
            let mut key = [0u8; KDF_HASH_LEN];
            key.copy_from_slice(&buffer);
            if verify_key(&key)? {
                return Ok(key);
            }
        }
        let _ = config_unlink("plaintext_key");
    }

    if let Ok(key) = agent_ask() {
        return Ok(key);
    }

    let key = agent_load_key()?;
    agent_start(&key)?;
    Ok(key)
}

pub fn agent_save(username: &str, iterations: u32, key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    config_write_string("iterations", &iterations.to_string())?;
    config_write_string("username", username)?;
    config_write_encrypted_string("verify", VERIFY_STRING, key)?;
    agent_start(key)
}

pub fn agent_is_available() -> bool {
    if let Ok(Some(buffer)) = config_read_buffer("plaintext_key") {
        if buffer.len() == KDF_HASH_LEN {
            let mut key = [0u8; KDF_HASH_LEN];
            key.copy_from_slice(&buffer);
            let valid = verify_key(&key).unwrap_or(false);
            key.zeroize();
            if valid {
                return true;
            }
        }
    }

    match agent_ask() {
        Ok(mut key) => {
            key.zeroize();
            true
        }
        Err(_) => false,
    }
}

pub fn agent_kill() -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs;
        use std::io::ErrorKind;
        use std::os::unix::net::UnixStream;

        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        let path = agent_socket_path()?;
        let mut stream = match UnixStream::connect(&path) {
            Ok(stream) => stream,
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused | ErrorKind::Other
                ) =>
            {
                let _ = fs::remove_file(&path);
                return Ok(());
            }
            Err(err) => return Err(LpassError::io("connect", err)),
        };

        let pid = if socket_send_pid() {
            let this_pid = std::process::id();
            stream
                .write_all(&this_pid.to_ne_bytes())
                .map_err(|err| LpassError::io("write pid", err))?;
            let mut buf = [0u8; 4];
            stream
                .read_exact(&mut buf)
                .map_err(|err| LpassError::io("read pid", err))?;
            Some(u32::from_ne_bytes(buf))
        } else {
            #[cfg(any(target_os = "linux", target_os = "android", target_os = "cygwin"))]
            {
                use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
                let creds = getsockopt(&stream, PeerCredentials)
                    .map_err(|err| LpassError::io("peer credentials", err.into()))?;
                Some(creds.pid() as u32)
            }
            #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
            {
                None
            }
        };

        if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
            if pid > 0 {
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            }
        }

        let _ = fs::remove_file(&path);
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        Ok(())
    }
}

pub fn agent_try_ask_decryption_key() -> Result<[u8; KDF_HASH_LEN]> {
    agent_ask()
}

fn verify_key(key: &[u8; KDF_HASH_LEN]) -> Result<bool> {
    match config_read_encrypted_string("verify", key)? {
        Some(value) => Ok(value == VERIFY_STRING),
        None => Ok(false),
    }
}

fn agent_load_key() -> Result<[u8; KDF_HASH_LEN]> {
    let iterations = config_read_string("iterations")?
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or(LpassError::Crypto("missing iterations"))?;

    let username = config_read_string("username")?.ok_or(LpassError::Crypto("missing username"))?;

    if !config_exists("verify") {
        return Err(LpassError::Crypto("missing verify"));
    }

    loop {
        let mut password = prompt_password(&username)?;
        let key = kdf_decryption_key(&username, &password, iterations)?;
        password.zeroize();
        if verify_key(&key)? {
            return Ok(key);
        }
    }
}

fn agent_start(key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    let _ = agent_kill();

    if config_exists("plaintext_key") {
        return Ok(());
    }
    if crate::lpenv::var("LPASS_AGENT_DISABLE").as_deref() == Ok("1") {
        return Ok(());
    }

    let exe = env::current_exe().map_err(|err| LpassError::io("current_exe", err))?;
    let mut child = Command::new(exe)
        .arg(AGENT_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| LpassError::io("spawn agent", err))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(key)
            .map_err(|err| LpassError::io("write agent", err))?;
    }

    Ok(())
}

fn read_key_from_stdin() -> Result<[u8; KDF_HASH_LEN]> {
    let mut key = [0u8; KDF_HASH_LEN];
    let mut stdin = std::io::stdin();
    stdin
        .read_exact(&mut key)
        .map_err(|err| LpassError::io("read agent key", err))?;
    Ok(key)
}

#[cfg(unix)]
fn run_agent(key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let path = agent_socket_path()?;
    if path.exists() {
        let _ = fs::remove_file(&path);
    }

    let listener = UnixListener::bind(&path).map_err(|err| LpassError::io("bind", err))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|err| LpassError::io("chmod", err))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| LpassError::io("nonblocking", err))?;

    let timeout = agent_timeout();
    let deadline = timeout.map(|duration| Instant::now() + duration);

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_client(stream, key);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(deadline) = deadline {
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(LpassError::io("accept", err)),
        }
    }

    let _ = fs::remove_file(&path);
    Ok(())
}

#[cfg(not(unix))]
fn run_agent(_key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    Err(LpassError::Crypto("agent unsupported"))
}

fn agent_socket_path() -> Result<PathBuf> {
    config_path("agent.sock")
}

fn agent_timeout() -> Option<Duration> {
    let value = crate::lpenv::var("LPASS_AGENT_TIMEOUT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60 * 60);
    if value == 0 {
        None
    } else {
        Some(Duration::from_secs(value))
    }
}

fn socket_send_pid() -> bool {
    !(cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "cygwin"
    )))
}

fn agent_ask() -> Result<[u8; KDF_HASH_LEN]> {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;

        let path = agent_socket_path()?;
        let mut stream =
            UnixStream::connect(&path).map_err(|err| LpassError::io("connect", err))?;

        if socket_send_pid() {
            let pid = std::process::id();
            stream
                .write_all(&pid.to_ne_bytes())
                .map_err(|err| LpassError::io("write pid", err))?;
            let mut buf = [0u8; 4];
            stream
                .read_exact(&mut buf)
                .map_err(|err| LpassError::io("read pid", err))?;
            let _ = u32::from_ne_bytes(buf);
        }

        let mut key = [0u8; KDF_HASH_LEN];
        stream
            .read_exact(&mut key)
            .map_err(|err| LpassError::io("read key", err))?;
        return Ok(key);
    }

    #[cfg(not(unix))]
    {
        Err(LpassError::Crypto("agent unsupported"))
    }
}

#[cfg(unix)]
fn handle_client(
    mut stream: std::os::unix::net::UnixStream,
    key: &[u8; KDF_HASH_LEN],
) -> Result<()> {
    if !peer_allowed(&stream)? {
        return Ok(());
    }

    if socket_send_pid() {
        let _ = read_pid(&mut stream);
        let pid = std::process::id();
        stream
            .write_all(&pid.to_ne_bytes())
            .map_err(|err| LpassError::io("write pid", err))?;
    }

    stream
        .write_all(key)
        .map_err(|err| LpassError::io("write key", err))?;
    Ok(())
}

#[cfg(unix)]
fn peer_allowed(stream: &std::os::unix::net::UnixStream) -> Result<bool> {
    use nix::unistd::{getgid, getuid};

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "cygwin"))]
    {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        let creds = getsockopt(stream, PeerCredentials)
            .map_err(|err| LpassError::io("peer credentials", err.into()))?;
        let uid = creds.uid();
        let gid = creds.gid();
        return Ok(uid == getuid().as_raw() && gid == getgid().as_raw());
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
    {
        use nix::unistd::getpeereid;
        let (uid, gid) =
            getpeereid(stream).map_err(|err| LpassError::io("peer credentials", err.into()))?;
        return Ok(uid == getuid() && gid == getgid());
    }
}

#[cfg(unix)]
fn read_pid(stream: &mut std::os::unix::net::UnixStream) -> Result<u32> {
    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .map_err(|err| LpassError::io("read pid", err))?;
    Ok(u32::from_ne_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maybe_run_agent_returns_none_for_non_agent_commands() {
        assert_eq!(maybe_run_agent(&[]), None);
        assert_eq!(maybe_run_agent(&["lpass".to_string()]), None);
        assert_eq!(
            maybe_run_agent(&["lpass".to_string(), "status".to_string()]),
            None
        );
    }

    #[test]
    fn socket_send_pid_matches_platform_contract() {
        if cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "cygwin"
        )) {
            assert!(!socket_send_pid());
        } else {
            assert!(socket_send_pid());
        }
    }

    #[test]
    fn agent_timeout_has_default_when_env_missing() {
        assert_eq!(agent_timeout(), Some(Duration::from_secs(60 * 60)));
    }
}
