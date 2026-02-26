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
    let arg = args.get(1)?;
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
    if let Ok(Some(buffer)) = config_read_buffer("plaintext_key")
        && buffer.len() == KDF_HASH_LEN
    {
        let mut key = [0u8; KDF_HASH_LEN];
        key.copy_from_slice(&buffer);
        let valid = verify_key(&key).unwrap_or(false);
        key.zeroize();
        if valid {
            return true;
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

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "cygwin"))]
        let pid = {
            use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
            let creds = getsockopt(&stream, PeerCredentials)
                .map_err(|err| LpassError::io("peer credentials", err.into()))?;
            Some(creds.pid() as u32)
        };

        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
        let pid = {
            let this_pid = std::process::id();
            stream
                .write_all(&this_pid.to_ne_bytes())
                .map_err(|err| LpassError::io("write pid", err))?;
            let mut buf = [0u8; 4];
            stream
                .read_exact(&mut buf)
                .map_err(|err| LpassError::io("read pid", err))?;
            Some(u32::from_ne_bytes(buf))
        };

        if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok())
            && pid > 0
            && pid != std::process::id() as i32
        {
            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
        }

        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[cfg(not(unix))]
    {
        Ok(())
    }
}

pub fn agent_try_ask_decryption_key() -> Result<[u8; KDF_HASH_LEN]> {
    agent_ask()
}

pub fn agent_load_on_disk_key() -> Result<[u8; KDF_HASH_LEN]> {
    agent_load_key()
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
                if let Some(deadline) = deadline
                    && Instant::now() >= deadline
                {
                    break;
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

#[cfg(test)]
fn socket_send_pid() -> bool {
    cfg!(not(any(
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

        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
        {
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
        Ok(key)
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

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
    {
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
        Ok(uid == getuid() && gid == getgid())
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
    use crate::config::{
        ConfigEnv, config_exists, config_write_buffer, config_write_encrypted_string,
        config_write_string, set_test_env,
    };
    use crate::kdf::kdf_decryption_key;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use tempfile::Builder;
    use tempfile::TempDir;

    fn test_config_env(temp: &TempDir) -> ConfigEnv {
        let runtime = temp.path().join("runtime");
        std::fs::create_dir_all(&runtime).expect("create runtime");
        ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            xdg_runtime_dir: Some(runtime),
            ..ConfigEnv::default()
        }
    }

    fn short_tempdir() -> TempDir {
        Builder::new()
            .prefix("lpa")
            .tempdir_in("/tmp")
            .expect("tempdir")
    }

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
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "cygwin"))]
        assert!(!socket_send_pid());
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
        assert!(socket_send_pid());
    }

    #[test]
    fn agent_timeout_has_default_when_env_missing() {
        let _guard = crate::lpenv::begin_test_overrides();
        assert_eq!(agent_timeout(), Some(Duration::from_secs(60 * 60)));
    }

    #[test]
    fn agent_timeout_respects_zero_and_invalid_values() {
        let _guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_AGENT_TIMEOUT", "0");
        assert_eq!(agent_timeout(), None);

        crate::lpenv::set_override_for_tests("LPASS_AGENT_TIMEOUT", "invalid");
        assert_eq!(agent_timeout(), Some(Duration::from_secs(60 * 60)));
    }

    #[test]
    fn verify_key_returns_false_when_verify_entry_is_missing() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));
        let key = [1u8; KDF_HASH_LEN];
        assert!(!verify_key(&key).expect("verify"));
    }

    #[test]
    fn run_agent_with_short_timeout_exits_and_cleans_socket_file() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_AGENT_TIMEOUT", "1");
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));
        let key = [3u8; KDF_HASH_LEN];

        if let Err(err) = run_agent(&key) {
            if matches!(
                err,
                LpassError::Io {
                    context: "bind",
                    ref source
                } if source.kind() == std::io::ErrorKind::PermissionDenied
            ) {
                return;
            }
            panic!("run agent: {err}");
        }

        let socket = agent_socket_path().expect("socket path");
        assert!(!socket.exists(), "socket must be removed after timeout");
    }

    #[test]
    fn agent_ask_reads_pid_handshake_and_key_from_socket() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));
        let socket = agent_socket_path().expect("socket path");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let expected_key = [42u8; KDF_HASH_LEN];

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
            {
                let mut pid = [0u8; 4];
                stream.read_exact(&mut pid).expect("read pid");
                stream.write_all(&pid).expect("write pid");
            }
            stream.write_all(&expected_key).expect("write key");
        });

        let key = agent_ask().expect("agent ask");
        assert_eq!(key, expected_key);
        server.join().expect("join server");
        let _ = std::fs::remove_file(&socket);
    }

    #[test]
    fn agent_kill_handles_pid_exchange_and_removes_socket() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));
        let socket = agent_socket_path().expect("socket path");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
            {
                let mut pid = [0u8; 4];
                stream.read_exact(&mut pid).expect("read pid");
                stream.write_all(&pid).expect("write pid");
            }
        });

        agent_kill().expect("agent kill");
        server.join().expect("join server");
        assert!(!socket.exists(), "socket should be removed");
    }

    #[test]
    fn agent_get_decryption_key_prefers_valid_plaintext_key() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));

        let key = [9u8; KDF_HASH_LEN];
        config_write_buffer("plaintext_key", &key).expect("write plaintext key");
        config_write_encrypted_string("verify", VERIFY_STRING, &key).expect("write verify");
        let got = agent_get_decryption_key().expect("get key");
        assert_eq!(got, key);
    }

    #[test]
    fn agent_get_decryption_key_falls_back_to_askpass_loaded_key() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));

        let askpass = temp.path().join("askpass.sh");
        std::fs::write(&askpass, "#!/bin/sh\necho hunter2\n").expect("write askpass");
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700))
            .expect("chmod askpass");

        let username = "user@example.com";
        let iterations = 2u32;
        let key = kdf_decryption_key(username, "hunter2", iterations).expect("derive key");
        config_write_string("iterations", &iterations.to_string()).expect("write iterations");
        config_write_string("username", username).expect("write username");
        config_write_encrypted_string("verify", VERIFY_STRING, &key).expect("write verify");
        config_write_buffer("plaintext_key", b"bad").expect("write invalid plaintext key");

        crate::lpenv::set_override_for_tests("LPASS_ASKPASS", &askpass.display().to_string());
        crate::lpenv::set_override_for_tests("LPASS_AGENT_DISABLE", "1");

        let got = agent_get_decryption_key().expect("load via askpass");
        assert_eq!(got, key);
        assert!(!config_exists("plaintext_key"));
    }

    #[test]
    fn agent_load_on_disk_key_reports_missing_username_and_verify() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));

        config_write_string("iterations", "2").expect("write iterations");
        let err = agent_load_on_disk_key().expect_err("missing username");
        assert!(format!("{err}").contains("missing username"));

        config_write_string("username", "user@example.com").expect("write username");
        let err = agent_load_on_disk_key().expect_err("missing verify");
        assert!(format!("{err}").contains("missing verify"));
    }

    #[test]
    fn agent_get_decryption_key_uses_running_agent_socket() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));
        let socket = agent_socket_path().expect("socket path");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let expected_key = [11u8; KDF_HASH_LEN];

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
            {
                let mut pid = [0u8; 4];
                stream.read_exact(&mut pid).expect("read pid");
                stream.write_all(&pid).expect("write pid");
            }
            stream.write_all(&expected_key).expect("write key");
        });

        let got = agent_get_decryption_key().expect("load key via agent");
        assert_eq!(got, expected_key);
        server.join().expect("join server");
        let _ = std::fs::remove_file(socket);
    }

    #[test]
    fn agent_is_available_true_when_agent_socket_responds() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));
        let socket = agent_socket_path().expect("socket path");
        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let expected_key = [12u8; KDF_HASH_LEN];

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
            {
                let mut pid = [0u8; 4];
                stream.read_exact(&mut pid).expect("read pid");
                stream.write_all(&pid).expect("write pid");
            }
            stream.write_all(&expected_key).expect("write key");
        });

        assert!(agent_is_available());
        server.join().expect("join server");
        let _ = std::fs::remove_file(socket);
    }

    #[test]
    fn agent_is_available_checks_plaintext_key_validity() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));

        let key = [4u8; KDF_HASH_LEN];
        config_write_buffer("plaintext_key", &key).expect("write key");
        config_write_encrypted_string("verify", VERIFY_STRING, &key).expect("write verify");
        assert!(agent_is_available());

        config_write_buffer("plaintext_key", b"bad").expect("write invalid key");
        assert!(!agent_is_available());
    }

    #[test]
    fn handle_client_writes_pid_and_key_over_stream_pair() {
        let key = [5u8; KDF_HASH_LEN];
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let worker = std::thread::spawn(move || handle_client(server, &key));

        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "cygwin")))]
        {
            client
                .write_all(&1234u32.to_ne_bytes())
                .expect("write pid request");
            let mut pid = [0u8; 4];
            client.read_exact(&mut pid).expect("read pid response");
            assert!(u32::from_ne_bytes(pid) > 0);
        }

        let mut got = [0u8; KDF_HASH_LEN];
        client.read_exact(&mut got).expect("read key");
        assert_eq!(got, key);
        worker.join().expect("join").expect("handle client");
    }

    #[test]
    fn read_pid_reports_truncated_payload() {
        let (mut writer, mut reader) = UnixStream::pair().expect("socket pair");
        writer.write_all(&[1u8]).expect("write short pid");
        drop(writer);

        let err = read_pid(&mut reader).expect_err("must fail");
        assert!(format!("{err}").contains("read pid"));
    }

    #[test]
    fn agent_ask_and_agent_kill_handle_missing_socket() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let temp = short_tempdir();
        let _config_guard = set_test_env(test_config_env(&temp));

        let err = agent_ask().expect_err("missing socket should fail");
        assert!(format!("{err}").contains("connect"));
        agent_kill().expect("kill without socket should be ok");
    }
}
