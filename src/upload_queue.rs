#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::commands::data::refresh_blob_from_server;
use crate::config::{ConfigStore, config_read_string, config_unlink};
use crate::error::{LpassError, Result};
use crate::http::HttpClient;
use crate::kdf::KDF_HASH_LEN;
use crate::session::{Session, session_load};

const UPLOAD_QUEUE_ARG: &str = "__upload-queue";
const QUEUE_DIR: &str = "upload-queue";
const FAIL_DIR: &str = "upload-fail";
const PID_NAME: &str = "uploader.pid";
const WAIT_INTERVAL: Duration = Duration::from_millis(333);
#[cfg(not(test))]
const MAX_RETRIES: usize = 5;
#[cfg(test)]
const MAX_RETRIES: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct QueueRequest {
    page: String,
    params: Vec<(String, String)>,
}

struct PidCleanup;

impl Drop for PidCleanup {
    fn drop(&mut self) {
        let _ = config_unlink(PID_NAME);
    }
}

pub fn maybe_run_uploader(args: &[String]) -> Option<i32> {
    let arg = args.get(1)?;
    if arg != UPLOAD_QUEUE_ARG {
        return None;
    }

    match read_key_from_stdin().and_then(|key| run_pending_from_disk(&key)) {
        Ok(()) => Some(0),
        Err(err) => {
            eprintln!("error: {err}");
            Some(1)
        }
    }
}

pub(crate) fn enqueue(
    key: &[u8; KDF_HASH_LEN],
    page: &str,
    params: Vec<(String, String)>,
    start_immediately: bool,
) -> Result<()> {
    enqueue_with_store(
        &ConfigStore::from_current(),
        key,
        QueueRequest {
            page: page.to_string(),
            params,
        },
        start_immediately,
    )
}

pub(crate) fn enqueue_with_store(
    store: &ConfigStore,
    key: &[u8; KDF_HASH_LEN],
    request: QueueRequest,
    start_immediately: bool,
) -> Result<()> {
    let name = next_queue_entry_name(store)?;
    let buffer =
        serde_json::to_vec(&request).map_err(|_| LpassError::Crypto("invalid upload queue"))?;
    store.write_encrypted_buffer(&name, &buffer, key)?;
    if start_immediately {
        ensure_running(key)?;
    }
    Ok(())
}

pub(crate) fn ensure_running(key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    if is_running() {
        return Ok(());
    }

    let _ = config_unlink(PID_NAME);
    let exe = env::current_exe().map_err(|err| LpassError::io("current_exe", err))?;
    let mut child = Command::new(exe)
        .arg(UPLOAD_QUEUE_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| LpassError::io("spawn uploader", err))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(key)
            .map_err(|err| LpassError::io("write uploader key", err))?;
    }

    ConfigStore::from_current().write_string(PID_NAME, &child.id().to_string())
}

pub(crate) fn wait_for_completion() {
    while is_running() {
        thread::sleep(WAIT_INTERVAL);
    }
}

pub(crate) fn is_running() -> bool {
    let Some(pid) = read_pid() else {
        return false;
    };
    let running = process_exists(pid);
    if !running {
        let _ = config_unlink(PID_NAME);
    }
    running
}

pub(crate) fn kill() -> Result<()> {
    if let Some(pid) = read_pid() {
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
        }
    }

    config_unlink(PID_NAME).map(|_| ())
}

pub(crate) fn process_pending(key: &[u8; KDF_HASH_LEN], session: &Session) -> Result<()> {
    let client = HttpClient::from_env()?;
    process_pending_with_client(&ConfigStore::from_current(), &client, session, key)
}

pub(crate) fn process_pending_with_client(
    store: &ConfigStore,
    client: &HttpClient,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<()> {
    let mut should_refresh = false;

    while let Some(name) = oldest_queue_entry_name(store)? {
        let queue_name = format!("{QUEUE_DIR}/{name}");
        let request = match store.read_encrypted_buffer(&queue_name, key)? {
            Some(buffer) => match serde_json::from_slice::<QueueRequest>(&buffer) {
                Ok(request) => request,
                Err(_) => {
                    let _ = store.unlink(&queue_name);
                    continue;
                }
            },
            None => continue,
        };

        if process_request(client, session, &request) {
            let _ = store.unlink(&queue_name);
            should_refresh |= request.page != "loglogin.php";
        } else {
            move_failed_entry(store, &name)?;
        }
    }

    if should_refresh {
        let _ = refresh_blob_from_server(client, session, key);
    }

    Ok(())
}

fn run_pending_from_disk(key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    let _pid_guard = PidCleanup;
    let session = session_load(key)?.ok_or(LpassError::User(
        "Could not find session. Perhaps you need to login with `lpass login`.",
    ))?;
    process_pending(key, &session)
}

fn process_request(client: &HttpClient, session: &Session, request: &QueueRequest) -> bool {
    let params_ref: Vec<(&str, &str)> = request
        .params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();

    let mut backoff = 1;
    let mut backoff_scale = 8;

    for attempt in 0..MAX_RETRIES {
        if attempt > 0 {
            sleep_backoff(backoff);
            backoff = backoff.saturating_mul(backoff_scale);
        }

        match client.post_lastpass(None, &request.page, Some(session), &params_ref) {
            Ok(response) if response.status < 400 => return true,
            Ok(response) if response.status == 500 => backoff_scale = 2,
            Ok(_) => {}
            Err(_) => {}
        }
    }

    false
}

#[cfg(not(test))]
fn sleep_backoff(seconds: u64) {
    thread::sleep(Duration::from_secs(seconds));
}

#[cfg(test)]
fn sleep_backoff(_seconds: u64) {}

fn next_queue_entry_name(store: &ConfigStore) -> Result<String> {
    let serial_base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let _ = queue_dir(store, QUEUE_DIR)?;
    for serial in 0..10_000u64 {
        let name = format!("{QUEUE_DIR}/{serial_base}{serial:04}");
        if !store.exists(&name) {
            return Ok(name);
        }
    }

    Err(LpassError::User(
        "No more upload queue entry slots available.",
    ))
}

fn oldest_queue_entry_name(store: &ConfigStore) -> Result<Option<String>> {
    let dir = queue_dir(store, QUEUE_DIR)?;
    let mut names: Vec<String> = fs::read_dir(dir)
        .map_err(|err| LpassError::io("read_dir", err))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        .collect();
    names.sort();
    Ok(names.into_iter().next())
}

fn move_failed_entry(store: &ConfigStore, name: &str) -> Result<()> {
    let src = store.path(&format!("{QUEUE_DIR}/{name}"))?;
    let _ = queue_dir(store, FAIL_DIR)?;
    let dst = store.path(&format!("{FAIL_DIR}/{name}"))?;

    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(LpassError::io("rename", err)),
    }
}

fn queue_dir(store: &ConfigStore, name: &str) -> Result<PathBuf> {
    let marker = store.path(&format!("{name}/.marker"))?;
    Ok(marker
        .parent()
        .expect("queue marker should have a parent")
        .to_path_buf())
}

fn read_key_from_stdin() -> Result<[u8; KDF_HASH_LEN]> {
    let mut key = [0u8; KDF_HASH_LEN];
    std::io::stdin()
        .read_exact(&mut key)
        .map_err(|err| LpassError::io("read uploader key", err))?;
    Ok(key)
}

fn read_pid() -> Option<i32> {
    config_read_string(PID_NAME)
        .ok()
        .flatten()
        .and_then(|value| value.trim().parse::<i32>().ok())
        .filter(|pid| *pid > 0)
}

#[cfg(unix)]
fn process_exists(pid: i32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    match kill(Pid::from_raw(pid), None) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn process_exists(_pid: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigEnv, set_test_env};
    use crate::session::session_save_with_store;
    use tempfile::TempDir;

    fn store_with_home() -> (ConfigStore, TempDir) {
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        (store, temp)
    }

    fn session() -> Session {
        Session {
            uid: "u1".to_string(),
            session_id: "s1".to_string(),
            token: "tok".to_string(),
            url_encryption_enabled: false,
            url_logging_enabled: false,
            server: None,
            private_key: None,
            private_key_enc: None,
        }
    }

    fn minimal_blob_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"LPAV");
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(b"1");
        bytes
    }

    #[test]
    fn enqueue_writes_encrypted_queue_entry() {
        let (store, _temp) = store_with_home();
        let key = [7u8; KDF_HASH_LEN];
        enqueue_with_store(
            &store,
            &key,
            QueueRequest {
                page: "loglogin.php".to_string(),
                params: vec![("id".to_string(), "1".to_string())],
            },
            false,
        )
        .expect("enqueue");

        let name = oldest_queue_entry_name(&store)
            .expect("read queue")
            .expect("queued entry");
        let entry = store
            .read_encrypted_buffer(&format!("{QUEUE_DIR}/{name}"), &key)
            .expect("read encrypted")
            .expect("entry bytes");
        let request: QueueRequest = serde_json::from_slice(&entry).expect("decode request");
        assert_eq!(request.page, "loglogin.php");
    }

    #[test]
    fn enqueue_with_start_immediately_reuses_running_uploader() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [1u8; KDF_HASH_LEN];
        store
            .write_string(PID_NAME, &std::process::id().to_string())
            .expect("write pid");

        enqueue_with_store(
            &store,
            &key,
            QueueRequest {
                page: "loglogin.php".to_string(),
                params: vec![("id".to_string(), "42".to_string())],
            },
            true,
        )
        .expect("enqueue");

        assert_eq!(read_pid(), Some(std::process::id() as i32));
    }

    #[test]
    fn process_pending_with_client_clears_successful_entries() {
        let (store, _temp) = store_with_home();
        let key = [8u8; KDF_HASH_LEN];
        let session = session();
        session_save_with_store(&store, &session, &key).expect("save session");

        enqueue_with_store(
            &store,
            &key,
            QueueRequest {
                page: "loglogin.php".to_string(),
                params: vec![("id".to_string(), "1".to_string())],
            },
            false,
        )
        .expect("enqueue");

        process_pending_with_client(&store, &HttpClient::mock(), &session, &key).expect("process");
        assert!(
            oldest_queue_entry_name(&store)
                .expect("read queue")
                .is_none()
        );
    }

    #[test]
    fn process_pending_drops_invalid_queue_entries() {
        let (store, _temp) = store_with_home();
        let key = [2u8; KDF_HASH_LEN];
        store
            .write_encrypted_buffer("upload-queue/100", b"not-json", &key)
            .expect("write queue");

        process_pending_with_client(&store, &HttpClient::mock(), &session(), &key).expect("drop");

        assert!(
            store
                .read_buffer("upload-queue/100")
                .expect("read queue file")
                .is_none()
        );
    }

    #[test]
    fn process_pending_refreshes_blob_after_non_loglogin_success() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [3u8; KDF_HASH_LEN];
        let session = session();
        let blob = String::from_utf8(minimal_blob_bytes()).expect("blob string");
        let client = HttpClient::mock_with_overrides(&[
            ("show_website.php", 200, "ok"),
            ("getaccts.php", 200, &blob),
        ]);

        enqueue_with_store(
            &store,
            &key,
            QueueRequest {
                page: "show_website.php".to_string(),
                params: vec![("aid".to_string(), "1".to_string())],
            },
            false,
        )
        .expect("enqueue");

        process_pending_with_client(&store, &client, &session, &key).expect("process");

        let stored = store
            .read_encrypted_buffer("blob", &key)
            .expect("read blob")
            .expect("blob written");
        assert_eq!(stored, minimal_blob_bytes());
    }

    #[test]
    fn process_pending_moves_failed_entries_into_fail_dir() {
        let (store, _temp) = store_with_home();
        let key = [9u8; KDF_HASH_LEN];
        let mut session = session();
        session.server = Some("127.0.0.1:1".to_string());

        enqueue_with_store(
            &store,
            &key,
            QueueRequest {
                page: "loglogin.php".to_string(),
                params: Vec::new(),
            },
            false,
        )
        .expect("enqueue");

        let dir = queue_dir(&store, FAIL_DIR).expect("fail dir");
        let client = HttpClient::real().expect("real client");
        process_pending_with_client(&store, &client, &session, &key).expect("process");
        let entries: Vec<_> = fs::read_dir(dir)
            .expect("read fail dir")
            .filter_map(|entry| entry.ok())
            .collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn process_request_retries_on_http_500_and_returns_false() {
        let session = session();
        let request = QueueRequest {
            page: "show_website.php".to_string(),
            params: Vec::new(),
        };
        let client = HttpClient::mock_with_overrides(&[
            ("show_website.php", 500, "fail"),
            ("show_website.php", 500, "fail"),
        ]);

        assert!(!process_request(&client, &session, &request));
    }

    #[test]
    fn process_request_returns_false_for_other_http_errors() {
        let session = session();
        let request = QueueRequest {
            page: "show_website.php".to_string(),
            params: Vec::new(),
        };
        let client = HttpClient::mock_with_overrides(&[
            ("show_website.php", 404, "missing"),
            ("show_website.php", 404, "missing"),
        ]);

        assert!(!process_request(&client, &session, &request));
    }

    #[test]
    fn queue_dir_creates_nested_directory() {
        let (store, _temp) = store_with_home();
        let dir = queue_dir(&store, QUEUE_DIR).expect("queue dir");
        assert!(dir.is_dir());
    }

    #[test]
    fn ensure_running_returns_when_pid_is_already_live() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [4u8; KDF_HASH_LEN];
        store
            .write_string(PID_NAME, &std::process::id().to_string())
            .expect("write pid");

        ensure_running(&key).expect("reuse running uploader");
        assert_eq!(read_pid(), Some(std::process::id() as i32));
    }

    #[test]
    fn run_pending_from_disk_requires_session_and_cleans_pid() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [5u8; KDF_HASH_LEN];
        store.write_string(PID_NAME, "123").expect("write pid");

        let err = run_pending_from_disk(&key).expect_err("missing session");
        assert!(format!("{err}").contains("Could not find session"));
        assert!(read_pid().is_none());
    }

    #[test]
    fn run_pending_from_disk_processes_saved_session() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");

        let key = [6u8; KDF_HASH_LEN];
        let session = session();
        session_save_with_store(&store, &session, &key).expect("save session");
        enqueue_with_store(
            &store,
            &key,
            QueueRequest {
                page: "loglogin.php".to_string(),
                params: vec![("id".to_string(), "1".to_string())],
            },
            false,
        )
        .expect("enqueue");

        run_pending_from_disk(&key).expect("run pending");
        assert!(oldest_queue_entry_name(&store).expect("queue").is_none());
    }

    #[test]
    fn move_failed_entry_ignores_missing_source() {
        let (store, _temp) = store_with_home();
        move_failed_entry(&store, "does-not-exist").expect("missing source is ignored");
    }

    #[test]
    fn read_pid_ignores_invalid_values() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        store.write_string(PID_NAME, "abc").expect("write pid");
        assert_eq!(read_pid(), None);
    }

    #[test]
    fn is_running_cleans_up_stale_pid_file() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        store
            .write_string(PID_NAME, "2147483647")
            .expect("write pid");

        assert!(!is_running());
        assert!(read_pid().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn wait_for_completion_and_kill_manage_pid_files() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let mut short_child = std::process::Command::new("sleep")
            .arg("0.2")
            .spawn()
            .expect("spawn short child");
        let short_pid = short_child.id();
        let short_waiter = std::thread::spawn(move || {
            let _ = short_child.wait();
        });
        store
            .write_string(PID_NAME, &short_pid.to_string())
            .expect("write short pid");
        wait_for_completion();
        let _ = short_waiter.join();
        assert!(read_pid().is_none());

        let mut long_child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn long child");
        let long_pid = long_child.id();
        let long_waiter = std::thread::spawn(move || {
            let _ = long_child.wait();
        });
        store
            .write_string(PID_NAME, &long_pid.to_string())
            .expect("write long pid");
        kill().expect("kill child");
        let _ = long_waiter.join();
        assert!(read_pid().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn process_exists_detects_live_and_missing_processes() {
        assert!(process_exists(std::process::id() as i32));
        assert!(!process_exists(2147483647));
    }
}
