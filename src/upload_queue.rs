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
    let mut stdin = std::io::stdin();
    let mut stderr = std::io::stderr();
    maybe_run_uploader_with(args, &mut stdin, &mut stderr)
}

fn maybe_run_uploader_with<R: Read, W: Write>(
    args: &[String],
    reader: &mut R,
    stderr: &mut W,
) -> Option<i32> {
    let arg = args.get(1)?;
    if arg != UPLOAD_QUEUE_ARG {
        return None;
    }

    let outcome = match read_key(reader) {
        Ok(key) => run_pending_from_disk(&key),
        Err(err) => Err(err),
    };
    match outcome {
        Ok(()) => Some(0),
        Err(err) => {
            let _ = writeln!(stderr, "{}", crate::terminal::cli_failure_text(&err.to_string()));
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
    let buffer = serialize_queue_request(&request);
    store.write_encrypted_buffer(&name, &buffer, key)?;
    if start_immediately {
        ensure_running(key)?;
    }
    Ok(())
}

pub(crate) fn ensure_running(key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    ensure_running_with_launcher(&ConfigStore::from_current(), key, || {
        let exe = env::current_exe()?;
        let mut command = Command::new(exe);
        command.arg(UPLOAD_QUEUE_ARG);
        Ok(command)
    })
}

fn ensure_running_with_launcher<F>(
    store: &ConfigStore,
    key: &[u8; KDF_HASH_LEN],
    launcher: F,
) -> Result<()>
where
    F: FnOnce() -> std::io::Result<Command>,
{
    if is_running() {
        return Ok(());
    }

    let _ = config_unlink(PID_NAME);
    let mut command = launcher_command(launcher)?;
    let mut child = spawn_uploader(&mut command)?;

    write_uploader_key(child.stdin.take(), key)?;

    store.write_string(PID_NAME, &child.id().to_string())
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

    config_unlink(PID_NAME)?;
    Ok(())
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
        let Some(request) = load_queue_request(store, &queue_name, key)? else {
            continue;
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

fn write_uploader_key<W: Write>(sink: Option<W>, key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    let Some(mut sink) = sink else {
        return Ok(());
    };
    match sink.write_all(key) {
        Ok(()) => Ok(()),
        Err(err) => Err(LpassError::io("write uploader key", err)),
    }
}

fn serialize_queue_request(request: &QueueRequest) -> Vec<u8> {
    serde_json::to_vec(request).expect("QueueRequest serialization should not fail")
}

fn launcher_command<F>(launcher: F) -> Result<Command>
where
    F: FnOnce() -> std::io::Result<Command>,
{
    match launcher() {
        Ok(command) => Ok(command),
        Err(err) => Err(LpassError::io("current_exe", err)),
    }
}

fn spawn_uploader(command: &mut Command) -> Result<std::process::Child> {
    command.stdin(Stdio::piped());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    match command.spawn() {
        Ok(child) => Ok(child),
        Err(err) => Err(LpassError::io("spawn uploader", err)),
    }
}

fn load_queue_request(
    store: &ConfigStore,
    queue_name: &str,
    key: &[u8; KDF_HASH_LEN],
) -> Result<Option<QueueRequest>> {
    match store.read_encrypted_buffer(queue_name, key)? {
        Some(buffer) => match serde_json::from_slice::<QueueRequest>(&buffer) {
            Ok(request) => Ok(Some(request)),
            Err(_) => {
                let _ = store.unlink(queue_name);
                Ok(None)
            }
        },
        None => Ok(None),
    }
}

fn run_pending_from_disk(key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    let _pid_guard = PidCleanup;
    let session = require_session(session_load(key)?)?;
    process_pending(key, &session)
}

fn process_request(client: &HttpClient, session: &Session, request: &QueueRequest) -> bool {
    let mut params_ref = Vec::with_capacity(request.params.len());
    for (name, value) in &request.params {
        params_ref.push((name.as_str(), value.as_str()));
    }

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

fn sleep_backoff(seconds: u64) {
    #[cfg(test)]
    let seconds = seconds.saturating_sub(seconds);
    thread::sleep(Duration::from_secs(seconds));
}

fn next_queue_entry_name(store: &ConfigStore) -> Result<String> {
    let serial_base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    next_queue_entry_name_with(store, serial_base, 10_000)
}

fn next_queue_entry_name_with(
    store: &ConfigStore,
    serial_base: u64,
    max_serial: u64,
) -> Result<String> {
    let _ = queue_dir(store, QUEUE_DIR)?;
    for serial in 0..max_serial {
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
    let mut entry_names = Vec::new();
    for entry in read_queue_dir(dir)? {
        entry_names.push(dir_entry_name(entry));
    }
    let mut names = collect_valid_queue_names(entry_names);
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

fn require_session(session: Option<Session>) -> Result<Session> {
    session.ok_or(LpassError::User(
        "Could not find session. Perhaps you need to login with `lpass login`.",
    ))
}

fn read_queue_dir(path: PathBuf) -> Result<fs::ReadDir> {
    match fs::read_dir(path) {
        Ok(entries) => Ok(entries),
        Err(err) => Err(LpassError::io("read_dir", err)),
    }
}

fn dir_entry_name(entry: std::io::Result<fs::DirEntry>) -> Option<String> {
    match entry {
        Ok(entry) => os_string_name(entry.file_name()),
        Err(_) => None,
    }
}

fn os_string_name(name: std::ffi::OsString) -> Option<String> {
    name.into_string().ok()
}

fn collect_valid_queue_names<I>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = Option<String>>,
{
    let mut collected = Vec::new();
    for name in names {
        let Some(name) = name else {
            continue;
        };
        if name.bytes().all(|byte| byte.is_ascii_digit()) {
            collected.push(name);
        }
    }
    collected
}

fn read_key<R: Read>(reader: &mut R) -> Result<[u8; KDF_HASH_LEN]> {
    let mut key = [0u8; KDF_HASH_LEN];
    match reader.read_exact(&mut key) {
        Ok(()) => {}
        Err(err) => return Err(LpassError::io("read uploader key", err)),
    }
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
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    process_exists_result(kill(Pid::from_raw(pid), None))
}

#[cfg(unix)]
fn process_exists_result(result: std::result::Result<(), nix::errno::Errno>) -> bool {
    use nix::errno::Errno;

    match result {
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
    use std::io::Cursor;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
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
    fn enqueue_wrapper_uses_current_store() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [8u8; KDF_HASH_LEN];
        enqueue(
            &key,
            "loglogin.php",
            vec![("id".to_string(), "2".to_string())],
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
        assert_eq!(request.params, vec![("id".to_string(), "2".to_string())]);
    }

    #[test]
    fn maybe_run_uploader_returns_none_for_non_uploader_commands() {
        assert_eq!(maybe_run_uploader(&[]), None);
        assert_eq!(
            maybe_run_uploader(&["lpass".to_string(), "status".to_string()]),
            None
        );
    }

    #[test]
    fn maybe_run_uploader_with_processes_queue_from_reader() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [7u8; KDF_HASH_LEN];
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

        let args = vec!["lpass".to_string(), UPLOAD_QUEUE_ARG.to_string()];
        let mut stdin = Cursor::new(key.to_vec());
        let mut stderr = Vec::new();
        assert_eq!(
            maybe_run_uploader_with(&args, &mut stdin, &mut stderr),
            Some(0)
        );
        assert!(oldest_queue_entry_name(&store).expect("queue").is_none());
        assert!(stderr.is_empty());
    }

    #[test]
    fn maybe_run_uploader_with_reports_errors() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [6u8; KDF_HASH_LEN];
        let args = vec!["lpass".to_string(), UPLOAD_QUEUE_ARG.to_string()];
        let mut stdin = Cursor::new(key.to_vec());
        let mut stderr = Vec::new();

        assert_eq!(
            maybe_run_uploader_with(&args, &mut stdin, &mut stderr),
            Some(1)
        );
        assert!(oldest_queue_entry_name(&store).expect("queue").is_none());
        let stderr = String::from_utf8(stderr).expect("stderr utf8");
        assert!(stderr.contains("Could not find session"));
    }

    #[test]
    fn maybe_run_uploader_with_reports_short_key_errors() {
        let args = vec!["lpass".to_string(), UPLOAD_QUEUE_ARG.to_string()];
        let mut stdin = Cursor::new(vec![0u8; KDF_HASH_LEN - 1]);
        let mut stderr = Vec::new();

        assert_eq!(
            maybe_run_uploader_with(&args, &mut stdin, &mut stderr),
            Some(1)
        );
        let stderr = String::from_utf8(stderr).expect("stderr utf8");
        assert!(stderr.contains("read uploader key"));
    }

    #[test]
    fn write_uploader_key_ignores_missing_stdin() {
        let key = [1u8; KDF_HASH_LEN];
        write_uploader_key::<Vec<u8>>(None, &key).expect("no stdin");
    }

    #[test]
    fn write_uploader_key_reports_write_failures() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "writer closed",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let key = [1u8; KDF_HASH_LEN];
        let mut writer = FailingWriter;
        writer.flush().expect("flush");
        let err = write_uploader_key(Some(writer), &key).expect_err("write must fail");
        assert!(format!("{err}").contains("write uploader key"));
    }

    #[test]
    fn launcher_command_and_spawn_uploader_map_io_errors() {
        let err = launcher_command(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "missing executable",
            ))
        })
        .expect_err("launcher must fail");
        assert!(format!("{err}").contains("current_exe"));

        let mut command = Command::new("/definitely/missing/uploader");
        let err = spawn_uploader(&mut command).expect_err("spawn must fail");
        assert!(format!("{err}").contains("spawn uploader"));
    }

    #[test]
    fn serialize_require_and_read_dir_helpers_cover_error_paths() {
        let request = QueueRequest {
            page: "loglogin.php".to_string(),
            params: vec![("id".to_string(), "1".to_string())],
        };
        let buffer = serialize_queue_request(&request);
        let round_trip: QueueRequest = serde_json::from_slice(&buffer).expect("decode request");
        assert_eq!(round_trip, request);

        let err = require_session(None).expect_err("missing session");
        assert!(format!("{err}").contains("Could not find session"));

        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("not-a-dir");
        fs::write(&file, b"x").expect("write file");
        let err = read_queue_dir(file).expect_err("read_dir must fail");
        assert!(format!("{err}").contains("read_dir"));

        assert!(dir_entry_name(Err(std::io::Error::other("bad entry"))).is_none());
        #[cfg(unix)]
        assert!(os_string_name(std::ffi::OsString::from_vec(vec![0xff])).is_none());
    }

    #[test]
    fn read_key_reads_exact_bytes_and_reports_short_input() {
        let key = [2u8; KDF_HASH_LEN];
        let mut full = Cursor::new(key.to_vec());
        assert_eq!(read_key(&mut full).expect("read key"), key);

        let mut short = Cursor::new(vec![0u8; KDF_HASH_LEN - 1]);
        let err = read_key(&mut short).expect_err("short read must fail");
        assert!(format!("{err}").contains("read uploader key"));
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
    fn ensure_running_with_launcher_spawns_process_and_writes_pid() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [3u8; KDF_HASH_LEN];

        ensure_running_with_launcher(&store, &key, || {
            let mut command = Command::new("sh");
            command
                .arg("-c")
                .arg("dd of=/dev/null bs=32 count=1 >/dev/null 2>&1");
            Ok(command)
        })
        .expect("spawn uploader");

        assert!(read_pid().is_some());
        kill().expect("cleanup pid file");
    }

    #[test]
    fn ensure_running_covers_current_exe_launcher() {
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [4u8; KDF_HASH_LEN];

        let _ = ensure_running(&key);
        let _ = store;
        let _ = kill();
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
    fn process_pending_uses_http_client_from_env() {
        let _override_guard = crate::lpenv::begin_test_overrides();
        crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
        let (store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        let key = [9u8; KDF_HASH_LEN];
        let session = session();
        enqueue_with_store(
            &store,
            &key,
            QueueRequest {
                page: "loglogin.php".to_string(),
                params: vec![("id".to_string(), "3".to_string())],
            },
            false,
        )
        .expect("enqueue");

        process_pending(&key, &session).expect("process pending");
        assert!(oldest_queue_entry_name(&store).expect("queue").is_none());
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
    fn load_queue_request_returns_none_when_entry_disappears() {
        let (store, _temp) = store_with_home();
        let key = [2u8; KDF_HASH_LEN];
        assert!(
            load_queue_request(&store, "upload-queue/missing", &key)
                .expect("load queue request")
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
    fn next_queue_entry_name_reports_exhausted_slots() {
        let (store, _temp) = store_with_home();
        let dir = queue_dir(&store, QUEUE_DIR).expect("queue dir");
        fs::write(dir.join("100000"), b"x").expect("write entry");
        fs::write(dir.join("100001"), b"x").expect("write entry");

        let err = next_queue_entry_name_with(&store, 10, 2).expect_err("queue should be full");
        assert!(format!("{err}").contains("No more upload queue entry slots available."));
    }

    #[test]
    fn next_queue_entry_name_uses_current_time_prefix() {
        let (store, _temp) = store_with_home();
        let name = next_queue_entry_name(&store).expect("queue name");
        assert!(name.starts_with(&format!("{QUEUE_DIR}/")));
    }

    #[test]
    fn collect_valid_queue_names_skips_missing_and_non_numeric_entries() {
        let names =
            collect_valid_queue_names([None, Some("abc".to_string()), Some("123".to_string())]);
        assert_eq!(names, vec!["123".to_string()]);
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
    fn move_failed_entry_reports_rename_errors() {
        let (store, _temp) = store_with_home();
        let queue_path = queue_dir(&store, QUEUE_DIR).expect("queue dir");
        let fail_path = queue_dir(&store, FAIL_DIR).expect("fail dir");
        fs::write(queue_path.join("100"), b"entry").expect("write entry");
        fs::create_dir_all(fail_path.join("100")).expect("create blocking dir");

        let err = move_failed_entry(&store, "100").expect_err("rename should fail");
        assert!(format!("{err}").contains("IO error while rename"));
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
    fn is_running_returns_false_without_pid_file() {
        let (_store, temp) = store_with_home();
        let _config_guard = set_test_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        assert!(!is_running());
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

    #[test]
    #[cfg(unix)]
    fn process_exists_result_treats_eperm_as_running() {
        assert!(process_exists_result(Err(nix::errno::Errno::EPERM)));
    }
}
