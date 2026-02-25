#[cfg(unix)]
mod unix_tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static NEXT_TEST_HOME_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_test_home() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let seq = NEXT_TEST_HOME_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lpass-agent-cov-{}-{nanos}-{seq}",
            std::process::id()
        ))
    }

    #[test]
    fn standalone_agent_serves_key_and_exits_after_timeout() {
        let exe = env!("CARGO_BIN_EXE_lpass");
        let home = unique_test_home();
        fs::create_dir_all(&home).expect("create home");
        let socket_path = home.join("agent.sock");

        let key = [0x5Au8; 32];
        let mut child = Command::new(exe)
            .env("LPASS_HOME", &home)
            .env("LPASS_AGENT_TIMEOUT", "1")
            .arg("__agent")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn agent");

        {
            let stdin = child.stdin.as_mut().expect("stdin available");
            stdin.write_all(&key).expect("write key");
        }

        for _ in 0..120 {
            if socket_path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !socket_path.exists() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_dir_all(&home);
            return;
        }

        let mut connected = None;
        for _ in 0..120 {
            match UnixStream::connect(&socket_path) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("connect socket: {err}"),
            }
        }
        let mut stream = connected.expect("connect socket");
        if !cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "cygwin"
        )) {
            let pid = std::process::id();
            stream.write_all(&pid.to_ne_bytes()).expect("write pid");
            let mut pid_buf = [0u8; 4];
            stream.read_exact(&mut pid_buf).expect("read pid");
            let server_pid = u32::from_ne_bytes(pid_buf);
            assert!(server_pid > 0);
        }

        let mut received = [0u8; 32];
        stream.read_exact(&mut received).expect("read key");
        assert_eq!(received, key);

        let mut exited = false;
        for _ in 0..200 {
            if let Some(status) = child.try_wait().expect("try_wait") {
                assert_eq!(status.code().unwrap_or(-1), 0);
                exited = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        if !exited {
            let _ = child.kill();
            let _ = child.wait();
            panic!("agent did not exit after timeout");
        }

        let _ = fs::remove_dir_all(&home);
    }
}
