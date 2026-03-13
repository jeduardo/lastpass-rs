use super::*;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::{Arc, Once};
use std::thread;

use crate::session::Session;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

fn install_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn insecure_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent(user_agent())
        .build()
        .expect("client")
}

fn spawn_https_server(response: Vec<u8>) -> (String, thread::JoinHandle<()>) {
    install_crypto_provider();

    let cert = generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .expect("generate cert");
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept");
        let conn = ServerConnection::new(config).expect("server connection");
        let mut tls = StreamOwned::new(conn, tcp);
        let mut buf = [0u8; 4096];
        let _ = tls.read(&mut buf);
        tls.write_all(&response).expect("write response");
        tls.flush().expect("flush response");
    });
    (format!("127.0.0.1:{}", addr.port()), handle)
}

fn spawn_https_server_with_request_capture(
    response: Vec<u8>,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    install_crypto_provider();

    let cert = generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .expect("generate cert");
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (request_tx, request_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().expect("accept");
        let conn = ServerConnection::new(config).expect("server connection");
        let mut tls = StreamOwned::new(conn, tcp);
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let size = tls.read(&mut buf).expect("read request");
            if size == 0 {
                break;
            }
            request.extend_from_slice(&buf[..size]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        request_tx
            .send(String::from_utf8_lossy(&request).into_owned())
            .expect("send request");
        tls.write_all(&response).expect("write response");
        tls.flush().expect("flush response");
    });
    (format!("127.0.0.1:{}", addr.port()), request_rx, handle)
}

#[test]
fn mock_iterations() {
    let client = HttpClient::mock();
    let response = client
        .post_lastpass(
            None,
            "iterations.php",
            None,
            &[("email", "user@example.com")],
        )
        .expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body.trim(), "1000");
}

#[test]
fn mock_login_success() {
    let client = HttpClient::mock();
    let hash = kdf_login_key("user@example.com", "123456", 1000).expect("hash");
    let response = client
        .post_lastpass(
            None,
            "login.php",
            None,
            &[("username", "user@example.com"), ("hash", &hash)],
        )
        .expect("response");
    assert!(response.body.contains("<ok"));
}

#[test]
fn mock_login_failure() {
    let client = HttpClient::mock();
    let response = client
        .post_lastpass(
            None,
            "login.php",
            None,
            &[("username", "user@example.com"), ("hash", "bad")],
        )
        .expect("response");
    assert!(response.body.contains("invalid password"));
}

#[test]
fn mock_login_check_and_unknown_page_responses() {
    let client = HttpClient::mock();
    let ok = client
        .post_lastpass(None, "login_check.php", None, &[])
        .expect("response");
    assert!(ok.body.contains("accts_version"));

    let unknown = client
        .post_lastpass(None, "unknown.php", None, &[])
        .expect("response");
    assert!(unknown.body.contains("unimplemented"));
}

#[test]
fn post_lastpass_bytes_returns_raw_body() {
    let client = HttpClient::mock();
    let response = client
        .post_lastpass_bytes(None, "iterations.php", None, &[("email", "u@example.com")])
        .expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"1000".to_vec());
}

#[test]
fn mock_show_website_returns_empty_body() {
    let client = HttpClient::mock();
    let response = client
        .post_lastpass(None, "show_website.php", None, &[])
        .expect("response");
    assert_eq!(response.status, 200);
    assert!(response.body.is_empty());
}

#[test]
fn free_post_lastpass_wrapper_uses_mock_transport_from_env() {
    let _guard = crate::lpenv::begin_test_overrides();
    crate::lpenv::set_override_for_tests("LPASS_HTTP_MOCK", "1");
    let response = super::post_lastpass("iterations.php", None, &[("email", "u@example.com")])
        .expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "1000");
}

#[test]
fn mock_getattach_handles_missing_and_unknown_storage_keys() {
    let client = HttpClient::mock();

    let missing = client
        .post_lastpass(None, "getattach.php", None, &[])
        .expect("response");
    assert_eq!(missing.status, 200);
    assert!(missing.body.is_empty());

    let unknown = client
        .post_lastpass(
            None,
            "getattach.php",
            None,
            &[("getattach", "does-not-exist")],
        )
        .expect("response");
    assert_eq!(unknown.status, 200);
    assert!(unknown.body.is_empty());
}

#[test]
fn mock_getattach_known_keys_return_encrypted_payloads() {
    let client = HttpClient::mock();
    let text = client
        .post_lastpass(
            None,
            "getattach.php",
            None,
            &[("getattach", MOCK_ATTACH_STORAGE_KEY_TEXT)],
        )
        .expect("response");
    assert!(!text.body.is_empty());

    let bin = client
        .post_lastpass(
            None,
            "getattach.php",
            None,
            &[("getattach", MOCK_ATTACH_STORAGE_KEY_BIN)],
        )
        .expect("response");
    assert!(!bin.body.is_empty());

    let empty_json = client
        .post_lastpass(
            None,
            "getattach.php",
            None,
            &[("getattach", MOCK_ATTACH_STORAGE_KEY_EMPTY_JSON)],
        )
        .expect("response");
    assert_eq!(empty_json.body, "\"\"");
}

#[test]
fn params_to_map_keeps_all_pairs() {
    let map = params_to_map(&[("a", "1"), ("b", "2")]);
    assert_eq!(map.get("a").map(String::as_str), Some("1"));
    assert_eq!(map.get("b").map(String::as_str), Some("2"));
}

#[test]
fn user_agent_contains_crate_version() {
    let ua = user_agent();
    assert!(ua.starts_with("LastPass-CLI/"));
    assert!(ua.contains(crate::version::generated_version()));
}

#[test]
fn escape_xml_attr_escapes_xml_specials_and_control_whitespace() {
    let escaped = escape_xml_attr("&<>\"\n\r\tplain");
    assert_eq!(escaped, "&amp;&lt;&gt;&quot;&#10;&#13;&#9;plain");
}

#[test]
fn escape_xml_attr_preserves_empty_and_plain_text() {
    assert_eq!(escape_xml_attr(""), "");
    assert_eq!(escape_xml_attr("plain"), "plain");
}

#[test]
fn map_build_client_error_returns_crypto_error() {
    let err = Client::builder()
        .user_agent("\n")
        .build()
        .expect_err("builder must reject invalid user agent");
    let mapped = map_build_client_error(err);
    assert!(matches!(
        mapped,
        LpassError::Crypto("failed to build http client")
    ));
}

#[test]
fn mock_with_overrides_returns_custom_responses_in_sequence() {
    let client = HttpClient::mock_with_overrides(&[
        ("lastpass/api.php", 500, "first"),
        ("lastpass/api.php", 200, "second"),
    ]);

    let first = client
        .post_lastpass(None, "lastpass/api.php", None, &[])
        .expect("first");
    assert_eq!(first.status, 500);
    assert_eq!(first.body, "first");

    let second = client
        .post_lastpass(None, "lastpass/api.php", None, &[])
        .expect("second");
    assert_eq!(second.status, 200);
    assert_eq!(second.body, "second");
}

#[test]
fn mock_lastpass_api_returns_fail_without_uploadaccounts_cmd() {
    let client = HttpClient::mock();
    let response = client
        .post_lastpass(None, "lastpass/api.php", None, &[("cmd", "other")])
        .expect("response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "<lastpass rc=\"FAIL\"><error/></lastpass>");
}

#[test]
fn lock_overrides_recovers_from_poisoned_mutex() {
    let transport = MockTransport::new();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = transport.overrides.lock().expect("lock");
        panic!("poison");
    }));

    {
        let mut map = lock_overrides(transport.overrides.lock());
        map.insert(
            "page".to_string(),
            VecDeque::from([HttpResponse {
                status: 200,
                body: "ok".to_string(),
            }]),
        );
    }

    let response = transport
        .override_response("page")
        .expect("override response");
    assert_eq!(response.body, "ok");
}

#[test]
fn real_client_can_be_constructed() {
    let client = HttpClient::real().expect("client");
    assert!(client.is_real_transport());
}

#[test]
fn mock_client_reports_mock_transport() {
    assert!(!HttpClient::mock().is_real_transport());
}

#[test]
fn post_real_returns_io_error_when_request_fails() {
    let client = Client::builder()
        .user_agent(user_agent())
        .build()
        .expect("client");
    let err = post_real(
        &client,
        Some("127.0.0.1:1"),
        "login.php",
        None,
        &[("k", "v")],
    )
    .expect_err("request must fail");
    assert!(matches!(
        err,
        LpassError::Io {
            context: "http post",
            ..
        }
    ));
}

impl HttpClient {
    fn is_real_transport(&self) -> bool {
        match self.transport {
            Transport::Real(_) => true,
            Transport::Mock(_) => false,
        }
    }
}

#[test]
fn post_real_returns_response_body_on_success() {
    let (server, handle) =
        spawn_https_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec());
    let client = insecure_client();

    let response = post_real(&client, Some(&server), "login.php", None, &[("k", "v")])
        .expect("request should succeed");
    handle.join().expect("join server");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "ok");
}

#[test]
fn post_real_includes_cookie_header_when_session_has_session_id() {
    let (server, request_rx, handle) = spawn_https_server_with_request_capture(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
    );
    let client = insecure_client();
    let session = Session {
        session_id: "session-123".to_string(),
        ..Session::default()
    };

    let response = post_real(
        &client,
        Some(&server),
        "login.php",
        Some(&session),
        &[("k", "v")],
    )
    .expect("request should succeed");
    let request = request_rx.recv().expect("captured request");
    handle.join().expect("join server");

    assert_eq!(response.status, 200);
    assert!(
        request
            .to_ascii_lowercase()
            .contains("cookie: phpsessid=session-123")
    );
}

#[test]
fn post_real_reports_read_errors_after_successful_send() {
    let (server, handle) =
        spawn_https_server(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort".to_vec());
    let client = insecure_client();

    let err = post_real(&client, Some(&server), "login.php", None, &[("k", "v")])
        .expect_err("body read should fail");
    handle.join().expect("join server");

    assert!(matches!(
        err,
        LpassError::Io {
            context: "http read",
            ..
        }
    ));
}

#[test]
fn post_real_bytes_returns_io_error_when_request_fails() {
    let client = Client::builder()
        .user_agent(user_agent())
        .build()
        .expect("client");
    let err = post_real_bytes(
        &client,
        Some("127.0.0.1:1"),
        "login.php",
        None,
        &[("k", "v")],
    )
    .expect_err("request must fail");
    assert!(matches!(
        err,
        LpassError::Io {
            context: "http post",
            ..
        }
    ));
}

#[test]
fn post_real_bytes_returns_response_body_on_success() {
    let (server, handle) =
        spawn_https_server(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\x00\x01ok".to_vec());
    let client = insecure_client();

    let response = post_real_bytes(&client, Some(&server), "login.php", None, &[("k", "v")])
        .expect("request should succeed");
    handle.join().expect("join server");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"\x00\x01ok".to_vec());
}

#[test]
fn post_real_bytes_includes_cookie_header_when_session_has_session_id() {
    let (server, request_rx, handle) = spawn_https_server_with_request_capture(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\x00\x01ok".to_vec(),
    );
    let client = insecure_client();
    let session = Session {
        session_id: "session-456".to_string(),
        ..Session::default()
    };

    let response = post_real_bytes(
        &client,
        Some(&server),
        "login.php",
        Some(&session),
        &[("k", "v")],
    )
    .expect("request should succeed");
    let request = request_rx.recv().expect("captured request");
    handle.join().expect("join server");

    assert_eq!(response.status, 200);
    assert!(
        request
            .to_ascii_lowercase()
            .contains("cookie: phpsessid=session-456")
    );
}

#[test]
fn post_real_bytes_reports_read_errors_after_successful_send() {
    let (server, handle) =
        spawn_https_server(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort".to_vec());
    let client = insecure_client();

    let err = post_real_bytes(&client, Some(&server), "login.php", None, &[("k", "v")])
        .expect_err("body read should fail");
    handle.join().expect("join server");

    assert!(matches!(
        err,
        LpassError::Io {
            context: "http read",
            ..
        }
    ));
}
