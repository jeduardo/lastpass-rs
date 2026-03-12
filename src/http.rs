#![forbid(unsafe_code)]

use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use reqwest::blocking::Client;
use reqwest::header::{COOKIE, USER_AGENT};

use crate::crypto::{aes_encrypt_lastpass, base64_lastpass_encode};
use crate::error::{LpassError, Result};
use crate::kdf::kdf_login_key;
use crate::session::Session;

pub const LASTPASS_SERVER: &str = "lastpass.com";
const MOCK_ATTACH_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const MOCK_ATTACH_STORAGE_KEY_TEXT: &str = "mock-storage-0001-text";
const MOCK_ATTACH_STORAGE_KEY_BIN: &str = "mock-storage-0001-bin";
const MOCK_ATTACH_STORAGE_KEY_EMPTY_JSON: &str = "mock-storage-0001-empty-json";

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct HttpResponseBytes {
    pub status: u16,
    pub body: Vec<u8>,
}

enum Transport {
    Real(Client),
    Mock(MockTransport),
}

pub struct HttpClient {
    transport: Transport,
}

impl HttpClient {
    pub fn from_env() -> Result<Self> {
        if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
            Ok(Self::mock())
        } else {
            Self::real()
        }
    }

    pub fn real() -> Result<Self> {
        let client = Client::builder()
            .user_agent(user_agent())
            .gzip(false)
            .build()
            .map_err(map_build_client_error)?;
        Ok(Self {
            transport: Transport::Real(client),
        })
    }

    pub fn mock() -> Self {
        Self {
            transport: Transport::Mock(MockTransport::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn mock_with_overrides(overrides: &[(&str, u16, &str)]) -> Self {
        Self {
            transport: Transport::Mock(MockTransport::with_overrides(overrides)),
        }
    }

    pub fn post_lastpass(
        &self,
        server: Option<&str>,
        page: &str,
        session: Option<&Session>,
        params: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        match &self.transport {
            Transport::Real(client) => post_real(client, server, page, session, params),
            Transport::Mock(mock) => Ok(mock.respond(page, params)),
        }
    }

    pub fn post_lastpass_bytes(
        &self,
        server: Option<&str>,
        page: &str,
        session: Option<&Session>,
        params: &[(&str, &str)],
    ) -> Result<HttpResponseBytes> {
        match &self.transport {
            Transport::Real(client) => post_real_bytes(client, server, page, session, params),
            Transport::Mock(mock) => Ok(mock.respond_bytes(page, params)),
        }
    }
}

pub fn post_lastpass(
    page: &str,
    session: Option<&Session>,
    params: &[(&str, &str)],
) -> Result<HttpResponse> {
    let client = HttpClient::from_env()?;
    client.post_lastpass(None, page, session, params)
}

fn post_real(
    client: &Client,
    server: Option<&str>,
    page: &str,
    session: Option<&Session>,
    params: &[(&str, &str)],
) -> Result<HttpResponse> {
    let server = session
        .and_then(|session| session.server.as_deref())
        .or(server)
        .unwrap_or(LASTPASS_SERVER);
    let url = format!("https://{server}/{page}");

    let mut request = client.post(url).header(USER_AGENT, user_agent());
    if let Some(session) = session
        && !session.session_id.is_empty()
    {
        request = request.header(COOKIE, format!("PHPSESSID={}", session.session_id));
    }

    let response = request.form(&params).send().map_err(|_| LpassError::Io {
        context: "http post",
        source: std::io::Error::other("http request failed"),
    })?;

    let status = response.status().as_u16();
    let body = response.text().map_err(|_| LpassError::Io {
        context: "http read",
        source: std::io::Error::other("http response read failed"),
    })?;

    Ok(HttpResponse { status, body })
}

fn post_real_bytes(
    client: &Client,
    server: Option<&str>,
    page: &str,
    session: Option<&Session>,
    params: &[(&str, &str)],
) -> Result<HttpResponseBytes> {
    let server = session
        .and_then(|session| session.server.as_deref())
        .or(server)
        .unwrap_or(LASTPASS_SERVER);
    let url = format!("https://{server}/{page}");

    let mut request = client.post(url).header(USER_AGENT, user_agent());
    if let Some(session) = session
        && !session.session_id.is_empty()
    {
        request = request.header(COOKIE, format!("PHPSESSID={}", session.session_id));
    }

    let response = request.form(&params).send().map_err(|_| LpassError::Io {
        context: "http post",
        source: std::io::Error::other("http request failed"),
    })?;

    let status = response.status().as_u16();
    let body = response
        .bytes()
        .map_err(|_| LpassError::Io {
            context: "http read",
            source: std::io::Error::other("http response read failed"),
        })?
        .to_vec();

    Ok(HttpResponseBytes { status, body })
}

fn user_agent() -> String {
    format!("LastPass-CLI/{}", crate::version::generated_version())
}

fn map_build_client_error(_: reqwest::Error) -> LpassError {
    LpassError::Crypto("failed to build http client")
}

struct MockTransport {
    username: String,
    login_hash: String,
    iterations: u32,
    uid: String,
    #[cfg(test)]
    overrides: std::sync::Mutex<HashMap<String, VecDeque<HttpResponse>>>,
}

#[cfg(test)]
fn lock_overrides<'a>(
    result: std::sync::LockResult<
        std::sync::MutexGuard<'a, HashMap<String, VecDeque<HttpResponse>>>,
    >,
) -> std::sync::MutexGuard<'a, HashMap<String, VecDeque<HttpResponse>>> {
    match result {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl MockTransport {
    fn new() -> Self {
        let username = "user@example.com".to_string();
        let password = "123456";
        let iterations = 1000;
        let login_hash = mock_login_hash(&username, password, iterations);
        let uid = "57747756".to_string();
        Self {
            username,
            login_hash,
            iterations,
            uid,
            #[cfg(test)]
            overrides: std::sync::Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn with_overrides(overrides: &[(&str, u16, &str)]) -> Self {
        let transport = Self::new();
        let mut map = lock_overrides(transport.overrides.lock());
        for (page, status, body) in overrides {
            map.entry((*page).to_string())
                .or_insert_with(VecDeque::new)
                .push_back(HttpResponse {
                    status: *status,
                    body: (*body).to_string(),
                });
        }
        drop(map);
        transport
    }

    #[cfg(test)]
    fn override_response(&self, page: &str) -> Option<HttpResponse> {
        let mut map = lock_overrides(self.overrides.lock());
        let responses = map.get_mut(page)?;
        let response = responses.pop_front();
        if responses.is_empty() {
            map.remove(page);
        }
        response
    }

    fn respond(&self, page: &str, params: &[(&str, &str)]) -> HttpResponse {
        #[cfg(test)]
        if let Some(response) = self.override_response(page) {
            return response;
        }

        let map = params_to_map(params);
        let body = match page {
            "iterations.php" => self.iterations.to_string(),
            "login.php" => {
                let username = map.get("username").cloned().unwrap_or_default();
                let hash = map.get("hash").cloned().unwrap_or_default();
                if username == self.username && hash == self.login_hash {
                    format!(
                        "<response><ok uid=\"{}\" sessionid=\"1234\" token=\"abcd\"/></response>",
                        self.uid
                    )
                } else {
                    "<response><error message=\"invalid password\"/></response>".to_string()
                }
            }
            "login_check.php" => format!(
                "<response><ok uid=\"{}\" sessionid=\"1234\" token=\"abcd\" accts_version=\"123\"/></response>",
                self.uid
            ),
            "getaccts.php" => String::new(),
            "show_website.php" => String::new(),
            "loglogin.php" => String::new(),
            "lastpass/api.php" => {
                if map.get("cmd").map(String::as_str) == Some("uploadaccounts") {
                    "<lastpass rc=\"OK\"><ok/></lastpass>".to_string()
                } else {
                    "<lastpass rc=\"FAIL\"><error/></lastpass>".to_string()
                }
            }
            "getattach.php" => {
                let Some(storage_key) = map.get("getattach") else {
                    return HttpResponse {
                        status: 200,
                        body: String::new(),
                    };
                };
                if storage_key == MOCK_ATTACH_STORAGE_KEY_TEXT {
                    mock_attachment_ciphertext(b"demo")
                } else if storage_key == MOCK_ATTACH_STORAGE_KEY_BIN {
                    mock_attachment_ciphertext(&[0, 1, 2])
                } else if storage_key == MOCK_ATTACH_STORAGE_KEY_EMPTY_JSON {
                    "\"\"".to_string()
                } else {
                    String::new()
                }
            }
            _ => "<response><error message=\"unimplemented\"/></response>".to_string(),
        };

        HttpResponse { status: 200, body }
    }

    fn respond_bytes(&self, page: &str, params: &[(&str, &str)]) -> HttpResponseBytes {
        let response = self.respond(page, params);
        HttpResponseBytes {
            status: response.status,
            body: response.body.into_bytes(),
        }
    }
}

fn mock_login_hash(username: &str, password: &str, iterations: u32) -> String {
    kdf_login_key(username, password, iterations)
        .expect("fixed mock credentials should derive a login hash")
}

fn params_to_map(params: &[(&str, &str)]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (key, value) in params {
        map.insert((*key).to_string(), (*value).to_string());
    }
    map
}

fn mock_attachment_ciphertext(bytes: &[u8]) -> String {
    let raw_key = hex::decode(MOCK_ATTACH_KEY_HEX).expect("valid mock attachment key");
    let key: [u8; 32] = raw_key
        .as_slice()
        .try_into()
        .expect("mock attachment key must be 32 bytes");

    let plain_b64 = BASE64_STD.encode(bytes);
    let encrypted = aes_encrypt_lastpass(plain_b64.as_bytes(), &key).unwrap_or_default();
    serde_json::to_string(&base64_lastpass_encode(&encrypted)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Once};
    use std::thread;

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

        let cert =
            generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
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
}
