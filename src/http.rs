#![forbid(unsafe_code)]

use std::collections::HashMap;

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
            .map_err(|_| LpassError::Crypto("failed to build http client"))?;
        Ok(Self {
            transport: Transport::Real(client),
        })
    }

    pub fn mock() -> Self {
        Self {
            transport: Transport::Mock(MockTransport::new()),
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
    HttpClient::from_env()?.post_lastpass(None, page, session, params)
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
    format!("LastPass-CLI/{}", env!("CARGO_PKG_VERSION"))
}

struct MockTransport {
    username: String,
    login_hash: String,
    iterations: u32,
    uid: String,
}

impl MockTransport {
    fn new() -> Self {
        let username = "user@example.com".to_string();
        let password = "123456";
        let iterations = 1000;
        let login_hash =
            kdf_login_key(&username, password, iterations).unwrap_or_else(|_| "".to_string());
        let uid = "57747756".to_string();
        Self {
            username,
            login_hash,
            iterations,
            uid,
        }
    }

    fn respond(&self, page: &str, params: &[(&str, &str)]) -> HttpResponse {
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
        assert!(ua.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn real_client_can_be_constructed() {
        let client = HttpClient::real().expect("client");
        match client.transport {
            Transport::Real(_) => {}
            Transport::Mock(_) => panic!("expected real transport"),
        }
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
}
