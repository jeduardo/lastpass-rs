#![forbid(unsafe_code)]

use crate::error::{LpassError, Result};
use crate::session::Session;
use reqwest::blocking::Client;
use reqwest::header::{COOKIE, USER_AGENT};

pub const LASTPASS_SERVER: &str = "lastpass.com";

#[cfg(any(test, feature = "test-harness"))]
#[path = "http/mock.rs"]
mod mock;
#[cfg(any(test, feature = "test-harness"))]
pub(crate) use self::mock::MockTransport;
#[cfg(test)]
pub(crate) use self::mock::{
    MOCK_ATTACH_STORAGE_KEY_BIN, MOCK_ATTACH_STORAGE_KEY_EMPTY_JSON, MOCK_ATTACH_STORAGE_KEY_TEXT,
    MOCK_PRIVATE_KEY_HEX, MOCK_REMOTE_BLOB_NAME, escape_xml_attr, lock_overrides, params_to_map,
};

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
    #[cfg(any(test, feature = "test-harness"))]
    Mock(MockTransport),
}

pub struct HttpClient {
    transport: Transport,
}

impl HttpClient {
    pub fn from_env() -> Result<Self> {
        if crate::lpenv::var("LPASS_HTTP_MOCK").as_deref() == Ok("1") {
            #[cfg(any(test, feature = "test-harness"))]
            {
                return Ok(Self::mock());
            }
            #[cfg(not(any(test, feature = "test-harness")))]
            {
                return Err(LpassError::User(
                    "LPASS_HTTP_MOCK is only available in test-harness builds",
                ));
            }
        }

        Self::real()
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

    #[cfg(any(test, feature = "test-harness"))]
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
        crate::logging::log(5, &format!("Making request to {page}."));
        match &self.transport {
            Transport::Real(client) => post_real(client, server, page, session, params),
            #[cfg(any(test, feature = "test-harness"))]
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
        crate::logging::log(5, &format!("Making request to {page}."));
        match &self.transport {
            Transport::Real(client) => post_real_bytes(client, server, page, session, params),
            #[cfg(any(test, feature = "test-harness"))]
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
    let request = add_session_cookie(client.post(url).header(USER_AGENT, user_agent()), session);

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
    let request = add_session_cookie(client.post(url).header(USER_AGENT, user_agent()), session);

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

fn add_session_cookie(
    request: reqwest::blocking::RequestBuilder,
    session: Option<&Session>,
) -> reqwest::blocking::RequestBuilder {
    match session
        .and_then(|session| (!session.session_id.is_empty()).then_some(session.session_id.as_str()))
    {
        Some(session_id) => request.header(COOKIE, format!("PHPSESSID={session_id}")),
        None => request,
    }
}

fn map_build_client_error(_: reqwest::Error) -> LpassError {
    LpassError::Crypto("failed to build http client")
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
