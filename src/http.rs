#![forbid(unsafe_code)]

use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use reqwest::blocking::Client;
use reqwest::header::{COOKIE, USER_AGENT};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};

use crate::blob::{Account, Blob};
use crate::config::ConfigStore;
use crate::crypto::{
    aes_decrypt_base64_lastpass, aes_encrypt_lastpass, base64_lastpass_encode,
    encrypt_private_key,
};
use crate::error::{LpassError, Result};
use crate::kdf::{kdf_decryption_key, kdf_login_key};
use crate::session::Session;

pub const LASTPASS_SERVER: &str = "lastpass.com";
const MOCK_ATTACH_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const MOCK_ATTACH_STORAGE_KEY_TEXT: &str = "mock-storage-0001-text";
const MOCK_ATTACH_STORAGE_KEY_BIN: &str = "mock-storage-0001-bin";
const MOCK_ATTACH_STORAGE_KEY_EMPTY_JSON: &str = "mock-storage-0001-empty-json";
const MOCK_PRIVATE_KEY_HEX: &str = "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100a1a227a8887870284bd831eb4a16dbba04c1092ce93e821b1523dcac45c84e34ea07139bee3a21b703fe78a3765995944c6646f4820341486a0f1c4472050110099b28b410d89d9fe2ebc2af752e95efdbaa9393a70dd09024719ea4fbb98c4498f7feced228a29462239f955ae0d028bb0cc5a641bdedc66f67fd2b5b4514d5020301000102818100920fadd4df962e8c4b958feeb6e217276f5a5d874733647142d64879290a4c9a068de48b7968f0c4a908514e2e09e060c5f57ad34395db6dabe201c25c62e7447dd91d051e1c614eaae5e51c90c6dc155665b91adc40c9b00dbcbcf7c3b86076274b7c0f411df082369e46788062afd6f6838be1eb0e92835d07ce9b3c80da55024100d49e0f79d17befdf79005e7f80a1cfe9b6c0875a1e157e1c0b8aac538e6bd387854718c0d1b5a75a1d73606be981ec4e7652c973dbfd3f650223b6787126fdb3024100c29cf9f94b7d3d48eaec0d7c6d7b91ec1c745ec6ae49f6d18550a1d63ef3864849eb8f4aac735f3c546514724c1e071d2b237927646c69bef2fffd14694b2f5702402a17385d17597fbd2fc920ec00dd07b9eed1e279b6a6ee9642baab2ec76d152d28f750312bd2d85480ac0c94905f86166a5a2d4360739c0f350338e6531032fd02400f081ceeba7bf3eddbe75bab4eb18ab5d804cd053f950af16800b05f6201614fd815cfbd8ed0627cc070064245cad3f5d6cd28a0784b3f67b6513b750624fe85024004ddedf0e84ddafcc86999697526fb0cad99928334f656f38ac14854db2551be0a683984f85dde12e1a5be921d1d86f5f53210a0c0f8e9de8495a10fee4d4fd3";
const MOCK_PWCHANGE_REENCRYPT_ID: &str = "mock-reencrypt-id";
const MOCK_PWCHANGE_TOKEN: &str = "mock-pwchange-token";
const MOCK_BLOB_VERSION: &str = "123";
const MOCK_REMOTE_BLOB_NAME: &str = "mock-remote-blob.json";

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
        crate::logging::log(5, &format!("Making request to {page}."));
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
        crate::logging::log(5, &format!("Making request to {page}."));
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

struct MockTransport {
    username: String,
    login_hash: String,
    decryption_key: [u8; 32],
    iterations: u32,
    uid: String,
    private_key_enc: String,
    sharing_public_key_hex: String,
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
        let decryption_key = kdf_decryption_key(&username, password, iterations)
            .expect("fixed mock credentials should derive a decryption key");
        let uid = "57747756".to_string();
        let private_key = hex::decode(MOCK_PRIVATE_KEY_HEX).expect("valid mock private key");
        let private_key_enc = encrypt_private_key(&private_key, &decryption_key)
            .expect("fixed mock private key should encrypt");
        let sharing_public_key_hex = mock_public_key_hex(&private_key);
        Self {
            username,
            login_hash,
            decryption_key,
            iterations,
            uid,
            private_key_enc,
            sharing_public_key_hex,
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
                        "<response><ok uid=\"{}\" sessionid=\"1234\" token=\"abcd\" privatekeyenc=\"{}\"/></response>",
                        self.uid, self.private_key_enc
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
            "show_website.php" => {
                self.apply_show_website_update(&map);
                String::new()
            }
            "loglogin.php" => String::new(),
            "lastpass/api.php" => match map.get("cmd").map(String::as_str) {
                Some("uploadaccounts") => "<lastpass rc=\"OK\"><ok/></lastpass>".to_string(),
                Some("getacctschangepw") => self.respond_pwchange_start(&map),
                Some("updatepassword") => self.respond_pwchange_complete(&map),
                _ => "<lastpass rc=\"FAIL\"><error/></lastpass>".to_string(),
            },
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
            "share.php" => self.respond_share(&map),
            _ => "<response><error message=\"unimplemented\"/></response>".to_string(),
        };

        HttpResponse { status: 200, body }
    }

    fn respond_bytes(&self, page: &str, params: &[(&str, &str)]) -> HttpResponseBytes {
        #[cfg(test)]
        if let Some(response) = self.override_response(page) {
            return HttpResponseBytes {
                status: response.status,
                body: response.body.into_bytes(),
            };
        }

        if page == "getaccts.php" {
            return HttpResponseBytes {
                status: 200,
                body: self.mock_blob_bytes(),
            };
        }
        let response = self.respond(page, params);
        HttpResponseBytes {
            status: response.status,
            body: response.body.into_bytes(),
        }
    }

    fn respond_pwchange_start(&self, map: &HashMap<String, String>) -> String {
        let username = map.get("username").cloned().unwrap_or_default();
        let hash = map.get("hash").cloned().unwrap_or_default();
        if username != self.username || hash != self.login_hash {
            return "<lastpass rc=\"FAIL\"><error/></lastpass>".to_string();
        }

        let required = mock_pwchange_ciphertext(&self.decryption_key, b"required-field");
        let optional = mock_pwchange_ciphertext(&self.decryption_key, b"optional-field");
        let payload = format!(
            "{MOCK_PWCHANGE_REENCRYPT_ID}\n{}\n{}\n{}\t0\nendmarker\n",
            self.private_key_enc, required, optional
        );

        format!(
            "<lastpass rc=\"OK\"><data token=\"{MOCK_PWCHANGE_TOKEN}\" xml=\"{}\"/></lastpass>",
            escape_xml_attr(&payload)
        )
    }

    fn respond_pwchange_complete(&self, map: &HashMap<String, String>) -> String {
        let required = [
            ("pwupdate", "1"),
            ("email", self.username.as_str()),
            ("token", MOCK_PWCHANGE_TOKEN),
        ];
        let has_required = required
            .iter()
            .all(|(key, value)| map.get(*key).map(String::as_str) == Some(*value));
        let has_payload = map
            .get("reencrypt")
            .map(String::as_str)
            .is_some_and(|value| value.starts_with(MOCK_PWCHANGE_REENCRYPT_ID));
        let has_new_fields = [
            "newprivatekeyenc",
            "newuserkeyhexhash",
            "newprivatekeyenchexhash",
            "newpasswordhash",
            "encrypted_username",
            "origusername",
            "wxhash",
            "key_iterations",
            "sukeycnt",
        ]
        .iter()
        .all(|key| map.contains_key(*key));

        if has_required && has_payload && has_new_fields {
            "pwchangeok".to_string()
        } else {
            "<lastpass rc=\"FAIL\"><error/></lastpass>".to_string()
        }
    }

    fn respond_share(&self, map: &HashMap<String, String>) -> String {
        if map.get("getinfo").map(String::as_str) == Some("1") {
            return self.respond_share_getinfo();
        }
        if map.get("getpubkey").map(String::as_str) == Some("1") {
            return self.respond_share_getpubkey(map.get("uid").map(String::as_str));
        }
        if map.get("limit").map(String::as_str) == Some("1")
            && map.get("edit").map(String::as_str) == Some("1")
        {
            return "<xmlresponse><success>1</success></xmlresponse>".to_string();
        }
        if map.get("limit").map(String::as_str) == Some("1") {
            return self.respond_share_get_limits();
        }
        if map.get("delete").map(String::as_str) == Some("1")
            || map.get("update").map(String::as_str) == Some("1")
            || map.get("up").map(String::as_str) == Some("1")
        {
            return "<xmlresponse><success>1</success></xmlresponse>".to_string();
        }
        "<xmlresponse><error message=\"unimplemented\"/></xmlresponse>".to_string()
    }

    fn respond_share_getinfo(&self) -> String {
        format!(
            "<xmlresponse><users>\
                <item>\
                    <realname>Test User</realname>\
                    <uid>{}</uid>\
                    <group>0</group>\
                    <username>{}</username>\
                    <permissions><readonly>1</readonly><canadminister>0</canadminister><give>0</give></permissions>\
                    <outsideenterprise>0</outsideenterprise>\
                    <accepted>1</accepted>\
                </item>\
                <item>\
                    <uid>991</uid>\
                    <group>1</group>\
                    <username>group-team</username>\
                    <permissions><readonly>0</readonly><canadminister>1</canadminister><give>1</give></permissions>\
                    <outsideenterprise>0</outsideenterprise>\
                    <accepted>1</accepted>\
                </item>\
            </users></xmlresponse>",
            self.uid, self.username
        )
    }

    fn respond_share_getpubkey(&self, raw_uid: Option<&str>) -> String {
        let Some(requested) = raw_uid.and_then(parse_mock_uid_param) else {
            return "<xmlresponse><success>0</success></xmlresponse>".to_string();
        };

        if requested == self.uid || requested.eq_ignore_ascii_case(&self.username) {
            return format!(
                "<xmlresponse><success>1</success><pubkey0>{}</pubkey0><uid0>{}</uid0><username0>{}</username0></xmlresponse>",
                self.sharing_public_key_hex, self.uid, self.username
            );
        }

        if requested.eq_ignore_ascii_case("group-team") {
            return "<xmlresponse><success>1</success><uid0>991</uid0><username0>group-team</username0><cgid0>cg-991</cgid0></xmlresponse>".to_string();
        }

        format!(
            "<xmlresponse><success>1</success><pubkey0>{}</pubkey0><uid0>880</uid0><username0>{}</username0></xmlresponse>",
            self.sharing_public_key_hex, requested
        )
    }

    fn respond_share_get_limits(&self) -> String {
        "<xmlresponse><hidebydefault>0</hidebydefault><aids><aid0>100</aid0></aids></xmlresponse>"
            .to_string()
    }

    fn mock_blob_bytes(&self) -> Vec<u8> {
        mock_blob_bytes_from_blob(&self.load_mock_remote_blob(), &self.decryption_key)
    }

    fn load_mock_remote_blob(&self) -> Blob {
        let store = ConfigStore::from_current();
        match store.read_buffer(MOCK_REMOTE_BLOB_NAME) {
            Ok(Some(buffer)) => serde_json::from_slice(&buffer).unwrap_or_else(|_| default_mock_blob()),
            Ok(None) | Err(_) => default_mock_blob(),
        }
    }

    fn save_mock_remote_blob(&self, blob: &Blob) {
        let store = ConfigStore::from_current();
        if let Ok(buffer) = serde_json::to_vec(blob) {
            let _ = store.write_buffer(MOCK_REMOTE_BLOB_NAME, &buffer);
        }
    }

    fn apply_show_website_update(&self, map: &HashMap<String, String>) {
        let Some(aid) = map.get("aid") else {
            return;
        };

        let mut blob = self.load_mock_remote_blob();
        let Some(account) = blob.accounts.iter_mut().find(|account| account.id == *aid) else {
            return;
        };

        if let Some(value) = map.get("name") {
            account.name = decrypt_mock_value(value, &self.decryption_key);
        }
        if let Some(value) = map.get("grouping") {
            account.group = decrypt_mock_value(value, &self.decryption_key);
        }
        if let Some(value) = map.get("username") {
            account.username = decrypt_mock_value(value, &self.decryption_key);
        }
        if let Some(value) = map.get("password") {
            account.password = decrypt_mock_value(value, &self.decryption_key);
        }
        if let Some(value) = map.get("extra") {
            account.note = decrypt_mock_value(value, &self.decryption_key);
        }
        if let Some(value) = map.get("url") {
            account.url = decode_mock_url(value, &self.decryption_key);
        }
        if let Some(value) = map.get("pwprotect") {
            account.pwprotect = value == "on";
        }

        account.fullname = if account.group.is_empty() {
            account.name.clone()
        } else {
            format!("{}/{}", account.group, account.name)
        };
        self.save_mock_remote_blob(&blob);
    }
}

fn mock_blob_bytes_from_blob(blob: &Blob, key: &[u8; 32]) -> Vec<u8> {
    fn push_chunk(out: &mut Vec<u8>, tag: &str, body: &[u8]) {
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
    }

    fn push_item(body: &mut Vec<u8>, bytes: &[u8]) {
        body.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(bytes);
    }

    fn push_encrypted_item(
        body: &mut Vec<u8>,
        key: &[u8; 32],
        value: &str,
    ) {
        let encrypted = aes_encrypt_lastpass(value.as_bytes(), key).expect("mock blob encrypt");
        push_item(body, &encrypted);
    }

    fn push_account(
        out: &mut Vec<u8>,
        key: &[u8; 32],
        id: &str,
        name: &str,
        group: &str,
        url: &str,
        username: &str,
        password: &str,
        note: &str,
        pwprotect: bool,
    ) {
        let mut acct = Vec::new();
        push_item(&mut acct, id.as_bytes());
        push_encrypted_item(&mut acct, key, name);
        push_encrypted_item(&mut acct, key, group);
        push_encrypted_item(&mut acct, key, url);
        push_encrypted_item(&mut acct, key, note);
        push_item(&mut acct, b"0");
        push_item(&mut acct, b"");
        push_encrypted_item(&mut acct, key, username);
        push_encrypted_item(&mut acct, key, password);
        push_item(&mut acct, if pwprotect { b"1" } else { b"0" });
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"skipped");
        for _ in 0..13 {
            push_item(&mut acct, b"");
        }
        push_item(&mut acct, b"");
        push_item(&mut acct, b"0");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"skipped");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_chunk(out, "ACCT", &acct);
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"LPAV");
    bytes.extend_from_slice(&(MOCK_BLOB_VERSION.len() as u32).to_be_bytes());
    bytes.extend_from_slice(MOCK_BLOB_VERSION.as_bytes());
    for account in &blob.accounts {
        push_account(
            &mut bytes,
            key,
            &account.id,
            &account.name,
            &account.group,
            &account.url,
            &account.username,
            &account.password,
            &account.note,
            account.pwprotect,
        );
    }
    bytes
}

fn mock_login_hash(username: &str, password: &str, iterations: u32) -> String {
    kdf_login_key(username, password, iterations)
        .expect("fixed mock credentials should derive a login hash")
}

fn decrypt_mock_value(value: &str, key: &[u8; 32]) -> String {
    aes_decrypt_base64_lastpass(value, key)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_default()
}

fn decode_mock_url(value: &str, key: &[u8; 32]) -> String {
    if value.starts_with('!') {
        return decrypt_mock_value(value, key);
    }

    hex::decode(value)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .unwrap_or_default()
}

fn default_mock_blob() -> Blob {
    let mut blob = Blob {
        version: MOCK_BLOB_VERSION.parse().expect("mock blob version"),
        local_version: false,
        shares: Vec::new(),
        accounts: Vec::new(),
        attachments: Vec::new(),
    };

    blob.accounts.push(default_mock_account(
        "0001",
        "test-account",
        "test-group",
        "https://test-url.example.com/",
        "xyz@example.com",
        "test-account-password",
        "",
        false,
    ));
    blob.accounts.push(default_mock_account(
        "0002",
        "test-note",
        "test-group",
        "http://sn",
        "",
        "",
        "NoteType: Server\nHostname: foo.example.com\nUsername: test-note-user\nPassword: test-note-password",
        false,
    ));
    blob.accounts.push(default_mock_account(
        "0003",
        "test-reprompt-account",
        "test-group",
        "https://test-url.example.com/",
        "xyz@example.com",
        "test-account-password",
        "",
        true,
    ));
    blob.accounts.push(default_mock_account(
        "0004",
        "test-reprompt-note",
        "test-group",
        "http://sn",
        "",
        "",
        "NoteType: Server\nHostname: foo.example.com\nUsername: test-note-user\nPassword: test-note-password",
        true,
    ));
    blob
}

#[allow(clippy::too_many_arguments)]
fn default_mock_account(
    id: &str,
    name: &str,
    group: &str,
    url: &str,
    username: &str,
    password: &str,
    note: &str,
    pwprotect: bool,
) -> Account {
    Account {
        id: id.to_string(),
        share_name: None,
        share_id: None,
        share_readonly: false,
        name: name.to_string(),
        name_encrypted: None,
        group: group.to_string(),
        group_encrypted: None,
        fullname: format!("{group}/{name}"),
        url: url.to_string(),
        url_encrypted: None,
        username: username.to_string(),
        username_encrypted: None,
        password: password.to_string(),
        password_encrypted: None,
        note: note.to_string(),
        note_encrypted: None,
        last_touch: "skipped".to_string(),
        last_modified_gmt: "skipped".to_string(),
        fav: false,
        pwprotect,
        attachkey: String::new(),
        attachkey_encrypted: None,
        attachpresent: false,
        fields: Vec::new(),
    }
}

fn mock_public_key_hex(private_key_der: &[u8]) -> String {
    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(private_key_der))
        .expect("fixed mock private key should decode");
    let public_key = private_key.to_public_key();
    let der = public_key
        .to_public_key_der()
        .expect("fixed mock public key should encode");
    hex::encode(der.as_ref())
}

fn parse_mock_uid_param(value: &str) -> Option<String> {
    let prefix = "{\"";
    let rest = value.strip_prefix(prefix)?;
    let end = rest.find("\":{")?;
    Some(rest[..end].to_string())
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

fn mock_pwchange_ciphertext(key: &[u8; 32], bytes: &[u8]) -> String {
    let encrypted = aes_encrypt_lastpass(bytes, key).unwrap_or_default();
    base64_lastpass_encode(&encrypted)
}

fn escape_xml_attr(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\n' => escaped.push_str("&#10;"),
            '\r' => escaped.push_str("&#13;"),
            '\t' => escaped.push_str("&#9;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
