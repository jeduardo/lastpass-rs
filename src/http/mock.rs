use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};

use crate::blob::{Account, Blob};
use crate::config::ConfigStore;
use crate::crypto::{
    aes_decrypt_base64_lastpass, aes_encrypt_lastpass, base64_lastpass_encode, encrypt_private_key,
    rsa_encrypt_oaep,
};
use crate::kdf::{kdf_decryption_key, kdf_login_key};

use super::{HttpResponse, HttpResponseBytes};

pub(crate) const MOCK_ATTACH_KEY_HEX: &str =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
pub(crate) const MOCK_ATTACH_STORAGE_KEY_TEXT: &str = "mock-storage-0001-text";
pub(crate) const MOCK_ATTACH_STORAGE_KEY_BIN: &str = "mock-storage-0001-bin";
pub(crate) const MOCK_ATTACH_STORAGE_KEY_EMPTY_JSON: &str = "mock-storage-0001-empty-json";
pub(crate) const MOCK_PRIVATE_KEY_HEX: &str = "30820276020100300d06092a864886f70d0101010500048202603082025c02010002818100a1a227a8887870284bd831eb4a16dbba04c1092ce93e821b1523dcac45c84e34ea07139bee3a21b703fe78a3765995944c6646f4820341486a0f1c4472050110099b28b410d89d9fe2ebc2af752e95efdbaa9393a70dd09024719ea4fbb98c4498f7feced228a29462239f955ae0d028bb0cc5a641bdedc66f67fd2b5b4514d5020301000102818100920fadd4df962e8c4b958feeb6e217276f5a5d874733647142d64879290a4c9a068de48b7968f0c4a908514e2e09e060c5f57ad34395db6dabe201c25c62e7447dd91d051e1c614eaae5e51c90c6dc155665b91adc40c9b00dbcbcf7c3b86076274b7c0f411df082369e46788062afd6f6838be1eb0e92835d07ce9b3c80da55024100d49e0f79d17befdf79005e7f80a1cfe9b6c0875a1e157e1c0b8aac538e6bd387854718c0d1b5a75a1d73606be981ec4e7652c973dbfd3f650223b6787126fdb3024100c29cf9f94b7d3d48eaec0d7c6d7b91ec1c745ec6ae49f6d18550a1d63ef3864849eb8f4aac735f3c546514724c1e071d2b237927646c69bef2fffd14694b2f5702402a17385d17597fbd2fc920ec00dd07b9eed1e279b6a6ee9642baab2ec76d152d28f750312bd2d85480ac0c94905f86166a5a2d4360739c0f350338e6531032fd02400f081ceeba7bf3eddbe75bab4eb18ab5d804cd053f950af16800b05f6201614fd815cfbd8ed0627cc070064245cad3f5d6cd28a0784b3f67b6513b750624fe85024004ddedf0e84ddafcc86999697526fb0cad99928334f656f38ac14854db2551be0a683984f85dde12e1a5be921d1d86f5f53210a0c0f8e9de8495a10fee4d4fd3";
const MOCK_PWCHANGE_REENCRYPT_ID: &str = "mock-reencrypt-id";
const MOCK_PWCHANGE_TOKEN: &str = "mock-pwchange-token";
const MOCK_BLOB_VERSION: &str = "123";
pub(crate) const MOCK_REMOTE_BLOB_NAME: &str = "mock-remote-blob.json";

pub(crate) struct MockTransport {
    username: String,
    login_hash: String,
    decryption_key: [u8; 32],
    iterations: u32,
    uid: String,
    private_key_enc: String,
    sharing_public_key_hex: String,
    #[cfg(test)]
    pub(crate) overrides: std::sync::Mutex<HashMap<String, VecDeque<HttpResponse>>>,
}

#[cfg(test)]
pub(crate) fn lock_overrides<'a>(
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
    pub(crate) fn new() -> Self {
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
    pub(crate) fn with_overrides(overrides: &[(&str, u16, &str)]) -> Self {
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
    pub(crate) fn override_response(&self, page: &str) -> Option<HttpResponse> {
        let mut map = lock_overrides(self.overrides.lock());
        let responses = map.get_mut(page)?;
        let response = responses.pop_front();
        if responses.is_empty() {
            map.remove(page);
        }
        response
    }

    pub(crate) fn respond(&self, page: &str, params: &[(&str, &str)]) -> HttpResponse {
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
                "<response><ok uid=\"{}\" sessionid=\"1234\" token=\"abcd\" accts_version=\"{}\"/></response>",
                self.uid,
                self.load_mock_remote_blob().version
            ),
            "getaccts.php" => String::new(),
            "show_website.php" => {
                self.apply_show_website_update(&map);
                String::new()
            }
            "loglogin.php" => String::new(),
            "lastpass/api.php" => match map.get("cmd").map(String::as_str) {
                Some("uploadaccounts") => self.respond_uploadaccounts(&map),
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

    pub(crate) fn respond_bytes(&self, page: &str, params: &[(&str, &str)]) -> HttpResponseBytes {
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

    fn respond_uploadaccounts(&self, map: &HashMap<String, String>) -> String {
        self.apply_uploadaccounts(map);
        "<lastpass rc=\"OK\"><ok/></lastpass>".to_string()
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

    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn load_mock_remote_blob(&self) -> Blob {
        let store = ConfigStore::from_current();
        match store.read_buffer(MOCK_REMOTE_BLOB_NAME) {
            Ok(Some(buffer)) => {
                serde_json::from_slice(&buffer).unwrap_or_else(|_| default_mock_blob())
            }
            Ok(None) | Err(_) => self
                .load_local_blob_seed()
                .unwrap_or_else(default_mock_blob),
        }
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn save_mock_remote_blob(&self, blob: &Blob) {
        let store = ConfigStore::from_current();
        if let Ok(buffer) = serde_json::to_vec(blob) {
            let _ = store.write_buffer(MOCK_REMOTE_BLOB_NAME, &buffer);
        }
    }

    fn load_local_blob_seed(&self) -> Option<Blob> {
        let store = ConfigStore::from_current();
        let key = load_mock_store_key(&store)?;
        let buffer = store.read_encrypted_buffer("blob.json", &key).ok()??;
        serde_json::from_slice(&buffer).ok()
    }

    fn apply_uploadaccounts(&self, map: &HashMap<String, String>) {
        let mut blob = self.load_mock_remote_blob();
        let mut changed = false;

        for index in 0.. {
            let name_key = format!("name{index}");
            let aid_key = format!("aid{index}");
            if !map.contains_key(&name_key) && !map.contains_key(&aid_key) {
                break;
            }

            let account_id = map
                .get(&aid_key)
                .cloned()
                .filter(|value| !value.is_empty() && value != "0")
                .unwrap_or_else(|| next_mock_account_id(&blob.accounts));
            let mut account = blob
                .accounts
                .iter()
                .find(|account| account.id == account_id)
                .cloned()
                .unwrap_or_else(|| {
                    default_mock_account(&account_id, "", "", "", "", "", "", false)
                });
            let key = mock_upload_key(map, &blob, &self.decryption_key);

            if let Some(value) = map.get(&name_key) {
                account.name = decrypt_mock_value(value, key);
            }
            let grouping_key = format!("grouping{index}");
            if let Some(value) = map.get(&grouping_key) {
                account.group = decrypt_mock_value(value, key);
            }
            let url_key = format!("url{index}");
            if let Some(value) = map.get(&url_key) {
                account.url = decode_mock_url(value, key);
            }
            let username_key = format!("username{index}");
            if let Some(value) = map.get(&username_key) {
                account.username = decrypt_mock_value(value, key);
            }
            let password_key = format!("password{index}");
            if let Some(value) = map.get(&password_key) {
                account.password = decrypt_mock_value(value, key);
            }
            let extra_key = format!("extra{index}");
            if let Some(value) = map.get(&extra_key) {
                account.note = decrypt_mock_value(value, key);
            }
            let fav_key = format!("fav{index}");
            if let Some(value) = map.get(&fav_key) {
                account.fav = value == "1";
            }
            let pwprotect_key = format!("pwprotect{index}");
            if let Some(value) = map.get(&pwprotect_key) {
                account.pwprotect = value == "on";
            }
            if let Some(share_id) = map.get("sharedfolderid") {
                if let Some(share) = blob.shares.iter().find(|share| share.id == *share_id) {
                    account.share_id = Some(share.id.clone());
                    account.share_name = Some(share.name.clone());
                    account.share_readonly = share.readonly;
                } else {
                    account.share_id = Some(share_id.clone());
                    account.share_name = None;
                    account.share_readonly = false;
                }
            } else {
                account.share_id = None;
                account.share_name = None;
                account.share_readonly = false;
            }

            account.fullname = if account.group.is_empty() {
                if let Some(share_name) = account.share_name.as_deref() {
                    format!("{share_name}/{}", account.name)
                } else {
                    account.name.clone()
                }
            } else if let Some(share_name) = account.share_name.as_deref() {
                format!("{share_name}/{}/{}", account.group, account.name)
            } else {
                format!("{}/{}", account.group, account.name)
            };

            if let Some(existing) = blob
                .accounts
                .iter_mut()
                .find(|existing| existing.id == account.id)
            {
                *existing = account;
            } else {
                blob.accounts.push(account);
            }
            changed = true;
        }

        if changed {
            blob.version = blob.version.saturating_add(1);
            self.save_mock_remote_blob(&blob);
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
        blob.version = blob.version.saturating_add(1);
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

    fn push_encrypted_item(body: &mut Vec<u8>, key: &[u8; 32], value: &str) {
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

    fn push_share(out: &mut Vec<u8>, share: &crate::blob::Share) {
        let Some(share_key) = share.key.as_ref() else {
            return;
        };
        let private_key = hex::decode(MOCK_PRIVATE_KEY_HEX).expect("valid mock private key");
        let public_key_der = hex::decode(mock_public_key_hex(&private_key)).expect("public key");
        let encrypted_share_key =
            rsa_encrypt_oaep(&public_key_der, hex::encode(share_key).as_bytes())
                .expect("mock share key encrypt");
        let encrypted_name = aes_encrypt_lastpass(share.name.as_bytes(), share_key)
            .expect("mock share name encrypt");

        let mut shar = Vec::new();
        push_item(&mut shar, share.id.as_bytes());
        push_item(&mut shar, hex::encode(encrypted_share_key).as_bytes());
        push_item(
            &mut shar,
            base64_lastpass_encode(&encrypted_name).as_bytes(),
        );
        push_item(&mut shar, if share.readonly { b"1" } else { b"0" });
        push_chunk(out, "SHAR", &shar);
    }

    let mut bytes = Vec::new();
    let version = blob.version.to_string();
    bytes.extend_from_slice(b"LPAV");
    bytes.extend_from_slice(&(version.len() as u32).to_be_bytes());
    bytes.extend_from_slice(version.as_bytes());
    for account in blob
        .accounts
        .iter()
        .filter(|account| account.share_id.is_none())
    {
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
    for share in &blob.shares {
        push_share(&mut bytes, share);
        for account in blob
            .accounts
            .iter()
            .filter(|account| account.share_id.as_deref() == Some(share.id.as_str()))
        {
            let account_key = share.key.as_ref().unwrap_or(key);
            push_account(
                &mut bytes,
                account_key,
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

fn next_mock_account_id(accounts: &[Account]) -> String {
    let next = accounts
        .iter()
        .filter_map(|account| account.id.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    format!("{next:04}")
}

fn load_mock_store_key(store: &ConfigStore) -> Option<[u8; 32]> {
    let buffer = store.read_buffer("plaintext_key").ok()??;
    if buffer.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&buffer);
    Some(key)
}

fn mock_upload_key<'a>(
    map: &HashMap<String, String>,
    blob: &'a Blob,
    vault_key: &'a [u8; 32],
) -> &'a [u8; 32] {
    map.get("sharedfolderid")
        .and_then(|share_id| blob.shares.iter().find(|share| share.id == *share_id))
        .and_then(|share| share.key.as_ref())
        .unwrap_or(vault_key)
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

pub(crate) fn params_to_map(params: &[(&str, &str)]) -> HashMap<String, String> {
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

pub(crate) fn escape_xml_attr(value: &str) -> String {
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
