#![forbid(unsafe_code)]

use crate::crypto::{
    aes_decrypt_base64_lastpass, aes_decrypt_lastpass, base64_lastpass_encode, rsa_decrypt_oaep,
};
use crate::error::{LpassError, Result};
use crate::kdf::KDF_HASH_LEN;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub field_type: String,
    pub value: String,
    pub value_encrypted: Option<String>,
    pub checked: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub share_name: Option<String>,
    #[serde(default)]
    pub share_id: Option<String>,
    #[serde(default)]
    pub share_readonly: bool,
    pub name: String,
    pub name_encrypted: Option<String>,
    pub group: String,
    pub group_encrypted: Option<String>,
    pub fullname: String,
    pub url: String,
    pub url_encrypted: Option<String>,
    pub username: String,
    pub username_encrypted: Option<String>,
    pub password: String,
    pub password_encrypted: Option<String>,
    pub note: String,
    pub note_encrypted: Option<String>,
    pub last_touch: String,
    pub last_modified_gmt: String,
    pub fav: bool,
    pub pwprotect: bool,
    pub attachkey: String,
    pub attachkey_encrypted: Option<String>,
    pub attachpresent: bool,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Blob {
    pub version: u64,
    pub local_version: bool,
    #[serde(default)]
    pub shares: Vec<Share>,
    pub accounts: Vec<Account>,
}

#[derive(Debug, Clone)]
struct ShareContext {
    share: Share,
    key: [u8; KDF_HASH_LEN],
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct Share {
    pub id: String,
    pub name: String,
    pub readonly: bool,
}

pub fn blob_parse(
    data: &[u8],
    key: &[u8; KDF_HASH_LEN],
    private_key: Option<&[u8]>,
) -> Result<Blob> {
    let mut reader = BlobReader::new(data);
    let mut blob = Blob::default();
    let mut current_account_index: Option<usize> = None;
    let mut current_share: Option<ShareContext> = None;

    while let Some(mut chunk) = reader.read_chunk()? {
        match chunk.tag.as_str() {
            "LPAV" => {
                let version_str = String::from_utf8_lossy(chunk.data()).to_string();
                blob.version = version_str.trim().parse::<u64>().unwrap_or(0);
            }
            "LOCL" => {
                blob.local_version = true;
            }
            "SHAR" => {
                current_share = parse_share(&mut chunk, private_key)?;
                if let Some(share) = current_share.as_ref().map(|ctx| ctx.share.clone()) {
                    blob.shares.push(share);
                }
            }
            "ACCT" => {
                let account_key = current_share
                    .as_ref()
                    .map(|share| &share.key)
                    .unwrap_or(key);
                let mut account = parse_account(&mut chunk, account_key)?;
                if let Some(share) = &current_share {
                    account.share_name = Some(share.share.name.clone());
                    account.share_id = Some(share.share.id.clone());
                    account.share_readonly = share.share.readonly;
                    account.fullname = format!("{}/{}", share.share.name, account.fullname);
                }
                blob.accounts.push(account);
                current_account_index = Some(blob.accounts.len() - 1);
            }
            "ACFL" | "ACOF" => {
                if let Some(idx) = current_account_index {
                    let account_key = current_share
                        .as_ref()
                        .map(|share| &share.key)
                        .unwrap_or(key);
                    let field = parse_field(&mut chunk, account_key)?;
                    blob.accounts[idx].fields.push(field);
                }
            }
            _ => {}
        }
    }

    if blob.version == 0 {
        return Err(LpassError::Crypto("missing blob version"));
    }

    Ok(blob)
}

fn account_is_group(account: &Account) -> bool {
    account.url == "http://group"
}

fn parse_share(
    chunk: &mut ChunkCursor<'_>,
    private_key: Option<&[u8]>,
) -> Result<Option<ShareContext>> {
    let Some(private_key) = private_key else {
        return Ok(None);
    };

    let id = read_plain_string(chunk)?;
    let encrypted_share_key_hex = read_plain_string(chunk)?;
    if encrypted_share_key_hex.is_empty() {
        return Ok(None);
    }

    let ciphertext = match hex::decode(encrypted_share_key_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let decrypted_hex = match rsa_decrypt_oaep(private_key, &ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let decrypted_hex = decrypted_hex
        .iter()
        .copied()
        .take_while(|ch| *ch != 0)
        .filter(|ch| (*ch as char).is_ascii_hexdigit())
        .map(char::from)
        .collect::<String>();
    let share_key_bytes = match hex::decode(decrypted_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    if share_key_bytes.len() != KDF_HASH_LEN {
        return Ok(None);
    }
    let mut share_key = [0u8; KDF_HASH_LEN];
    share_key.copy_from_slice(&share_key_bytes);

    let share_name_b64 = read_plain_string(chunk)?;
    let share_name = match aes_decrypt_base64_lastpass(&share_name_b64, &share_key) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => String::new(),
    };

    let readonly = read_boolean(chunk)?;

    Ok(Some(ShareContext {
        share: Share {
            id,
            name: share_name,
            readonly,
        },
        key: share_key,
    }))
}

fn parse_account(chunk: &mut ChunkCursor<'_>, key: &[u8; KDF_HASH_LEN]) -> Result<Account> {
    let id = read_plain_string(chunk)?;
    let (name, name_encrypted) = read_crypt_string(chunk, key)?;
    let (group, group_encrypted) = read_crypt_string(chunk, key)?;

    let (url, url_encrypted) = if check_next_entry_encrypted(chunk) {
        read_crypt_string(chunk, key)?
    } else {
        (read_hex_string(chunk)?, None)
    };

    let (note, note_encrypted) = read_crypt_string(chunk, key)?;
    let fav = read_boolean(chunk)?;
    skip_item(chunk)?; // sharedfromaid
    let (username, username_encrypted) = read_crypt_string(chunk, key)?;
    let (password, password_encrypted) = read_crypt_string(chunk, key)?;
    let pwprotect = read_boolean(chunk)?;
    skip_item(chunk)?; // genpw
    skip_item(chunk)?; // sn
    let last_touch = read_plain_string(chunk)?;
    skip_item(chunk)?; // autologin
    skip_item(chunk)?; // never_autofill
    skip_item(chunk)?; // realm_data
    skip_item(chunk)?; // fiid
    skip_item(chunk)?; // custom_js
    skip_item(chunk)?; // submit_id
    skip_item(chunk)?; // captcha_id
    skip_item(chunk)?; // urid
    skip_item(chunk)?; // basic_auth
    skip_item(chunk)?; // method
    skip_item(chunk)?; // action
    skip_item(chunk)?; // groupid
    skip_item(chunk)?; // deleted
    let attachkey_encrypted = read_plain_string(chunk)?;
    let attachpresent = read_boolean(chunk)?;
    skip_item(chunk)?; // individualshare
    skip_item(chunk)?; // notetype
    skip_item(chunk)?; // noalert
    let last_modified_gmt = read_plain_string(chunk)?;
    skip_item(chunk)?; // hasbeenshared
    skip_item(chunk)?; // last_pwchange_gmt
    skip_item(chunk)?; // created_gmt
    skip_item(chunk)?; // vulnerable

    let name = if name.as_bytes().first() == Some(&16u8) {
        String::new()
    } else {
        name
    };
    let group = if group.as_bytes().first() == Some(&16u8) {
        String::new()
    } else {
        group
    };

    let attachkey = if !attachkey_encrypted.is_empty() {
        match aes_decrypt_base64_lastpass(&attachkey_encrypted, key) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };

    let mut account = Account {
        id,
        share_name: None,
        share_id: None,
        share_readonly: false,
        name,
        name_encrypted,
        group,
        group_encrypted,
        fullname: String::new(),
        url,
        url_encrypted,
        username,
        username_encrypted,
        password,
        password_encrypted,
        note,
        note_encrypted,
        last_touch,
        last_modified_gmt,
        fav,
        pwprotect,
        attachkey,
        attachkey_encrypted: if attachkey_encrypted.is_empty() {
            None
        } else {
            Some(attachkey_encrypted)
        },
        attachpresent,
        fields: Vec::new(),
    };

    if !account.group.is_empty() && (!account.name.is_empty() || account_is_group(&account)) {
        account.fullname = format!("{}/{}", account.group, account.name);
    } else {
        account.fullname = account.name.clone();
    }

    Ok(account)
}

fn parse_field(chunk: &mut ChunkCursor<'_>, key: &[u8; KDF_HASH_LEN]) -> Result<Field> {
    let name = read_plain_string(chunk)?;
    let field_type = read_plain_string(chunk)?;
    let (value, value_encrypted) = if matches!(
        field_type.as_str(),
        "email" | "tel" | "text" | "password" | "textarea"
    ) {
        read_crypt_string(chunk, key)?
    } else {
        (read_plain_string(chunk)?, None)
    };
    let checked = read_boolean(chunk)?;

    Ok(Field {
        name,
        field_type,
        value,
        value_encrypted,
        checked,
    })
}

#[derive(Debug)]
struct BlobReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BlobReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_chunk(&mut self) -> Result<Option<ChunkCursor<'a>>> {
        if self.remaining() == 0 {
            return Ok(None);
        }
        if self.remaining() < 8 {
            return Err(LpassError::Crypto("blob truncated"));
        }

        let tag = &self.data[self.pos..self.pos + 4];
        let tag_str = String::from_utf8_lossy(tag).to_string();
        self.pos += 4;

        let len = read_be_u32(self.data, &mut self.pos)? as usize;
        if self.remaining() < len {
            return Err(LpassError::Crypto("blob truncated"));
        }
        let start = self.pos;
        let end = start + len;
        self.pos = end;

        Ok(Some(ChunkCursor::new(tag_str, &self.data[start..end])))
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

#[derive(Debug)]
struct ChunkCursor<'a> {
    tag: String,
    data: &'a [u8],
    pos: usize,
}

impl<'a> ChunkCursor<'a> {
    fn new(tag: String, data: &'a [u8]) -> Self {
        Self { tag, data, pos: 0 }
    }

    fn data(&self) -> &'a [u8] {
        self.data
    }

    fn read_item(&mut self) -> Result<&'a [u8]> {
        if self.remaining() < 4 {
            return Err(LpassError::Crypto("chunk truncated"));
        }
        let len = read_be_u32(self.data, &mut self.pos)? as usize;
        if self.remaining() < len {
            return Err(LpassError::Crypto("chunk truncated"));
        }
        let start = self.pos;
        let end = start + len;
        self.pos = end;
        Ok(&self.data[start..end])
    }

    fn peek_item_first_byte(&self) -> Option<u8> {
        if self.remaining() < 5 {
            return None;
        }
        let len = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().ok()?) as usize;
        if len == 0 || self.remaining() < 4 + len {
            return None;
        }
        self.data.get(self.pos + 4).copied()
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

fn read_be_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > data.len() {
        return Err(LpassError::Crypto("read past end"));
    }
    let bytes: [u8; 4] = data[*pos..*pos + 4]
        .try_into()
        .map_err(|_| LpassError::Crypto("read past end"))?;
    *pos += 4;
    Ok(u32::from_be_bytes(bytes))
}

fn read_plain_string(chunk: &mut ChunkCursor<'_>) -> Result<String> {
    let item = chunk.read_item()?;
    if item.is_empty() {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(item).to_string())
}

fn read_hex_string(chunk: &mut ChunkCursor<'_>) -> Result<String> {
    let item = chunk.read_item()?;
    if item.is_empty() {
        return Ok(String::new());
    }
    let decoded = hex::decode(item).map_err(|_| LpassError::Crypto("hex decode failed"))?;
    Ok(String::from_utf8_lossy(&decoded).to_string())
}

fn read_crypt_string(
    chunk: &mut ChunkCursor<'_>,
    key: &[u8; KDF_HASH_LEN],
) -> Result<(String, Option<String>)> {
    let item = chunk.read_item()?;
    let encrypted = base64_lastpass_encode(item);
    if item.is_empty() {
        return Ok((String::new(), Some(encrypted)));
    }

    match aes_decrypt_lastpass(item, key) {
        Ok(bytes) => Ok((String::from_utf8_lossy(&bytes).to_string(), Some(encrypted))),
        Err(_) => Ok((String::new(), Some(encrypted))),
    }
}

fn read_boolean(chunk: &mut ChunkCursor<'_>) -> Result<bool> {
    let item = chunk.read_item()?;
    if item.len() != 1 {
        return Ok(false);
    }
    Ok(item[0] == b'1')
}

fn skip_item(chunk: &mut ChunkCursor<'_>) -> Result<()> {
    let _ = chunk.read_item()?;
    Ok(())
}

fn check_next_entry_encrypted(chunk: &ChunkCursor<'_>) -> bool {
    matches!(chunk.peek_item_first_byte(), Some(b'!'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes_encrypt_lastpass;

    fn push_chunk(out: &mut Vec<u8>, tag: &str, body: &[u8]) {
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
    }

    fn push_item(body: &mut Vec<u8>, bytes: &[u8]) {
        body.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(bytes);
    }

    #[test]
    fn parse_minimal_blob() {
        let key = [7u8; 32];
        let mut blob_bytes = Vec::new();

        let version = b"1".to_vec();
        push_chunk(&mut blob_bytes, "LPAV", &version);

        let mut acct = Vec::new();
        push_item(&mut acct, b"0001");
        let name = aes_encrypt_lastpass(b"test-account", &key).expect("enc");
        push_item(&mut acct, &name);
        let group = aes_encrypt_lastpass(b"test-group", &key).expect("enc");
        push_item(&mut acct, &group);
        let url = aes_encrypt_lastpass(b"https://example.com/", &key).expect("enc");
        push_item(&mut acct, &url);
        let note = aes_encrypt_lastpass(b"", &key).expect("enc");
        push_item(&mut acct, &note);
        push_item(&mut acct, b"0"); // fav
        push_item(&mut acct, b""); // sharedfromaid
        let user = aes_encrypt_lastpass(b"user", &key).expect("enc");
        push_item(&mut acct, &user);
        let pass = aes_encrypt_lastpass(b"pass", &key).expect("enc");
        push_item(&mut acct, &pass);
        push_item(&mut acct, b"0"); // pwprotect
        push_item(&mut acct, b""); // genpw
        push_item(&mut acct, b""); // sn
        push_item(&mut acct, b""); // last_touch
        for _ in 0..13 {
            push_item(&mut acct, b"");
        }
        push_item(&mut acct, b""); // attachkey_encrypted
        push_item(&mut acct, b"0"); // attachpresent
        push_item(&mut acct, b""); // individualshare
        push_item(&mut acct, b""); // notetype
        push_item(&mut acct, b""); // noalert
        push_item(&mut acct, b""); // last_modified_gmt
        push_item(&mut acct, b""); // hasbeenshared
        push_item(&mut acct, b""); // last_pwchange_gmt
        push_item(&mut acct, b""); // created_gmt
        push_item(&mut acct, b""); // vulnerable
        push_chunk(&mut blob_bytes, "ACCT", &acct);

        let blob = blob_parse(&blob_bytes, &key, None).expect("blob");
        assert_eq!(blob.version, 1);
        assert_eq!(blob.accounts.len(), 1);
        let account = &blob.accounts[0];
        assert_eq!(account.name, "test-account");
        assert_eq!(account.group, "test-group");
        assert_eq!(account.url, "https://example.com/");
        assert_eq!(account.fullname, "test-group/test-account");
    }

    #[test]
    fn blob_parse_rejects_missing_version_and_truncation() {
        let key = [1u8; 32];
        let err = blob_parse(b"", &key, None).expect_err("missing version must fail");
        assert!(matches!(err, LpassError::Crypto("missing blob version")));

        let mut broken = Vec::new();
        broken.extend_from_slice(b"LPAV");
        broken.extend_from_slice(&10u32.to_be_bytes());
        broken.extend_from_slice(b"1");
        let err = blob_parse(&broken, &key, None).expect_err("truncated blob must fail");
        assert!(matches!(err, LpassError::Crypto("blob truncated")));
    }

    #[test]
    fn primitive_readers_cover_edge_cases() {
        let mut pos = 0usize;
        let value = read_be_u32(&[0, 0, 0, 5], &mut pos).expect("read u32");
        assert_eq!(value, 5);
        assert_eq!(pos, 4);
        let mut short_pos = 0usize;
        let err = read_be_u32(&[0, 0], &mut short_pos).expect_err("short read must fail");
        assert!(matches!(err, LpassError::Crypto("read past end")));

        let mut body = Vec::new();
        push_item(&mut body, b"");
        push_item(&mut body, b"313233");
        push_item(&mut body, b"x");
        push_item(&mut body, b"1");
        push_item(&mut body, b"0");
        let mut chunk = ChunkCursor::new("TEST".to_string(), &body);
        assert_eq!(read_plain_string(&mut chunk).expect("empty"), "");
        assert_eq!(read_hex_string(&mut chunk).expect("hex"), "123");
        assert!(read_hex_string(&mut chunk).is_err());
        assert!(read_boolean(&mut chunk).expect("bool true"));
        assert!(!read_boolean(&mut chunk).expect("bool false"));
    }

    #[test]
    fn crypt_helpers_cover_empty_and_detection_paths() {
        let key = [3u8; 32];
        let mut body = Vec::new();
        push_item(&mut body, b"");
        let encrypted = aes_encrypt_lastpass(b"value", &key).expect("encrypt");
        push_item(&mut body, &encrypted);
        let mut chunk = ChunkCursor::new("TEST".to_string(), &body);
        let (empty, enc_empty) = read_crypt_string(&mut chunk, &key).expect("empty");
        assert_eq!(empty, "");
        assert!(enc_empty.is_some());
        let (value, enc_value) = read_crypt_string(&mut chunk, &key).expect("value");
        assert_eq!(value, "value");
        assert!(enc_value.is_some());

        let mut body2 = Vec::new();
        push_item(&mut body2, b"!abc");
        let chunk2 = ChunkCursor::new("TEST".to_string(), &body2);
        assert!(check_next_entry_encrypted(&chunk2));
    }

    #[test]
    fn parse_field_supports_encrypted_and_plain_types() {
        let key = [5u8; 32];
        let mut encrypted_body = Vec::new();
        push_item(&mut encrypted_body, b"Hostname");
        push_item(&mut encrypted_body, b"text");
        let encrypted = aes_encrypt_lastpass(b"srv", &key).expect("encrypt");
        push_item(&mut encrypted_body, &encrypted);
        push_item(&mut encrypted_body, b"1");
        let mut encrypted_chunk = ChunkCursor::new("ACFL".to_string(), &encrypted_body);
        let field = parse_field(&mut encrypted_chunk, &key).expect("field");
        assert_eq!(field.name, "Hostname");
        assert_eq!(field.value, "srv");
        assert!(field.checked);
        assert!(field.value_encrypted.is_some());

        let mut plain_body = Vec::new();
        push_item(&mut plain_body, b"TOTP");
        push_item(&mut plain_body, b"checkbox");
        push_item(&mut plain_body, b"yes");
        push_item(&mut plain_body, b"0");
        let mut plain_chunk = ChunkCursor::new("ACOF".to_string(), &plain_body);
        let field = parse_field(&mut plain_chunk, &key).expect("plain field");
        assert_eq!(field.value, "yes");
        assert_eq!(field.value_encrypted, None);
        assert!(!field.checked);
    }

    #[test]
    fn parse_account_decodes_legacy_hex_url() {
        let key = [9u8; 32];
        let mut acct = Vec::new();
        push_item(&mut acct, b"0002");
        push_item(
            &mut acct,
            &aes_encrypt_lastpass(b"legacy", &key).expect("name enc"),
        );
        push_item(
            &mut acct,
            &aes_encrypt_lastpass(b"group", &key).expect("group enc"),
        );
        push_item(&mut acct, b"68747470733a2f2f6578616d706c652e636f6d2f");
        push_item(
            &mut acct,
            &aes_encrypt_lastpass(b"", &key).expect("note enc"),
        );
        push_item(&mut acct, b"0");
        push_item(&mut acct, b"");
        push_item(
            &mut acct,
            &aes_encrypt_lastpass(b"user", &key).expect("user enc"),
        );
        push_item(
            &mut acct,
            &aes_encrypt_lastpass(b"pass", &key).expect("pass enc"),
        );
        push_item(&mut acct, b"0");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        for _ in 0..13 {
            push_item(&mut acct, b"");
        }
        push_item(&mut acct, b"");
        push_item(&mut acct, b"0");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");
        push_item(&mut acct, b"");

        let mut chunk = ChunkCursor::new("ACCT".to_string(), &acct);
        let account = parse_account(&mut chunk, &key).expect("account");
        assert_eq!(account.url, "https://example.com/");
        assert_eq!(account.fullname, "group/legacy");
    }
}
