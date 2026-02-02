#![forbid(unsafe_code)]

use crate::config::ConfigStore;
use crate::error::{LpassError, Result};
use crate::kdf::KDF_HASH_LEN;

#[derive(Debug, Clone, Default)]
pub struct Session {
    pub uid: String,
    pub session_id: String,
    pub token: String,
    pub server: Option<String>,
    pub private_key: Option<Vec<u8>>,
    pub private_key_enc: Option<String>,
}

impl Session {
    pub fn is_valid(&self) -> bool {
        !self.uid.is_empty() && !self.session_id.is_empty() && !self.token.is_empty()
    }

    pub fn set_private_key_enc(&mut self, private_key_enc: &str) {
        self.private_key_enc = Some(private_key_enc.to_string());
    }
}

pub fn session_load(key: &[u8; KDF_HASH_LEN]) -> Result<Option<Session>> {
    session_load_with_store(&ConfigStore::from_current(), key)
}

pub fn session_load_with_store(
    store: &ConfigStore,
    key: &[u8; KDF_HASH_LEN],
) -> Result<Option<Session>> {
    let uid = store.read_encrypted_string("session_uid", key)?;
    let session_id = store.read_encrypted_string("session_sessionid", key)?;
    let token = store.read_encrypted_string("session_token", key)?;
    let server = store.read_string("session_server")?;
    let private_key = store.read_encrypted_buffer("session_privatekey", key)?;
    let private_key_enc = store.read_encrypted_string("session_privatekeyenc", key)?;

    let session = Session {
        uid: uid.unwrap_or_default(),
        session_id: session_id.unwrap_or_default(),
        token: token.unwrap_or_default(),
        server,
        private_key,
        private_key_enc,
    };

    if session.is_valid() {
        Ok(Some(session))
    } else {
        Ok(None)
    }
}

pub fn session_save(session: &Session, key: &[u8; KDF_HASH_LEN]) -> Result<()> {
    session_save_with_store(&ConfigStore::from_current(), session, key)
}

pub fn session_save_with_store(
    store: &ConfigStore,
    session: &Session,
    key: &[u8; KDF_HASH_LEN],
) -> Result<()> {
    if !session.is_valid() {
        return Err(LpassError::Crypto("invalid session"));
    }

    store.write_encrypted_string("session_uid", &session.uid, key)?;
    store.write_encrypted_string("session_sessionid", &session.session_id, key)?;
    store.write_encrypted_string("session_token", &session.token, key)?;

    if let Some(private_key) = &session.private_key {
        store.write_encrypted_buffer("session_privatekey", private_key, key)?;
    } else {
        let _ = store.unlink("session_privatekey");
    }

    if let Some(private_key_enc) = &session.private_key_enc {
        store.write_encrypted_string("session_privatekeyenc", private_key_enc, key)?;
    } else {
        let _ = store.unlink("session_privatekeyenc");
    }

    if let Some(server) = &session.server {
        store.write_string("session_server", server)?;
    }

    Ok(())
}

pub fn session_kill() -> Result<()> {
    let store = ConfigStore::from_current();
    let _ = store.unlink("verify");
    let _ = store.unlink("username");
    let _ = store.unlink("session_sessionid");
    let _ = store.unlink("iterations");
    let _ = store.unlink("blob");
    let _ = store.unlink("blob.json");
    let _ = store.unlink("session_token");
    let _ = store.unlink("session_uid");
    let _ = store.unlink("session_privatekey");
    let _ = store.unlink("session_privatekeyenc");
    let _ = store.unlink("session_server");
    let _ = store.unlink("plaintext_key");
    let _ = store.unlink("uploader.pid");
    let _ = store.unlink("session_ff_url_encryption");
    let _ = store.unlink("session_ff_url_logging");
    let _ = crate::agent::agent_kill();
    let _ = store.unlink("agent.sock");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigEnv, ConfigStore};
    use tempfile::TempDir;

    fn store_with_home() -> (ConfigStore, TempDir) {
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });
        (store, temp)
    }

    #[test]
    fn session_save_load_roundtrip() {
        let (store, _temp) = store_with_home();
        let key = [3u8; KDF_HASH_LEN];
        let session = Session {
            uid: "u1".to_string(),
            session_id: "s1".to_string(),
            token: "t1".to_string(),
            server: Some("lastpass.com".to_string()),
            private_key: Some(vec![1, 2, 3]),
            private_key_enc: None,
        };

        session_save_with_store(&store, &session, &key).expect("save");
        let loaded = session_load_with_store(&store, &key)
            .expect("load")
            .expect("session");

        assert_eq!(loaded.uid, "u1");
        assert_eq!(loaded.session_id, "s1");
        assert_eq!(loaded.token, "t1");
        assert_eq!(loaded.server.as_deref(), Some("lastpass.com"));
        assert_eq!(loaded.private_key.as_deref(), Some(&[1, 2, 3][..]));
    }
}
