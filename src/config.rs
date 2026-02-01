#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use filetime::{set_file_mtime, FileTime};

use crate::crypto::{decrypt_authenticated, encrypt_authenticated};
use crate::error::{LpassError, Result};
use crate::kdf::KDF_HASH_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigType {
    Data,
    Config,
    Runtime,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigEnv {
    pub lpass_home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_runtime_dir: Option<PathBuf>,
    pub home: Option<PathBuf>,
}

impl ConfigEnv {
    pub fn from_current() -> Self {
        Self {
            lpass_home: env::var_os("LPASS_HOME").map(PathBuf::from),
            xdg_data_home: env::var_os("XDG_DATA_HOME").map(PathBuf::from),
            xdg_config_home: env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            xdg_runtime_dir: env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            home: env::var_os("HOME").map(PathBuf::from),
        }
    }
}

pub struct ConfigStore {
    env: ConfigEnv,
}

impl ConfigStore {
    pub fn from_current() -> Self {
        Self {
            env: ConfigEnv::from_current(),
        }
    }

    pub fn with_env(env: ConfigEnv) -> Self {
        Self { env }
    }

    pub fn path(&self, name: &str) -> Result<PathBuf> {
        config_path_for_type_with_env(&self.env, config_path_type(name), name)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name)
            .and_then(|path| fs::metadata(path).map_err(|err| LpassError::io("stat", err)))
            .is_ok()
    }

    pub fn unlink(&self, name: &str) -> Result<bool> {
        let path = self.path(name)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(LpassError::io("unlink", err)),
        }
    }

    pub fn mtime(&self, name: &str) -> Result<Option<SystemTime>> {
        let path = self.path(name)?;
        match fs::metadata(path) {
            Ok(metadata) => Ok(metadata.modified().ok()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(LpassError::io("stat", err)),
        }
    }

    pub fn touch(&self, name: &str) -> Result<()> {
        let path = self.path(name)?;
        let now = FileTime::from_system_time(SystemTime::now());
        set_file_mtime(path, now).map_err(|err| LpassError::io("utime", err))
    }

    pub fn write_string(&self, name: &str, value: &str) -> Result<()> {
        self.write_buffer(name, value.as_bytes())
    }

    pub fn write_buffer(&self, name: &str, buffer: &[u8]) -> Result<()> {
        let path = self.path(name)?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .map_err(|err| LpassError::io("mkstemp", err))?;
        temp.write_all(buffer)
            .map_err(|err| LpassError::io("write", err))?;
        temp.flush().map_err(|err| LpassError::io("flush", err))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            temp.as_file()
                .set_permissions(perms)
                .map_err(|err| LpassError::io("chmod", err))?;
        }

        temp.persist(&path)
            .map_err(|err| LpassError::io("rename", err.error))?;
        Ok(())
    }

    pub fn read_string(&self, name: &str) -> Result<Option<String>> {
        match self.read_buffer(name)? {
            Some(buffer) => String::from_utf8(buffer)
                .map(Some)
                .map_err(|_| LpassError::InvalidUtf8),
            None => Ok(None),
        }
    }

    pub fn read_buffer(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(name)?;
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(LpassError::io("open", err)),
        };

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|err| LpassError::io("read", err))?;
        Ok(Some(buffer))
    }

    pub fn write_encrypted_string(
        &self,
        name: &str,
        value: &str,
        key: &[u8; KDF_HASH_LEN],
    ) -> Result<()> {
        self.write_encrypted_buffer(name, value.as_bytes(), key)
    }

    pub fn write_encrypted_buffer(
        &self,
        name: &str,
        buffer: &[u8],
        key: &[u8; KDF_HASH_LEN],
    ) -> Result<()> {
        let encrypted = encrypt_authenticated(key, buffer)?;
        self.write_buffer(name, &encrypted)
    }

    pub fn read_encrypted_string(
        &self,
        name: &str,
        key: &[u8; KDF_HASH_LEN],
    ) -> Result<Option<String>> {
        match self.read_encrypted_buffer(name, key)? {
            Some(buffer) => String::from_utf8(buffer)
                .map(Some)
                .map_err(|_| LpassError::InvalidUtf8),
            None => Ok(None),
        }
    }

    pub fn read_encrypted_buffer(
        &self,
        name: &str,
        key: &[u8; KDF_HASH_LEN],
    ) -> Result<Option<Vec<u8>>> {
        let encrypted = match self.read_buffer(name)? {
            Some(buffer) => buffer,
            None => return Ok(None),
        };
        let decrypted = decrypt_authenticated(key, &encrypted)?;
        Ok(Some(decrypted))
    }
}

const PATHNAME_TYPE_LOOKUP: &[(&str, ConfigType)] = &[
    ("env", ConfigType::Config),
    ("blob", ConfigType::Data),
    ("iterations", ConfigType::Data),
    ("username", ConfigType::Data),
    ("verify", ConfigType::Data),
    ("plaintext_key", ConfigType::Data),
    ("trusted_id", ConfigType::Data),
    ("session_uid", ConfigType::Data),
    ("session_sessionid", ConfigType::Data),
    ("session_token", ConfigType::Data),
    ("session_privatekey", ConfigType::Data),
    ("session_privatekeyenc", ConfigType::Data),
    ("session_server", ConfigType::Data),
    ("lpass.log", ConfigType::Data),
    ("agent.sock", ConfigType::Runtime),
    ("uploader.pid", ConfigType::Runtime),
];

fn config_type_to_xdg(config_type: ConfigType) -> &'static str {
    match config_type {
        ConfigType::Data => "XDG_DATA_HOME",
        ConfigType::Config => "XDG_CONFIG_HOME",
        ConfigType::Runtime => "XDG_RUNTIME_DIR",
    }
}

pub fn config_path_type(name: &str) -> ConfigType {
    if name.starts_with("alias") {
        return ConfigType::Config;
    }

    if name.ends_with(".lock") {
        return ConfigType::Runtime;
    }

    for (candidate, config_type) in PATHNAME_TYPE_LOOKUP {
        if name == *candidate {
            return *config_type;
        }
    }

    ConfigType::Data
}

fn get_xdg_dir(env: &ConfigEnv, xdg_var: &str) -> Option<PathBuf> {
    match xdg_var {
        "XDG_DATA_HOME" => {
            if let Some(path) = env.xdg_data_home.as_ref() {
                return Some(path.clone());
            }
        }
        "XDG_CONFIG_HOME" => {
            if let Some(path) = env.xdg_config_home.as_ref() {
                return Some(path.clone());
            }
        }
        "XDG_RUNTIME_DIR" => {
            return env.xdg_runtime_dir.clone();
        }
        _ => {}
    }

    if env.xdg_runtime_dir.is_none() {
        return None;
    }

    let home = env.home.as_ref()?;
    match xdg_var {
        "XDG_DATA_HOME" => Some(home.join(".local/share")),
        "XDG_CONFIG_HOME" => Some(home.join(".config")),
        _ => None,
    }
}

fn ensure_dir(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if metadata.is_dir() {
                return Ok(());
            }
            fs::remove_file(path).map_err(|err| LpassError::io("remove file", err))?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(LpassError::io("stat", err)),
    }

    fs::create_dir_all(path).map_err(|err| LpassError::io("mkdir", err))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perms).map_err(|err| LpassError::io("chmod", err))?;
    }

    Ok(())
}

fn ensure_parent_dirs(base: &Path, name: &str) -> Result<()> {
    let rel = Path::new(name);
    let parent = match rel.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => return Ok(()),
    };

    let mut current = PathBuf::from(base);
    for component in parent.components() {
        current.push(component);
        ensure_dir(&current)?;
    }

    Ok(())
}

fn config_base_dir_for_type_with_env(env: &ConfigEnv, config_type: ConfigType) -> Result<PathBuf> {
    if let Some(home) = env.lpass_home.as_ref() {
        return Ok(home.clone());
    }

    let xdg_env = config_type_to_xdg(config_type);
    if let Some(xdg_dir) = get_xdg_dir(env, xdg_env) {
        return Ok(xdg_dir.join("lpass"));
    }

    let home = env.home.as_ref().ok_or(LpassError::MissingHome)?;
    Ok(home.join(".lpass"))
}

pub fn config_path_for_type(config_type: ConfigType, name: &str) -> Result<PathBuf> {
    config_path_for_type_with_env(&ConfigEnv::from_current(), config_type, name)
}

pub fn config_path_for_type_with_env(
    env: &ConfigEnv,
    config_type: ConfigType,
    name: &str,
) -> Result<PathBuf> {
    let base = config_base_dir_for_type_with_env(env, config_type)?;
    ensure_dir(&base)?;
    ensure_parent_dirs(&base, name)?;
    Ok(base.join(name))
}

pub fn config_path(name: &str) -> Result<PathBuf> {
    config_path_for_type_with_env(&ConfigEnv::from_current(), config_path_type(name), name)
}

pub fn config_exists(name: &str) -> bool {
    ConfigStore::from_current().exists(name)
}

pub fn config_unlink(name: &str) -> Result<bool> {
    ConfigStore::from_current().unlink(name)
}

pub fn config_mtime(name: &str) -> Result<Option<SystemTime>> {
    ConfigStore::from_current().mtime(name)
}

pub fn config_touch(name: &str) -> Result<()> {
    ConfigStore::from_current().touch(name)
}

pub fn config_write_string(name: &str, value: &str) -> Result<()> {
    ConfigStore::from_current().write_string(name, value)
}

pub fn config_write_buffer(name: &str, buffer: &[u8]) -> Result<()> {
    ConfigStore::from_current().write_buffer(name, buffer)
}

pub fn config_read_string(name: &str) -> Result<Option<String>> {
    ConfigStore::from_current().read_string(name)
}

pub fn config_read_buffer(name: &str) -> Result<Option<Vec<u8>>> {
    ConfigStore::from_current().read_buffer(name)
}

pub fn config_write_encrypted_string(
    name: &str,
    value: &str,
    key: &[u8; KDF_HASH_LEN],
) -> Result<()> {
    ConfigStore::from_current().write_encrypted_string(name, value, key)
}

pub fn config_write_encrypted_buffer(
    name: &str,
    buffer: &[u8],
    key: &[u8; KDF_HASH_LEN],
) -> Result<()> {
    ConfigStore::from_current().write_encrypted_buffer(name, buffer, key)
}

pub fn config_read_encrypted_string(
    name: &str,
    key: &[u8; KDF_HASH_LEN],
) -> Result<Option<String>> {
    ConfigStore::from_current().read_encrypted_string(name, key)
}

pub fn config_read_encrypted_buffer(
    name: &str,
    key: &[u8; KDF_HASH_LEN],
) -> Result<Option<Vec<u8>>> {
    ConfigStore::from_current().read_encrypted_buffer(name, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn env_with_home(home: &Path) -> ConfigEnv {
        ConfigEnv {
            home: Some(home.to_path_buf()),
            ..ConfigEnv::default()
        }
    }

    #[test]
    fn config_path_uses_lpass_home() {
        let temp = TempDir::new().expect("tempdir");
        let env = ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        };

        let path = config_path_for_type_with_env(&env, ConfigType::Data, "blob").expect("path");
        assert_eq!(path, temp.path().join("blob"));
        assert!(temp.path().is_dir());
    }

    #[test]
    fn config_path_uses_xdg_data_home() {
        let base = TempDir::new().expect("tempdir");
        let runtime = TempDir::new().expect("tempdir");
        let env = ConfigEnv {
            xdg_data_home: Some(base.path().to_path_buf()),
            xdg_runtime_dir: Some(runtime.path().to_path_buf()),
            ..ConfigEnv::default()
        };

        let path = config_path_for_type_with_env(&env, ConfigType::Data, "blob").expect("path");
        assert_eq!(path, base.path().join("lpass").join("blob"));
    }

    #[test]
    fn config_path_falls_back_to_home_when_runtime_set() {
        let home = TempDir::new().expect("tempdir");
        let runtime = TempDir::new().expect("tempdir");
        let env = ConfigEnv {
            home: Some(home.path().to_path_buf()),
            xdg_runtime_dir: Some(runtime.path().to_path_buf()),
            ..ConfigEnv::default()
        };

        let path = config_path_for_type_with_env(&env, ConfigType::Data, "blob").expect("path");
        assert_eq!(
            path,
            home.path()
                .join(".local/share")
                .join("lpass")
                .join("blob")
        );
    }

    #[test]
    fn config_path_defaults_to_dot_lpass() {
        let home = TempDir::new().expect("tempdir");
        let env = env_with_home(home.path());

        let path = config_path_for_type_with_env(&env, ConfigType::Data, "blob").expect("path");
        assert_eq!(path, home.path().join(".lpass").join("blob"));
    }

    #[test]
    fn config_path_creates_nested_dirs() {
        let temp = TempDir::new().expect("tempdir");
        let env = ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        };

        let path = config_path_for_type_with_env(&env, ConfigType::Data, "nested/dir/item")
            .expect("path");
        assert_eq!(path, temp.path().join("nested/dir/item"));
        assert!(temp.path().join("nested").is_dir());
        assert!(temp.path().join("nested/dir").is_dir());
    }

    #[test]
    fn config_read_write_roundtrip() {
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        store.write_string("username", "alice").expect("write");
        let value = store.read_string("username").expect("read");
        assert_eq!(value.as_deref(), Some("alice"));
    }

    #[test]
    fn config_encrypted_roundtrip() {
        let temp = TempDir::new().expect("tempdir");
        let store = ConfigStore::with_env(ConfigEnv {
            lpass_home: Some(temp.path().to_path_buf()),
            ..ConfigEnv::default()
        });

        let key = [9u8; KDF_HASH_LEN];
        store
            .write_encrypted_string("secret", "hunter2", &key)
            .expect("write");
        let value = store
            .read_encrypted_string("secret", &key)
            .expect("read");
        assert_eq!(value.as_deref(), Some("hunter2"));
    }
}
