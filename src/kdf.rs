#![forbid(unsafe_code)]

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{LpassError, Result};
use crate::util::bytes_to_hex;

pub const KDF_HASH_LEN: usize = 32;
pub const KDF_HEX_LEN: usize = KDF_HASH_LEN * 2;
pub const MINIMUM_ITERATIONS: u32 = 2;

pub fn kdf_login_key(username: &str, password: &str, iterations: u32) -> Result<String> {
    if iterations < MINIMUM_ITERATIONS {
        return Err(LpassError::InvalidIterations(iterations));
    }

    let mut user_lower = username.to_ascii_lowercase();
    let mut hash = [0u8; KDF_HASH_LEN];

    pbkdf2_hmac::<Sha256>(password.as_bytes(), user_lower.as_bytes(), iterations, &mut hash);
    let mut login_hash = [0u8; KDF_HASH_LEN];
    pbkdf2_hmac::<Sha256>(&hash, password.as_bytes(), 1, &mut login_hash);

    let hex = bytes_to_hex(&login_hash);
    user_lower.zeroize();
    hash.zeroize();
    login_hash.zeroize();

    Ok(hex)
}

pub fn kdf_decryption_key(
    username: &str,
    password: &str,
    iterations: u32,
) -> Result<[u8; KDF_HASH_LEN]> {
    if iterations < MINIMUM_ITERATIONS {
        return Err(LpassError::InvalidIterations(iterations));
    }

    let mut user_lower = username.to_ascii_lowercase();
    let mut hash = [0u8; KDF_HASH_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), user_lower.as_bytes(), iterations, &mut hash);
    user_lower.zeroize();
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_matches_reference_vectors() {
        let username = "user@example.com";
        let password = "password";
        let iterations = 2;

        let login = kdf_login_key(username, password, iterations).expect("login key");
        assert_eq!(
            login,
            "74cad137c2a0359b825640cc52a6c0e852dbffaa7a1bf9be88dc3d161edb6a55"
        );

        let decrypt = kdf_decryption_key(username, password, iterations).expect("dec key");
        assert_eq!(
            bytes_to_hex(&decrypt),
            "d46f3846aba080354bc8f896b20d3c534c6f9651c375b9e6e64ba916b3e4dd0f"
        );
    }

    #[test]
    fn kdf_rejects_low_iterations() {
        let err = kdf_login_key("user", "pass", 1).expect_err("should fail");
        match err {
            LpassError::InvalidIterations(1) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
