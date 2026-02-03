#![forbid(unsafe_code)]

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::Sha256;

use crate::error::{LpassError, Result};

const HMAC_LEN: usize = 32;
const IV_LEN: usize = 16;
const LP_PKEY_PREFIX: &str = "LastPassPrivateKey<";
const LP_PKEY_SUFFIX: &str = ">LastPassPrivateKey";

type HmacSha256 = Hmac<Sha256>;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn encrypt_authenticated(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);

    let mut buffer = plaintext.to_vec();
    let padded_len = ((buffer.len() / IV_LEN) + 1) * IV_LEN;
    buffer.resize(padded_len, 0u8);

    let ciphertext = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|_| LpassError::Crypto("AES-CBC encrypt failed"))?
        .to_vec();

    let mut out = Vec::with_capacity(HMAC_LEN + IV_LEN + ciphertext.len());
    out.extend_from_slice(&[0u8; HMAC_LEN]);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| LpassError::Crypto("invalid HMAC key length"))?;
    mac.update(&out[HMAC_LEN..]);
    let tag = mac.finalize().into_bytes();
    out[..HMAC_LEN].copy_from_slice(&tag);

    Ok(out)
}

pub fn decrypt_authenticated(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < HMAC_LEN + IV_LEN + IV_LEN {
        return Err(LpassError::Crypto("ciphertext too short"));
    }

    let (tag, rest) = ciphertext.split_at(HMAC_LEN);
    let (iv, data) = rest.split_at(IV_LEN);

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| LpassError::Crypto("invalid HMAC key length"))?;
    mac.update(rest);
    mac.verify_slice(tag)
        .map_err(|_| LpassError::Crypto("HMAC verification failed"))?;

    let mut buffer = data.to_vec();
    let plaintext = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| LpassError::Crypto("AES-CBC decrypt failed"))?
        .to_vec();

    Ok(plaintext)
}

pub fn aes_encrypt_lastpass(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let mut iv = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv);

    let mut buffer = plaintext.to_vec();
    let padded_len = ((buffer.len() / IV_LEN) + 1) * IV_LEN;
    buffer.resize(padded_len, 0u8);

    let ciphertext = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|_| LpassError::Crypto("AES-CBC encrypt failed"))?
        .to_vec();

    let mut out = Vec::with_capacity(1 + IV_LEN + ciphertext.len());
    out.push(b'!');
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn aes_decrypt_lastpass(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() {
        return Err(LpassError::Crypto("ciphertext empty"));
    }

    if ciphertext[0] == b'!' {
        if ciphertext.len() < 1 + IV_LEN {
            return Err(LpassError::Crypto("ciphertext too short"));
        }
        let iv = &ciphertext[1..1 + IV_LEN];
        let data = &ciphertext[1 + IV_LEN..];

        let mut buffer = data.to_vec();
        let plaintext = Aes256CbcDec::new(key.into(), iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|_| LpassError::Crypto("AES-CBC decrypt failed"))?
            .to_vec();
        Ok(plaintext)
    } else {
        use cipher::block_padding::Pkcs7 as EcbPkcs7;
        use cipher::{BlockDecryptMut as _, KeyInit as _};
        use ecb::Decryptor as EcbDecryptor;

        let mut buffer = ciphertext.to_vec();
        let plaintext = EcbDecryptor::<Aes256>::new(key.into())
            .decrypt_padded_mut::<EcbPkcs7>(&mut buffer)
            .map_err(|_| LpassError::Crypto("AES-ECB decrypt failed"))?
            .to_vec();
        Ok(plaintext)
    }
}

pub fn decrypt_private_key(private_key_enc: &str, key: &[u8; 32]) -> Result<Vec<u8>> {
    let decrypted = if private_key_enc.starts_with('!') {
        aes_decrypt_base64_lastpass(private_key_enc, key)?
    } else {
        if private_key_enc.len() % 2 != 0 {
            return Err(LpassError::Crypto("invalid private key format"));
        }
        let mut encrypted = Vec::with_capacity(1 + 16 + private_key_enc.len() / 2);
        encrypted.push(b'!');
        encrypted.extend_from_slice(&key[..16]);
        let hex_bytes =
            hex::decode(private_key_enc).map_err(|_| LpassError::Crypto("invalid private key"))?;
        encrypted.extend_from_slice(&hex_bytes);
        aes_decrypt_lastpass(&encrypted, key)?
    };

    let text = String::from_utf8_lossy(&decrypted);
    let start = text
        .find(LP_PKEY_PREFIX)
        .map(|idx| idx + LP_PKEY_PREFIX.len())
        .ok_or(LpassError::Crypto("missing private key prefix"))?;
    let end = text
        .find(LP_PKEY_SUFFIX)
        .ok_or(LpassError::Crypto("missing private key suffix"))?;
    if end <= start {
        return Err(LpassError::Crypto("invalid private key"));
    }

    let key_hex = text[start..end]
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    if key_hex.is_empty() || key_hex.len() % 2 != 0 {
        return Err(LpassError::Crypto("invalid private key"));
    }
    hex::decode(key_hex).map_err(|_| LpassError::Crypto("invalid private key"))
}

pub fn rsa_decrypt_oaep(private_key_der: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(private_key_der))
        .map_err(|_| LpassError::Crypto("invalid rsa private key"))?;
    private_key
        .decrypt(Oaep::new::<Sha1>(), ciphertext)
        .map_err(|_| LpassError::Crypto("RSA decrypt failed"))
}

pub fn base64_lastpass_encode(bytes: &[u8]) -> String {
    if bytes.len() >= 33 && bytes[0] == b'!' && bytes.len() % 16 == 1 {
        let iv = &bytes[1..1 + IV_LEN];
        let data = &bytes[1 + IV_LEN..];
        format!("!{}|{}", BASE64_STD.encode(iv), BASE64_STD.encode(data))
    } else {
        BASE64_STD.encode(bytes)
    }
}

pub fn base64_lastpass_decode(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        return Err(LpassError::Crypto("base64 empty"));
    }

    if !s.starts_with('!') {
        return BASE64_STD
            .decode(s.as_bytes())
            .map_err(|_| LpassError::Crypto("base64 decode failed"));
    }

    let trimmed = &s[1..];
    let mut parts = trimmed.splitn(2, '|');
    let iv_b64 = parts.next().unwrap_or("");
    let data_b64 = parts.next().unwrap_or("");
    if iv_b64.is_empty() || data_b64.is_empty() {
        return Err(LpassError::Crypto("invalid base64 format"));
    }
    let iv = BASE64_STD
        .decode(iv_b64.as_bytes())
        .map_err(|_| LpassError::Crypto("base64 decode failed"))?;
    let data = BASE64_STD
        .decode(data_b64.as_bytes())
        .map_err(|_| LpassError::Crypto("base64 decode failed"))?;

    let mut out = Vec::with_capacity(1 + iv.len() + data.len());
    out.push(b'!');
    out.extend_from_slice(&iv);
    out.extend_from_slice(&data);
    Ok(out)
}

pub fn aes_decrypt_base64_lastpass(ciphertext_b64: &str, key: &[u8; 32]) -> Result<Vec<u8>> {
    let bytes = base64_lastpass_decode(ciphertext_b64)?;
    aes_decrypt_lastpass(&bytes, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let plaintext = b"secret payload";
        let encrypted = encrypt_authenticated(&key, plaintext).expect("encrypt");
        let decrypted = decrypt_authenticated(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_tampered_data() {
        let key = [42u8; 32];
        let plaintext = b"secret payload";
        let mut encrypted = encrypt_authenticated(&key, plaintext).expect("encrypt");
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x55;
        let err = decrypt_authenticated(&key, &encrypted).expect_err("should fail");
        match err {
            LpassError::Crypto(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn base64_lastpass_roundtrip() {
        let key = [1u8; 32];
        let plaintext = b"hello";
        let encrypted = aes_encrypt_lastpass(plaintext, &key).expect("encrypt");
        let encoded = base64_lastpass_encode(&encrypted);
        let decoded = base64_lastpass_decode(&encoded).expect("decode");
        let decrypted = aes_decrypt_lastpass(&decoded, &key).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_authenticated_rejects_short_ciphertext() {
        let key = [7u8; 32];
        let err = decrypt_authenticated(&key, b"short").expect_err("must fail");
        assert!(matches!(err, LpassError::Crypto("ciphertext too short")));
    }

    #[test]
    fn aes_lastpass_encrypt_decrypt_and_errors() {
        let key = [9u8; 32];
        let plaintext = b"payload";
        let encrypted = aes_encrypt_lastpass(plaintext, &key).expect("encrypt");
        let decrypted = aes_decrypt_lastpass(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, plaintext);

        let err = aes_decrypt_lastpass(b"", &key).expect_err("empty must fail");
        assert!(matches!(err, LpassError::Crypto("ciphertext empty")));

        let err = aes_decrypt_lastpass(b"!", &key).expect_err("short must fail");
        assert!(matches!(err, LpassError::Crypto("ciphertext too short")));
    }

    #[test]
    fn base64_lastpass_decode_rejects_invalid_inputs() {
        let err = base64_lastpass_decode("").expect_err("empty must fail");
        assert!(matches!(err, LpassError::Crypto("base64 empty")));

        let err = base64_lastpass_decode("!abc").expect_err("format must fail");
        assert!(matches!(err, LpassError::Crypto("invalid base64 format")));

        let err = base64_lastpass_decode("!!!|!!!").expect_err("decode must fail");
        assert!(matches!(err, LpassError::Crypto("base64 decode failed")));
    }

    #[test]
    fn aes_decrypt_base64_lastpass_roundtrip() {
        let key = [11u8; 32];
        let encrypted = aes_encrypt_lastpass(b"xyz", &key).expect("encrypt");
        let encoded = base64_lastpass_encode(&encrypted);
        let decrypted = aes_decrypt_base64_lastpass(&encoded, &key).expect("decrypt");
        assert_eq!(decrypted, b"xyz");
    }

    #[test]
    fn decrypt_private_key_rejects_invalid_formats() {
        let key = [13u8; 32];
        let err = decrypt_private_key("abc", &key).expect_err("odd hex must fail");
        assert!(matches!(
            err,
            LpassError::Crypto("invalid private key format")
        ));

        let err = decrypt_private_key("zz", &key).expect_err("invalid hex must fail");
        assert!(matches!(err, LpassError::Crypto("invalid private key")));
    }

    #[test]
    fn rsa_decrypt_oaep_rejects_invalid_private_key() {
        let err = rsa_decrypt_oaep(b"not-a-key", b"ciphertext").expect_err("must fail");
        assert!(matches!(err, LpassError::Crypto("invalid rsa private key")));
    }
}
