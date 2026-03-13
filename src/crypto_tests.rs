use super::*;
use aes::Aes256;
use cbc::Encryptor as Aes256CbcEncryptor;
use cipher::block_padding::Pkcs7;
use cipher::{BlockEncryptMut, KeyInit, KeyIvInit};
use ecb::Encryptor as Aes256EcbEncryptor;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePublicKey;

fn encrypt_legacy_private_key_payload(payload: &str, key: &[u8; 32]) -> String {
    let mut buffer = payload.as_bytes().to_vec();
    let msg_len = buffer.len();
    buffer.resize(msg_len + 16, 0);
    let ciphertext = Aes256CbcEncryptor::<Aes256>::new(key.into(), (&key[..16]).into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, msg_len)
        .expect("encrypt legacy private key")
        .to_vec();
    hex::encode(ciphertext)
}

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
fn aes_decrypt_lastpass_supports_legacy_ecb_ciphertexts() {
    let key = [19u8; 32];
    let plaintext = b"legacy ecb payload";
    let mut buffer = plaintext.to_vec();
    let msg_len = buffer.len();
    buffer.resize(msg_len + 16, 0);
    let ciphertext = Aes256EcbEncryptor::<Aes256>::new((&key).into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, msg_len)
        .expect("encrypt legacy ecb")
        .to_vec();

    let decrypted = aes_decrypt_lastpass(&ciphertext, &key).expect("decrypt legacy ecb");
    assert_eq!(decrypted, plaintext);
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
fn decrypt_private_key_supports_legacy_hex_payload() {
    let key = [17u8; 32];
    let private_key = vec![0x30, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef];
    let payload = format!(
        "{LP_PKEY_PREFIX}{}{LP_PKEY_SUFFIX}",
        hex::encode(&private_key)
    );
    let legacy_hex = encrypt_legacy_private_key_payload(&payload, &key);
    let decrypted = decrypt_private_key(&legacy_hex, &key).expect("decrypt legacy private key");
    assert_eq!(decrypted, private_key);
}

#[test]
fn decrypt_private_key_rejects_empty_and_odd_hex_payloads() {
    let key = [18u8; 32];

    let empty_payload =
        encrypt_legacy_private_key_payload(&format!("{LP_PKEY_PREFIX}{LP_PKEY_SUFFIX}"), &key);
    let err = decrypt_private_key(&empty_payload, &key).expect_err("empty payload must fail");
    assert!(matches!(err, LpassError::Crypto("invalid private key")));

    let odd_payload =
        encrypt_legacy_private_key_payload(&format!("{LP_PKEY_PREFIX}a{LP_PKEY_SUFFIX}"), &key);
    let err = decrypt_private_key(&odd_payload, &key).expect_err("odd payload must fail");
    assert!(matches!(err, LpassError::Crypto("invalid private key")));
}

#[test]
fn decrypt_private_key_rejects_suffix_before_prefix() {
    let key = [20u8; 32];
    let payload = format!("{LP_PKEY_SUFFIX}{LP_PKEY_PREFIX}aa");
    let encrypted = encrypt_legacy_private_key_payload(&payload, &key);
    let err = decrypt_private_key(&encrypted, &key).expect_err("payload must fail");
    assert!(matches!(err, LpassError::Crypto("invalid private key")));
}

#[test]
fn encrypt_private_key_roundtrip() {
    let key = [15u8; 32];
    let private_key = vec![0x30, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef];
    let encrypted = encrypt_private_key(&private_key, &key).expect("encrypt");
    let decrypted = decrypt_private_key(&encrypted, &key).expect("decrypt");
    assert_eq!(decrypted, private_key);
}

#[test]
fn encrypt_private_key_returns_empty_for_empty_input() {
    let key = [16u8; 32];
    assert_eq!(encrypt_private_key(&[], &key).expect("encrypt"), "");
}

#[test]
fn rsa_decrypt_oaep_rejects_invalid_private_key() {
    let err = rsa_decrypt_oaep(b"not-a-key", b"ciphertext").expect_err("must fail");
    assert!(matches!(err, LpassError::Crypto("invalid rsa private key")));
}

#[test]
fn rsa_encrypt_oaep_rejects_invalid_public_key() {
    let err = rsa_encrypt_oaep(b"not-a-key", b"ciphertext").expect_err("must fail");
    assert!(matches!(err, LpassError::Crypto("invalid rsa public key")));
}

#[test]
fn rsa_encrypt_oaep_rejects_oversized_plaintext() {
    let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("private key");
    let public_key = private_key.to_public_key();
    let public_der = public_key.to_public_key_der().expect("public der");
    let plaintext = vec![0u8; 256];
    let err = rsa_encrypt_oaep(public_der.as_ref(), &plaintext).expect_err("must fail");
    assert!(matches!(err, LpassError::Crypto("RSA encrypt failed")));
}

#[test]
fn rsa_encrypt_oaep_roundtrip() {
    let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("private key");
    let public_key = private_key.to_public_key();
    let public_der = public_key.to_public_key_der().expect("public der");
    let plaintext = b"shared-folder-key";

    let ciphertext = rsa_encrypt_oaep(public_der.as_ref(), plaintext).expect("encrypt");
    let private_der = private_key.to_pkcs1_der().expect("private der");
    let decrypted = rsa_decrypt_oaep(private_der.as_bytes(), &ciphertext).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn sha256_hex_matches_reference() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
