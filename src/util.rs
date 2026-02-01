#![forbid(unsafe_code)]

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
