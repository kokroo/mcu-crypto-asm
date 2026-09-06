//! Tests for Poly1305 (RFC 8439).

use mcu_crypto_asm::poly1305::poly1305_auth;

#[test]
fn test_rfc8439_poly1305() {
    let key: [u8; 32] = hex_literal_32("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let msg = b"Cryptographic Forum Research Group";
    let tag = poly1305_auth(&key, msg);
    let expected: [u8; 16] = hex_literal_16("a8061dc1305136c6c22b8baf0c0127a9");
    assert_eq!(tag, expected, "RFC 8439 Poly1305 test vector failed");
}

fn hex_literal_16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_literal_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
