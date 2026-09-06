//! Integration tests for Curve25519 / X25519.

use mcu_crypto_asm::curve25519::x25519;

#[test]
fn test_rfc7748_x25519() {
    let a: [u8; 32] = hex_literal_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b: [u8; 32] = hex_literal_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    let a_pub = x25519::public_key(&a);
    let expected_a_pub: [u8; 32] = hex_literal_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assert_eq!(a_pub, expected_a_pub, "Alice public key mismatch");

    let b_pub = x25519::public_key(&b);
    let expected_b_pub: [u8; 32] = hex_literal_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    assert_eq!(b_pub, expected_b_pub, "Bob public key mismatch");

    let shared_a = x25519::scalarmult(&a, &b_pub);
    let shared_b = x25519::scalarmult(&b, &a_pub);
    let expected_shared: [u8; 32] = hex_literal_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(shared_a, expected_shared, "Shared secret A mismatch");
    assert_eq!(shared_b, expected_shared, "Shared secret B mismatch");
}

#[test]
fn test_wycheproof_tc1() {
    let pubk: [u8; 32] = hex_literal_32("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829");
    let privk: [u8; 32] = hex_literal_32("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475");
    let shared = x25519::scalarmult(&privk, &pubk);
    let expected: [u8; 32] = hex_literal_32("436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320");
    assert_eq!(shared, expected, "Wycheproof TC1 mismatch");
}

fn hex_literal_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
