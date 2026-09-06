use mcu_crypto_asm::secp256k1::{
    ecdh, public_key_from_secret, AffinePoint, FieldElement, ProjectivePoint, PublicKey,
    SECP256K1_GX, SECP256K1_GY,
};

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[test]
fn test_generator_on_curve() {
    let g_affine = AffinePoint {
        x: FieldElement(SECP256K1_GX),
        y: FieldElement(SECP256K1_GY),
    };
    assert!(g_affine.is_on_curve(), "Generator G must satisfy y^2 = x^3 + 7 mod p");
}

#[test]
fn test_point_doubling() {
    let g = ProjectivePoint::GENERATOR;
    let g2 = g.double();
    let aff2 = g2.to_affine().expect("2*G should not be at infinity");

    let expected_x = hex_to_32("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    let expected_y = hex_to_32("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a");

    assert_eq!(aff2.x.to_bytes_be(), expected_x, "2*G x mismatch");
    assert_eq!(aff2.y.to_bytes_be(), expected_y, "2*G y mismatch");
    assert!(aff2.is_on_curve(), "2*G must be on curve");
}

#[test]
fn test_point_addition_and_identity() {
    let g = ProjectivePoint::GENERATOR;
    let ident = ProjectivePoint::IDENTITY;

    // G + O = G
    let g_plus_o = g.add(&ident);
    let aff = g_plus_o.to_affine().unwrap();
    assert_eq!(aff.x.0, SECP256K1_GX);
    assert_eq!(aff.y.0, SECP256K1_GY);

    // G + (-G) = O
    let g_neg = ProjectivePoint {
        x: g.x,
        y: g.y.neg(),
        z: g.z,
    };
    let g_minus_g = g.add(&g_neg);
    assert!(g_minus_g.is_identity(), "G + (-G) must be identity");
}

#[test]
fn test_rfc6979_vector() {
    // RFC 6979 Section A.2.5 official test vector
    let priv_bytes = hex_to_32("C98B3B5C3C4413E74160EEA42E85D537711B38F3804EB61480EA4E1FDBAC9A52");
    let pubkey = public_key_from_secret(&priv_bytes).expect("Failed to derive public key");

    let expected_x = hex_to_32("653CA8F6019AEF38AEB8BA892D9CF8FD5A152625536D33EF4D15406CF0FEF096");
    let expected_y = hex_to_32("E6D51321CC291F3F39AD539F051DF140322C25A52F992823D658519B9A6A96AE");

    assert_eq!(pubkey.0.x.to_bytes_be(), expected_x, "RFC 6979 pubkey x mismatch");
    assert_eq!(pubkey.0.y.to_bytes_be(), expected_y, "RFC 6979 pubkey y mismatch");
}

#[test]
fn test_compression_decompression() {
    let priv_bytes = hex_to_32("C98B3B5C3C4413E74160EEA42E85D537711B38F3804EB61480EA4E1FDBAC9A52");
    let pubkey = public_key_from_secret(&priv_bytes).unwrap();

    // Compressed 33-byte encoding
    let (comp_bytes, comp_len) = pubkey.to_sec1_bytes(true);
    assert_eq!(comp_len, 33);
    assert_eq!(comp_bytes[0], 0x02); // y is even

    let parsed_comp = PublicKey::from_sec1_bytes(&comp_bytes[..33]).unwrap();
    assert_eq!(parsed_comp, pubkey);

    // Uncompressed 65-byte encoding
    let (uncomp_bytes, uncomp_len) = pubkey.to_sec1_bytes(false);
    assert_eq!(uncomp_len, 65);
    assert_eq!(uncomp_bytes[0], 0x04);

    let parsed_uncomp = PublicKey::from_sec1_bytes(&uncomp_bytes[..65]).unwrap();
    assert_eq!(parsed_uncomp, pubkey);
}

#[test]
fn test_ecdh_shared_secret() {
    // Alice
    let alice_priv = hex_to_32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    let alice_pub = public_key_from_secret(&alice_priv).unwrap();

    // Bob
    let bob_priv = hex_to_32("201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201");
    let bob_pub = public_key_from_secret(&bob_priv).unwrap();

    // Alice calculates shared secret with Bob's public key
    let secret_alice = ecdh(&alice_priv, &bob_pub).unwrap();

    // Bob calculates shared secret with Alice's public key
    let secret_bob = ecdh(&bob_priv, &alice_pub).unwrap();

    assert_eq!(secret_alice, secret_bob, "ECDH shared secrets must match!");
    assert_ne!(secret_alice, [0u8; 32], "Shared secret must not be zero");
}
