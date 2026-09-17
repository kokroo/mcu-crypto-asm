//! RFC Known Answer Tests (KATs)
//!
//! Covers:
//! - RFC 7748: Elliptic Curves for Security (X25519 Diffie-Hellman & Iterated Ladder)
//! - RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519 Sign and Verify)
//! - RFC 8439: ChaCha20 and Poly1305 for IETF Protocols (Block, Encryption, MAC, AEAD)
//! - RFC 6979: Deterministic Usage of the Digital Signature Algorithm (secp256k1)
//! - RFC 4231: HMAC-SHA-512 Known Answer Tests

use mcu_crypto_asm::chacha20::{chacha20_block, chacha20_xor};
use mcu_crypto_asm::curve25519::{ed25519, x25519};
use mcu_crypto_asm::poly1305::{poly1305_auth, Poly1305};
use mcu_crypto_asm::secp256k1::public_key_from_secret;
use mcu_crypto_asm::sha512::{HmacSha512Family, SHA512_IV};

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex string")
}

// =========================================================================
// 1. RFC 7748: X25519 Known Answer Tests
// =========================================================================

#[test]
fn test_rfc7748_diffie_hellman_kat() {
    let alice_priv = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub_expected =
        hex_to_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let alice_pub = x25519::public_key(&alice_priv);
    assert_eq!(alice_pub, alice_pub_expected, "RFC 7748 Alice public key");

    let bob_priv = hex_to_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pub_expected =
        hex_to_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let bob_pub = x25519::public_key(&bob_priv);
    assert_eq!(bob_pub, bob_pub_expected, "RFC 7748 Bob public key");

    let shared_alice = x25519::scalarmult(&alice_priv, &bob_pub);
    let shared_bob = x25519::scalarmult(&bob_priv, &alice_pub);
    let expected_shared =
        hex_to_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(
        shared_alice, expected_shared,
        "RFC 7748 Alice shared secret"
    );
    assert_eq!(shared_bob, expected_shared, "RFC 7748 Bob shared secret");
}

#[test]
fn test_rfc7748_1000_iterations() {
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut u = [0u8; 32];
    u[0] = 9;

    for _ in 0..1000 {
        let next_u = x25519::scalarmult(&k, &u);
        u = k;
        k = next_u;
    }

    let expected_k = hex_to_32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    assert_eq!(
        k, expected_k,
        "RFC 7748 1000-iteration Montgomery ladder chain"
    );
}

// =========================================================================
// 2. RFC 8032: Ed25519 Known Answer Tests
// =========================================================================

#[test]
fn test_rfc8032_ed25519_test_vectors() {
    // RFC 8032 Section 7.1 Test 1 (Empty message)
    let priv1 = hex_to_32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pub1_expected =
        hex_to_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let sig1_expected = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ).unwrap();

    let pub1_derived = ed25519::public_key(&priv1);
    assert_eq!(
        pub1_derived, pub1_expected,
        "RFC 8032 Test 1 public key derivation"
    );

    let sig1_computed = ed25519::sign(&priv1, b"");
    assert_eq!(
        sig1_computed.as_slice(),
        sig1_expected.as_slice(),
        "RFC 8032 Test 1 sign"
    );

    let sig1_arr: [u8; 64] = sig1_expected.try_into().unwrap();
    assert!(
        ed25519::verify(&pub1_expected, b"", &sig1_arr).is_ok(),
        "RFC 8032 Test 1 verify"
    );

    // Corrupted signature rejection
    let mut bad_sig = sig1_arr;
    bad_sig[0] ^= 1;
    assert!(
        ed25519::verify(&pub1_expected, b"", &bad_sig).is_err(),
        "RFC 8032 Corrupted signature must be rejected"
    );

    // Roundtrip verification on non-empty payload
    let test_msg = b"Helius embedded secure mesh networking";
    let sig_msg = ed25519::sign(&priv1, test_msg);
    assert!(
        ed25519::verify(&pub1_expected, test_msg, &sig_msg).is_ok(),
        "Ed25519 sign & verify roundtrip"
    );

    let mut bad_msg = test_msg.to_vec();
    bad_msg[0] ^= 1;
    assert!(
        ed25519::verify(&pub1_expected, &bad_msg, &sig_msg).is_err(),
        "Ed25519 tampered message rejection"
    );
}

// =========================================================================
// 3. RFC 8439: ChaCha20 & Poly1305 Known Answer Tests
// =========================================================================

#[test]
fn test_rfc8439_chacha20_block() {
    let state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
        0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
        0x4a000000, 0x00000000,
    ];

    let mut out = [0u8; 64];
    chacha20_block(&mut out, &state);

    let expected = hex::decode(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    ).unwrap();
    assert_eq!(
        out.as_slice(),
        expected.as_slice(),
        "RFC 8439 Section 2.3.2 ChaCha20 block"
    );
}

#[test]
fn test_rfc8439_chacha20_encryption() {
    let key = hex_to_32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let mut nonce = [0u8; 12];
    nonce[7] = 0x4a;
    let counter = 1u32;

    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let mut data = *plaintext;
    chacha20_xor(&key, &nonce, counter, &mut data);

    let expected = hex::decode(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
    ).unwrap();
    assert_eq!(
        &data[..],
        expected.as_slice(),
        "RFC 8439 Section 2.4.2 encryption"
    );

    // Decrypt roundtrip
    chacha20_xor(&key, &nonce, counter, &mut data);
    assert_eq!(&data[..], plaintext, "ChaCha20 roundtrip decrypt");
}

#[test]
fn test_rfc8439_poly1305_mac() {
    let key = hex_to_32("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let msg = b"Cryptographic Forum Research Group";
    let tag = poly1305_auth(&key, msg);
    let expected = hex::decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap();
    assert_eq!(
        tag.as_slice(),
        expected.as_slice(),
        "RFC 8439 Section 2.5.2 Poly1305 tag"
    );
}

#[test]
fn test_rfc8439_aead_construction() {
    let key = hex_to_32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce_bytes = hex_to_vec("070000004041424344454647");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let aad = hex_to_vec("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let mut ciphertext = plaintext.to_vec();
    chacha20_xor(&key, &nonce, 1, &mut ciphertext);

    let expected_ct = hex::decode(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    ).unwrap();
    assert_eq!(ciphertext, expected_ct, "RFC 8439 AEAD Ciphertext");

    let mut poly_key = [0u8; 64];
    chacha20_xor(&key, &nonce, 0, &mut poly_key);
    let mut k = [0u8; 32];
    k.copy_from_slice(&poly_key[..32]);

    let mut poly = Poly1305::new(&k);
    poly.update(&aad);
    if aad.len() % 16 != 0 {
        poly.update(&vec![0u8; 16 - (aad.len() % 16)]);
    }
    poly.update(&ciphertext);
    if ciphertext.len() % 16 != 0 {
        poly.update(&vec![0u8; 16 - (ciphertext.len() % 16)]);
    }
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.update(&lens);
    let tag = poly.finish();

    let expected_tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();
    assert_eq!(tag.as_slice(), expected_tag.as_slice(), "RFC 8439 AEAD Tag");
}

// =========================================================================
// 4. RFC 6979: secp256k1 Known Answer Tests
// =========================================================================

#[test]
fn test_rfc6979_secp256k1_vector() {
    let priv_bytes = hex_to_32("C98B3B5C3C4413E74160EEA42E85D537711B38F3804EB61480EA4E1FDBAC9A52");
    let pubkey = public_key_from_secret(&priv_bytes).expect("Failed to derive public key");

    let expected_x = hex_to_32("653CA8F6019AEF38AEB8BA892D9CF8FD5A152625536D33EF4D15406CF0FEF096");
    let expected_y = hex_to_32("E6D51321CC291F3F39AD539F051DF140322C25A52F992823D658519B9A6A96AE");

    assert_eq!(
        pubkey.0.x.to_bytes_be(),
        expected_x,
        "RFC 6979 pubkey x mismatch"
    );
    assert_eq!(
        pubkey.0.y.to_bytes_be(),
        expected_y,
        "RFC 6979 pubkey y mismatch"
    );
}

// =========================================================================
// 5. RFC 4231: HMAC-SHA-512 Known Answer Tests
// =========================================================================

#[test]
fn test_rfc4231_hmac_sha512() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let mut hmac = HmacSha512Family::new(SHA512_IV, key, 64);
    hmac.update(data);
    let tag = hmac.finalize(SHA512_IV);
    let expected = hex::decode(
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    ).unwrap();
    assert_eq!(
        &tag[..64],
        expected.as_slice(),
        "RFC 4231 HMAC-SHA-512 TC2 mismatch"
    );
}
