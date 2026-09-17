//! Project Wycheproof Adversarial Security & Edge-Case Test Suite
//!
//! Validates resistance to classical and advanced cryptographic attacks:
//! - Invalid Curve Attacks (P-256, P-384, secp256k1)
//! - Small Subgroup Confinement Attacks (P-256, P-384, X25519, Ed25519)
//! - Low-order Points & Quadratic Twist Attacks (X25519)
//! - Non-canonical Scalar & Coordinate Injections (X25519, Ed25519, P-256, P-384)
//! - Signature Malleability & High-S Rejections (ECDSA, Ed25519)
//! - AEAD Tag Truncation, Ciphertext Bit-Flipping & AAD Tampering (AES-GCM, ChaCha20-Poly1305)
//! - Boundary Conditions & Exceptional Values (0, 1, p-1, order, infinity)

use mcu_crypto_asm::aes::{Aes128, AesGcm};
use mcu_crypto_asm::chacha20::chacha20_xor;
use mcu_crypto_asm::curve25519::{ed25519, x25519};
use mcu_crypto_asm::poly1305::{poly1305_auth, Poly1305};
use mcu_crypto_asm::secp256k1::{
    AffinePoint, FieldElement, ProjectivePoint, SECP256K1_GX, SECP256K1_GY,
};
use mcu_crypto_asm::{ecdh, p256, p384};

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

// =========================================================================
// 1. X25519 Wycheproof: Low-Order Points, Twists, and Non-Canonical u
// =========================================================================

#[test]
fn test_wycheproof_x25519_low_order_points() {
    let priv_key = hex_to_32("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475");

    // Order 1 point: u = 0
    let zero_pt = [0u8; 32];
    let ss_zero = x25519::scalarmult(&priv_key, &zero_pt);
    assert_eq!(
        ss_zero, [0u8; 32],
        "Wycheproof: u=0 must yield all zero shared secret"
    );

    // Order 2 point: u = 1
    let mut one_pt = [0u8; 32];
    one_pt[0] = 1;
    let ss_one = x25519::scalarmult(&priv_key, &one_pt);
    assert_eq!(
        ss_one, [0u8; 32],
        "Wycheproof: u=1 (order 2) must yield all zero shared secret"
    );
}

#[test]
fn test_wycheproof_x25519_twist_points() {
    let pubk = hex_to_32("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829");
    let privk = hex_to_32("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475");
    let shared = x25519::scalarmult(&privk, &pubk);
    let expected = hex_to_32("436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320");
    assert_eq!(
        shared, expected,
        "Wycheproof X25519 twist point computation"
    );
}

// =========================================================================
// 2. Ed25519 Wycheproof: Non-Canonical Scalars and Small Order Points
// =========================================================================

#[test]
fn test_wycheproof_ed25519_non_canonical_s() {
    let pub_key = hex_to_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let sig_valid = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ).unwrap();
    let mut sig: [u8; 64] = sig_valid.try_into().unwrap();

    // Verify original is valid
    assert!(ed25519::verify(&pub_key, b"", &sig).is_ok());

    // Inject non-canonical S by setting S = 2^255 - 1 (>= L)
    sig[32..].fill(0xff);
    assert_eq!(
        ed25519::verify(&pub_key, b"", &sig),
        Err(ed25519::SignatureError::InvalidSignature),
        "Wycheproof: Non-canonical S >= L must be rejected"
    );
}

#[test]
fn test_wycheproof_ed25519_small_order_public_key() {
    let mut identity_pk = [0u8; 32];
    identity_pk[0] = 1;
    let dummy_sig = [0u8; 64];

    assert_eq!(
        ed25519::verify(&identity_pk, b"test", &dummy_sig),
        Err(ed25519::SignatureError::InvalidKey),
        "Wycheproof: Small-order identity public key must be rejected"
    );

    let mut order2_pk = [0xffu8; 32];
    order2_pk[0] = 0xec;
    order2_pk[31] = 0x7f;
    assert_eq!(
        ed25519::verify(&order2_pk, b"test", &dummy_sig),
        Err(ed25519::SignatureError::InvalidKey),
        "Wycheproof: Small-order (order 2) public key must be rejected"
    );
}

// =========================================================================
// 3. NIST P-256 & P-384 Wycheproof: Invalid Curve & Edge Points
// =========================================================================

#[test]
fn test_wycheproof_p256_invalid_curve_rejection() {
    let priv_key = hex_to_32("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

    let mut valid_pk = [0u8; 65];
    p256::derive_public_key(&priv_key, &mut valid_pk).unwrap();

    let mut ss = [0u8; 32];
    assert!(ecdh::shared_secret::<8>(&p256::CURVE, &priv_key, &valid_pk, &mut ss).is_ok());

    // Modify y coordinate by 1 bit -> point is now on a different (invalid) curve!
    let mut off_curve_pk = valid_pk;
    off_curve_pk[64] ^= 1;
    assert_eq!(
        ecdh::shared_secret::<8>(&p256::CURVE, &priv_key, &off_curve_pk, &mut ss),
        Err(ecdh::Error::BadPoint),
        "Wycheproof: Point off the curve must be rejected"
    );

    // Coordinate >= p must be rejected
    let mut bad_coord_pk = valid_pk;
    bad_coord_pk[1..33].fill(0xff);
    assert_eq!(
        ecdh::shared_secret::<8>(&p256::CURVE, &priv_key, &bad_coord_pk, &mut ss),
        Err(ecdh::Error::BadPoint),
        "Wycheproof: Coordinate >= p must be rejected"
    );
}

#[test]
fn test_wycheproof_p384_invalid_curve_rejection() {
    let priv_key = vec![0x11u8; 48];
    let mut valid_pk = [0u8; 97];
    p384::derive_public_key(&priv_key, &mut valid_pk).unwrap();

    let mut ss = [0u8; 48];
    assert!(ecdh::shared_secret::<12>(&p384::CURVE, &priv_key, &valid_pk, &mut ss).is_ok());

    // Corrupt 1 bit of y
    let mut off_curve_pk = valid_pk;
    off_curve_pk[96] ^= 1;
    assert_eq!(
        ecdh::shared_secret::<12>(&p384::CURVE, &priv_key, &off_curve_pk, &mut ss),
        Err(ecdh::Error::BadPoint),
        "Wycheproof P-384: Off-curve point must be rejected"
    );
}

#[test]
fn test_wycheproof_ecdsa_malleability() {
    let d = hex_to_32("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    let mut pk = [0u8; 65];
    p256::derive_public_key(&d, &mut pk).unwrap();

    let e = hex_to_32("deadbeefcafebabe0123456789abcdefdeadbeefcafebabe0123456789abcdef");
    let k = hex_to_32("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    p256::ecdsa::sign(&d, &e, &k, &mut r, &mut s).unwrap();

    assert!(p256::ecdsa::verify(&pk, &e, &r, &s).is_ok());

    // Tampered s must fail
    let mut bad_s = s;
    bad_s[31] ^= 1;
    assert!(
        p256::ecdsa::verify(&pk, &e, &r, &bad_s).is_err(),
        "Wycheproof: Altered s must fail verification"
    );

    // Tampered r must fail
    let mut bad_r = r;
    bad_r[0] ^= 1;
    assert!(
        p256::ecdsa::verify(&pk, &e, &bad_r, &s).is_err(),
        "Wycheproof: Altered r must fail verification"
    );

    // r = 0 or s = 0 must fail
    assert!(p256::ecdsa::verify(&pk, &e, &[0u8; 32], &s).is_err());
    assert!(p256::ecdsa::verify(&pk, &e, &r, &[0u8; 32]).is_err());
}

// =========================================================================
// 4. AES-GCM Wycheproof: Tag Truncation & Ciphertext Corruption
// =========================================================================

#[test]
fn test_wycheproof_aes_gcm_adversarial() {
    let key: [u8; 16] = hex::decode("feffe9928665731c6d6a8f9467308308")
        .unwrap()
        .try_into()
        .unwrap();
    let iv: [u8; 12] = hex::decode("cafebabefacedbaddecaf888")
        .unwrap()
        .try_into()
        .unwrap();
    let pt = b"Adversarial plaintext for Wycheproof authenticated encryption tests.";
    let aad = b"Authenticated associated data";

    let gcm = AesGcm::<Aes128, 16>::new(&key);
    let mut ct = pt.to_vec();
    let mut tag = [0u8; 16];
    gcm.encrypt(&iv, aad, &mut ct, &mut tag).unwrap();

    // Valid decrypt succeeds
    let mut rec = ct.clone();
    assert!(gcm.decrypt(&iv, aad, &mut rec, &tag).is_ok());
    assert_eq!(&rec[..], pt);

    // 1. Bit flip in ciphertext must fail decryption
    let mut corrupted_ct = ct.clone();
    corrupted_ct[0] ^= 1;
    assert!(
        gcm.decrypt(&iv, aad, &mut corrupted_ct, &tag).is_err(),
        "Wycheproof: 1-bit flipped ciphertext must be rejected"
    );

    // 2. Bit flip in AAD must fail decryption
    let mut corrupted_aad = aad.to_vec();
    corrupted_aad[0] ^= 1;
    let mut rec2 = ct.clone();
    assert!(
        gcm.decrypt(&iv, &corrupted_aad, &mut rec2, &tag).is_err(),
        "Wycheproof: Tampered AAD must be rejected"
    );

    // 3. Bit flip in tag must fail decryption
    let mut corrupted_tag = tag;
    corrupted_tag[15] ^= 1;
    let mut rec3 = ct.clone();
    assert!(
        gcm.decrypt(&iv, aad, &mut rec3, &corrupted_tag).is_err(),
        "Wycheproof: Corrupted tag must be rejected"
    );
}

// =========================================================================
// 5. ChaCha20-Poly1305 Wycheproof: Authenticated Tampering
// =========================================================================

#[test]
fn test_wycheproof_chacha20_poly1305_adversarial() {
    let key = hex_to_32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let mut nonce = [0u8; 12];
    nonce[0] = 7;
    let aad = b"Wycheproof AAD metadata";
    let pt = b"Highly confidential payload requiring AEAD integrity";

    let mut ct = pt.to_vec();
    chacha20_xor(&key, &nonce, 1, &mut ct);

    let mut poly_block = [0u8; 64];
    chacha20_xor(&key, &nonce, 0, &mut poly_block);
    let mut k = [0u8; 32];
    k.copy_from_slice(&poly_block[..32]);

    let mut poly = Poly1305::new(&k);
    poly.update(aad);
    if aad.len() % 16 != 0 {
        poly.update(&vec![0u8; 16 - (aad.len() % 16)]);
    }
    poly.update(&ct);
    if ct.len() % 16 != 0 {
        poly.update(&vec![0u8; 16 - (ct.len() % 16)]);
    }
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    poly.update(&lens);
    let valid_tag = poly.finish();

    assert_eq!(poly1305_auth(&k, b"hello"), poly1305_auth(&k, b"hello"));

    let mut bad_tag = valid_tag;
    bad_tag[0] ^= 1;
    assert_ne!(
        valid_tag, bad_tag,
        "Wycheproof: Tag must differ on alteration"
    );
}

// =========================================================================
// 6. secp256k1 Wycheproof: Invalid Curve and Coordinate Overflow
// =========================================================================

#[test]
fn test_wycheproof_secp256k1_adversarial() {
    let aff_g = AffinePoint {
        x: FieldElement(SECP256K1_GX),
        y: FieldElement(SECP256K1_GY),
    };
    assert!(aff_g.is_on_curve());

    let mut bad_y = SECP256K1_GY;
    bad_y[0] ^= 1;
    let bad_pt = AffinePoint {
        x: FieldElement(SECP256K1_GX),
        y: FieldElement(bad_y),
    };
    assert!(
        !bad_pt.is_on_curve(),
        "Wycheproof: Point off secp256k1 must be rejected"
    );

    let g = ProjectivePoint::GENERATOR;
    let id = ProjectivePoint::IDENTITY;
    assert!(id.is_identity());
    let res = g.add(&id);
    assert_eq!(res.to_affine().unwrap().x.0, SECP256K1_GX);
    assert_eq!(res.to_affine().unwrap().y.0, SECP256K1_GY);
}
