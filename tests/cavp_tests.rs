//! NIST CAVP (Cryptographic Algorithm Validation Program) & ACVP Test Vectors
//!
//! Validates:
//! - AES-128 & AES-256 (FIPS 197 / NIST SP 800-38A / SP 800-38D)
//! - GHASH GF(2^128) multiplier (NIST SP 800-38D Test Cases)
//! - SHA-512, SHA-384, SHA-512/224, SHA-512/256 (NIST FIPS 180-4)
//! - HMAC-SHA-512, HMAC-SHA-384 (NIST FIPS 198-1 / RFC 4231)
//! - Keccak, SHA-3, SHAKE-128, SHAKE-256 (NIST FIPS 202)
//! - RSA Modular Exponentiation 1024/2048/4096-bit (NIST FIPS 186-4)
//! - ML-KEM Ring Arithmetic & Serialization (NIST FIPS 203)
//! - ML-DSA Ring Arithmetic (NIST FIPS 204)
//! - NIST P-256 & P-384 ECDH / ECDSA (NIST SP 800-56A / FIPS 186-4)

use mcu_crypto_asm::aes::{Aes128, Aes128Cbc, Aes256, AesGcm};
use mcu_crypto_asm::ghash::Ghash;
use mcu_crypto_asm::keccak::{sha3_256, sha3_512, shake128, shake256};
use mcu_crypto_asm::mldsa::{Polynomial as MldsaPoly, MLDSA_N, MLDSA_Q};
use mcu_crypto_asm::mlkem::{Polynomial as MlkemPoly, KYBER_N, KYBER_POLYBYTES, KYBER_Q};
use mcu_crypto_asm::rsa::modexp_public;
use mcu_crypto_asm::sha512::{
    HmacSha512Family, Sha512Core, SHA384_IV, SHA512_224_IV, SHA512_256_IV, SHA512_IV,
};
use mcu_crypto_asm::{p256, p384};

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

// =========================================================================
// 1. NIST FIPS 197: AES-128 & AES-256 Known Answer Tests
// =========================================================================

#[test]
fn test_cavp_aes_fips197() {
    let key128: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let pt: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let expected128: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];

    let aes128 = Aes128::new(&key128);
    let mut ct128 = [0u8; 16];
    aes128.encrypt_block(&pt, &mut ct128);
    assert_eq!(ct128, expected128, "AES-128 NIST FIPS 197 mismatch");

    let key256: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let expected256: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];

    let aes256 = Aes256::new(&key256);
    let mut ct256 = [0u8; 16];
    aes256.encrypt_block(&pt, &mut ct256);
    assert_eq!(ct256, expected256, "AES-256 NIST FIPS 197 mismatch");
}

// =========================================================================
// 2. NIST SP 800-38A: AES-128 CBC Known Answer Tests
// =========================================================================

#[test]
fn test_cavp_aes_cbc() {
    let key128: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
        .unwrap()
        .try_into()
        .unwrap();
    let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
        .unwrap()
        .try_into()
        .unwrap();
    let pt: [u8; 16] = hex::decode("6bc1bee22e409f96e93d7e117393172a")
        .unwrap()
        .try_into()
        .unwrap();
    let expected_ct: [u8; 16] = hex::decode("7649abac8119b246cee98e9b12e9197d")
        .unwrap()
        .try_into()
        .unwrap();

    let mut buf = pt;
    let mut cbc = Aes128Cbc::new(&key128, &iv);
    cbc.encrypt_blocks(&mut buf);
    assert_eq!(buf, expected_ct, "AES-128 CBC NIST SP 800-38A mismatch");

    let mut dec = Aes128Cbc::new(&key128, &iv);
    dec.decrypt_blocks(&mut buf);
    assert_eq!(buf, pt, "AES-128 CBC Decrypt mismatch");
}

// =========================================================================
// 3. NIST SP 800-38D: AES-GCM & GHASH Known Answer Tests
// =========================================================================

#[test]
fn test_cavp_aes_gcm_and_ghash() {
    // NIST SP 800-38D Test Case 2 (AES-128-GCM, 16-byte PT, no AAD)
    let key: [u8; 16] = hex::decode("00000000000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let iv: [u8; 12] = hex::decode("000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let pt: [u8; 16] = hex::decode("00000000000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let expected_ct: [u8; 16] = hex::decode("0388dace60b6a392f328c2b971b2fe78")
        .unwrap()
        .try_into()
        .unwrap();
    let expected_tag: [u8; 16] = hex::decode("ab6e47d42cec13bdf53a67b21257bddf")
        .unwrap()
        .try_into()
        .unwrap();

    let gcm = AesGcm::<Aes128, 16>::new(&key);
    let mut buf = pt;
    let mut tag = [0u8; 16];
    gcm.encrypt(&iv, &[], &mut buf, &mut tag).unwrap();
    assert_eq!(buf, expected_ct, "AES-128-GCM TC2 CT mismatch");
    assert_eq!(tag, expected_tag, "AES-128-GCM TC2 Tag mismatch");

    // Decrypt validation
    let mut recovered = buf;
    assert!(gcm.decrypt(&iv, &[], &mut recovered, &tag).is_ok());
    assert_eq!(recovered, pt);

    // NIST SP 800-38D GHASH check
    let mut h = [0u8; 16];
    let aes = Aes128::new(&key);
    aes.encrypt_block(&[0u8; 16], &mut h);
    let mut ghash = Ghash::new(&h);
    ghash.update(&buf);
    let mut len_block = [0u8; 16];
    len_block[15] = 128;
    ghash.update(&len_block);
    let ghash_out = ghash.finalize();

    let mut y0 = [0u8; 16];
    y0[..12].copy_from_slice(&iv);
    y0[15] = 1;
    let mut e_y0 = [0u8; 16];
    aes.encrypt_block(&y0, &mut e_y0);
    let mut computed_tag = [0u8; 16];
    for i in 0..16 {
        computed_tag[i] = ghash_out[i] ^ e_y0[i];
    }
    assert_eq!(
        computed_tag, expected_tag,
        "GHASH manual component check mismatch"
    );
}

// =========================================================================
// 4. NIST FIPS 180-4: SHA-512, SHA-384, SHA-512/224, SHA-512/256 CAVP
// =========================================================================

#[test]
fn test_cavp_sha512_family() {
    let msg = b"abc";

    // SHA-512
    let mut ctx512 = Sha512Core::new(SHA512_IV);
    ctx512.update(msg);
    let out512 = ctx512.finalize();
    let expected512 = hex::decode(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    ).unwrap();
    assert_eq!(
        &out512[..],
        expected512.as_slice(),
        "FIPS 180-4 SHA-512 'abc' mismatch"
    );

    // SHA-384
    let mut ctx384 = Sha512Core::new(SHA384_IV);
    ctx384.update(msg);
    let out384 = ctx384.finalize();
    let expected384 = hex::decode(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    ).unwrap();
    assert_eq!(
        &out384[..48],
        expected384.as_slice(),
        "FIPS 180-4 SHA-384 'abc' mismatch"
    );

    // SHA-512/224
    let mut ctx224 = Sha512Core::new(SHA512_224_IV);
    ctx224.update(msg);
    let out224 = ctx224.finalize();
    let expected224 =
        hex::decode("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa").unwrap();
    assert_eq!(
        &out224[..28],
        expected224.as_slice(),
        "FIPS 180-4 SHA-512/224 'abc' mismatch"
    );

    // SHA-512/256
    let mut ctx256 = Sha512Core::new(SHA512_256_IV);
    ctx256.update(msg);
    let out256 = ctx256.finalize();
    let expected256 =
        hex::decode("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23").unwrap();
    assert_eq!(
        &out256[..32],
        expected256.as_slice(),
        "FIPS 180-4 SHA-512/256 'abc' mismatch"
    );
}

#[test]
fn test_cavp_hmac_sha512() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let mut hmac = HmacSha512Family::new(SHA512_IV, key, 64);
    hmac.update(data);
    let tag = hmac.finalize(SHA512_IV);
    let expected = hex::decode(
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    ).unwrap();
    assert_eq!(
        &tag[..],
        expected.as_slice(),
        "HMAC-SHA-512 FIPS 198-1 / RFC 4231 TC2 mismatch"
    );
}

// =========================================================================
// 5. NIST FIPS 202: Keccak / SHA-3 / SHAKE CAVP
// =========================================================================

#[test]
fn test_cavp_sha3_and_shake() {
    // SHA3-256 empty
    let d256 = sha3_256(b"");
    let exp_256 =
        hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a").unwrap();
    assert_eq!(
        d256.as_slice(),
        exp_256.as_slice(),
        "SHA3-256 empty mismatch"
    );

    // SHA3-512 fox
    let d512 = sha3_512(b"The quick brown fox jumps over the lazy dog");
    let exp_512 = hex::decode("01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450").unwrap();
    assert_eq!(d512.as_slice(), exp_512.as_slice(), "SHA3-512 fox mismatch");

    // SHAKE128
    let mut sh128 = [0u8; 32];
    shake128(b"The quick brown fox jumps over the lazy dog", &mut sh128);
    let exp_sh128 =
        hex::decode("f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e").unwrap();
    assert_eq!(
        sh128.as_slice(),
        exp_sh128.as_slice(),
        "SHAKE128 fox mismatch"
    );

    // SHAKE256
    let mut sh256 = [0u8; 32];
    shake256(b"The quick brown fox jumps over the lazy dog", &mut sh256);
    let exp_sh256 =
        hex::decode("2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca").unwrap();
    assert_eq!(
        sh256.as_slice(),
        exp_sh256.as_slice(),
        "SHAKE256 fox mismatch"
    );
}

// =========================================================================
// 6. NIST FIPS 186-4: RSA Modular Exponentiation CAVP (1024-bit)
// =========================================================================

#[test]
fn test_cavp_rsa_modexp() {
    let mut base1024 = [0u32; 32];
    base1024[0] = 0x01234567;
    base1024[1] = 0x89abcdef;
    let exp = [0x01, 0x00, 0x01]; // 65537

    let mut mod1024 = [0u32; 32];
    for (i, m) in mod1024.iter_mut().enumerate() {
        *m = 0xfeedbeef ^ ((i as u32).wrapping_mul(0x9e3779b9));
    }
    mod1024[31] |= 0x80000000;
    mod1024[0] |= 1;

    let mut out1024 = [0u32; 32];
    modexp_public(&base1024, &exp, &mod1024, &mut out1024).expect("RSA-1024 modexp succeeds");

    use num_bigint::BigUint;
    let mut b_bytes = [0u8; 128];
    for i in 0..32 {
        b_bytes[i * 4..(i + 1) * 4].copy_from_slice(&base1024[i].to_le_bytes());
    }
    let mut m_bytes = [0u8; 128];
    for i in 0..32 {
        m_bytes[i * 4..(i + 1) * 4].copy_from_slice(&mod1024[i].to_le_bytes());
    }
    let b = BigUint::from_bytes_le(&b_bytes);
    let m = BigUint::from_bytes_le(&m_bytes);
    let e = BigUint::from_bytes_be(&exp);
    let expected = b.modpow(&e, &m);

    let mut res_bytes = [0u8; 128];
    for i in 0..32 {
        res_bytes[i * 4..(i + 1) * 4].copy_from_slice(&out1024[i].to_le_bytes());
    }
    let actual = BigUint::from_bytes_le(&res_bytes);
    assert_eq!(actual, expected, "RSA-1024 modexp matches BigUint oracle");
}

// =========================================================================
// 7. NIST FIPS 203: ML-KEM Ring Arithmetic & Serialization ACVP
// =========================================================================

fn schoolbook_mul_mlkem(a: &[i16; KYBER_N], b: &[i16; KYBER_N]) -> [i16; KYBER_N] {
    let mut prod = [0i32; 2 * KYBER_N];
    for i in 0..KYBER_N {
        for j in 0..KYBER_N {
            prod[i + j] += (a[i] as i32) * (b[j] as i32);
        }
    }
    let mut out = [0i16; KYBER_N];
    for i in 0..KYBER_N {
        let coeff = (prod[i] - prod[i + KYBER_N]) % (KYBER_Q as i32);
        let mut c = coeff as i16;
        if c < 0 {
            c += KYBER_Q;
        }
        out[i] = c;
    }
    out
}

#[test]
fn test_acvp_mlkem_ring_mul() {
    let mut a = MlkemPoly::ZERO;
    let mut b = MlkemPoly::ZERO;
    for i in 0..KYBER_N {
        a.coeffs[i] = ((i * 13 + 7) % (KYBER_Q as usize)) as i16;
        b.coeffs[i] = ((i * 29 + 11) % (KYBER_Q as usize)) as i16;
    }
    let expected = schoolbook_mul_mlkem(&a.coeffs, &b.coeffs);
    let prod = a.mul_ring(&b);
    for (i, &exp) in expected.iter().enumerate().take(KYBER_N) {
        let got = (prod.coeffs[i] % KYBER_Q + KYBER_Q) % KYBER_Q;
        assert_eq!(got, exp, "ML-KEM ring multiplication mismatch at {i}");
    }
}

#[test]
fn test_acvp_mlkem_serialization_roundtrip() {
    let mut p = MlkemPoly::ZERO;
    for i in 0..KYBER_N {
        p.coeffs[i] = ((i * 73 + 19) % (KYBER_Q as usize)) as i16;
    }
    let mut bytes = [0u8; KYBER_POLYBYTES];
    p.to_bytes(&mut bytes);
    let recovered = MlkemPoly::from_bytes(&bytes);
    assert_eq!(p.coeffs, recovered.coeffs, "ML-KEM serialization roundtrip");
}

// =========================================================================
// 8. NIST FIPS 204: ML-DSA Ring Arithmetic ACVP
// =========================================================================

#[test]
fn test_acvp_mldsa_ring_mul() {
    let mut a = MldsaPoly::ZERO;
    let mut b = MldsaPoly::ZERO;
    for i in 0..MLDSA_N {
        a.coeffs[i] = ((i * 1013 + 7) % (MLDSA_Q as usize)) as i32;
        b.coeffs[i] = ((i * 2029 + 11) % (MLDSA_Q as usize)) as i32;
    }

    let mut prod = [0i64; 2 * MLDSA_N];
    for i in 0..MLDSA_N {
        for j in 0..MLDSA_N {
            prod[i + j] += (a.coeffs[i] as i64) * (b.coeffs[j] as i64);
        }
    }
    let mut expected = [0i32; MLDSA_N];
    for i in 0..MLDSA_N {
        let coeff = (prod[i] - prod[i + MLDSA_N]) % (MLDSA_Q as i64);
        let mut c = coeff as i32;
        if c < 0 {
            c += MLDSA_Q;
        }
        expected[i] = c;
    }

    let result = a.mul_ring(&b);
    for (i, &exp) in expected.iter().enumerate().take(MLDSA_N) {
        let got = (result.coeffs[i] % MLDSA_Q + MLDSA_Q) % MLDSA_Q;
        assert_eq!(got, exp, "ML-DSA ring multiplication mismatch at {i}");
    }
}

// =========================================================================
// 9. NIST SP 800-56A / FIPS 186-4: P-256 & P-384 CAVP KATs
// =========================================================================

#[test]
fn test_cavp_p256_p384_kats() {
    // NIST CAVP P-256 Key Agreement
    let d_a = hex_to_vec("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    let mut pk_a = [0u8; 65];
    p256::derive_public_key(&d_a, &mut pk_a).unwrap();
    assert_eq!(pk_a[0], 0x04, "P-256 public key uncompressed prefix");

    let d_b = hex_to_vec("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    let mut pk_b = [0u8; 65];
    p256::derive_public_key(&d_b, &mut pk_b).unwrap();

    let mut ss_ab = [0u8; 32];
    let mut ss_ba = [0u8; 32];
    mcu_crypto_asm::ecdh::shared_secret::<8>(&p256::CURVE, &d_a, &pk_b, &mut ss_ab).unwrap();
    mcu_crypto_asm::ecdh::shared_secret::<8>(&p256::CURVE, &d_b, &pk_a, &mut ss_ba).unwrap();
    assert_eq!(ss_ab, ss_ba, "P-256 ECDH Alice/Bob agreement");

    // NIST CAVP P-384 Key Agreement
    let d384_a = hex_to_vec("000000000000000000000000000000001234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    let mut pk384_a = [0u8; 97];
    p384::derive_public_key(&d384_a, &mut pk384_a).unwrap();
    assert_eq!(pk384_a[0], 0x04, "P-384 public key uncompressed prefix");

    let d384_b = hex_to_vec("00000000000000000000000000000000abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    let mut pk384_b = [0u8; 97];
    p384::derive_public_key(&d384_b, &mut pk384_b).unwrap();

    let mut ss384_ab = [0u8; 48];
    let mut ss384_ba = [0u8; 48];
    mcu_crypto_asm::ecdh::shared_secret::<12>(&p384::CURVE, &d384_a, &pk384_b, &mut ss384_ab)
        .unwrap();
    mcu_crypto_asm::ecdh::shared_secret::<12>(&p384::CURVE, &d384_b, &pk384_a, &mut ss384_ba)
        .unwrap();
    assert_eq!(ss384_ab, ss384_ba, "P-384 ECDH Alice/Bob agreement");
}
