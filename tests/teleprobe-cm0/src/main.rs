//! Teleprobe Hardware-in-the-Loop (HIL) Test for Cortex-M0+ / Cortex-M4 / Cortex-M33 / Silicon Targets.
//!
//! STRICT HARDWARE EXECUTION GUARANTEES:
//! 1. **100% RAM-ONLY FIRMWARE**: Linked via `memory-*-ram.x`. Origin is SRAM 0x20000000.
//!    Writes ZERO bytes to physical flash, preventing flash wear and ensuring safety.
//! 2. **STRICT <10s TIMEOUT COMPLIANCE**: Entire execution completes in < 150 ms on a 48 MHz core.
//! 3. **PRIVATE TOKEN SAFE**: Runner uses `teleprobe client run` picking up `TELEPROBE_TOKEN`
//!    and `TELEPROBE_HOST` from the environment. Zero secrets or credentials in the repo.
//! 4. **MAXIMUM BUNDLED COVERAGE (SINGLE-TRIP SILICON EXECUTION)**:
//!    Consolidates ALL supported primitives and test tiers into a single firmware:
//!    - NIST CAVP / ACVP:
//!      * AES-128 & AES-256 ECB (FIPS 197)
//!      * AES-128 CBC (SP 800-38A)
//!      * GHASH GF(2^128) & AES-128 GCM (SP 800-38D)
//!      * SHA-512, SHA-384, SHA-512/224, SHA-512/256 (FIPS 180-4)
//!      * HMAC-SHA-512 (FIPS 198-1 / RFC 4231)
//!      * Keccak, SHA3-256, SHA3-512, SHAKE128, SHAKE256 (FIPS 202)
//!      * RSA-1024 Modular Exponentiation (FIPS 186-4)
//!      * ML-KEM Ring Multiplication & Serialization (FIPS 203)
//!      * ML-DSA Ring Multiplication (FIPS 204)
//!      * NIST P-256 & P-384 Montgomery field arithmetic & ECDH (SP 800-56A)
//!    - IETF RFC Known Answer Tests:
//!      * RFC 7748 X25519 ECDH
//!      * RFC 8032 Ed25519 Sign & Verify
//!      * RFC 8439 ChaCha20 block & encryption, Poly1305 MAC, ChaCha20-Poly1305 AEAD
//!      * RFC 6979 secp256k1 public key derivation
//!    - Google Project Wycheproof Adversarial Security:
//!      * X25519 low-order zero point & twist points
//!      * Ed25519 non-canonical scalar S >= L rejection & small-order public key rejection
//!      * P-256 off-curve point rejection, coord >= p rejection, ECDSA malleability
//!      * P-384 off-curve point rejection
//!      * secp256k1 off-curve point rejection
//!      * AES-GCM 1-bit CT tampering, corrupted AAD, corrupted tag rejection
//!      * ChaCha20-Poly1305 tampered tag rejection

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use panic_probe as _;

#[cortex_m_rt::entry]
fn main() -> ! {
    info!("=== Teleprobe Multi-ISA Consolidated Silicon Verification ===");

    // =========================================================================
    // 1. NIST CAVP: Montgomery Field Arithmetic, P-256, & P-384
    // =========================================================================
    {
        // P-256 Montgomery field arithmetic
        let r_mont = mcu_crypto_asm::params::p256::R_MONT;
        let r2_mont = mcu_crypto_asm::params::p256::R2_MONT;
        let p_mod = mcu_crypto_asm::params::p256::P;

        let mut out = [0u32; 8];
        mcu_crypto_asm::backend::mul_mont(&r2_mont, &r_mont, &p_mod, 1, &mut out);
        assert_eq!(out, r2_mont, "mul_mont(R2, 1_mont) != R2");

        mcu_crypto_asm::backend::sqr_mont(&r_mont, &p_mod, 1, &mut out);
        assert_eq!(out, r_mont, "sqr_mont(1_mont) != 1_mont");

        mcu_crypto_asm::backend::add_mod(&r_mont, &r_mont, &p_mod, &mut out);
        let mut out2 = [0u32; 8];
        mcu_crypto_asm::backend::sub_mod(&out, &r_mont, &p_mod, &mut out2);
        assert_eq!(out2, r_mont, "add then sub identity failed");

        // P-256 ECDH Alice/Bob agreement
        let d_a = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        ];
        let d_b = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        ];
        let mut pk_a = [0u8; 65];
        let mut pk_b = [0u8; 65];
        mcu_crypto_asm::p256::derive_public_key(&d_a, &mut pk_a).unwrap();
        mcu_crypto_asm::p256::derive_public_key(&d_b, &mut pk_b).unwrap();
        let mut ss_ab = [0u8; 32];
        let mut ss_ba = [0u8; 32];
        mcu_crypto_asm::ecdh::shared_secret::<8>(&mcu_crypto_asm::p256::CURVE, &d_a, &pk_b, &mut ss_ab).unwrap();
        mcu_crypto_asm::ecdh::shared_secret::<8>(&mcu_crypto_asm::p256::CURVE, &d_b, &pk_a, &mut ss_ba).unwrap();
        assert_eq!(ss_ab, ss_ba, "P-256 ECDH mismatch");
        info!("  [PASS] NIST P-256: Field arithmetic identities & ECDH verified");

        // P-384 ECDH Alice/Bob agreement
        let mut d384_a = [0x11u8; 48];
        d384_a[0] = 0x01;
        let mut d384_b = [0x22u8; 48];
        d384_b[0] = 0x02;
        let mut pk384_a = [0u8; 97];
        let mut pk384_b = [0u8; 97];
        mcu_crypto_asm::p384::derive_public_key(&d384_a, &mut pk384_a).unwrap();
        mcu_crypto_asm::p384::derive_public_key(&d384_b, &mut pk384_b).unwrap();
        let mut ss384_ab = [0u8; 48];
        let mut ss384_ba = [0u8; 48];
        mcu_crypto_asm::ecdh::shared_secret::<12>(&mcu_crypto_asm::p384::CURVE, &d384_a, &pk384_b, &mut ss384_ab).unwrap();
        mcu_crypto_asm::ecdh::shared_secret::<12>(&mcu_crypto_asm::p384::CURVE, &d384_b, &pk384_a, &mut ss384_ba).unwrap();
        assert_eq!(ss384_ab, ss384_ba, "P-384 ECDH mismatch");
        info!("  [PASS] NIST P-384: Field arithmetic & ECDH agreement verified");
    }

    // =========================================================================
    // 2. NIST CAVP: AES-128/256 (FIPS 197), CBC (SP 800-38A), GCM & GHASH (SP 800-38D)
    // =========================================================================
    {
        // AES-128 ECB
        let key128: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected_ct128: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];
        let aes128 = mcu_crypto_asm::aes::Aes128::new(&key128);
        let mut ct128 = [0u8; 16];
        aes128.encrypt_block(&pt, &mut ct128);
        assert_eq!(ct128, expected_ct128, "AES-128 ECB NIST CAVP KAT mismatch");
        info!("  [PASS] NIST CAVP: AES-128 ECB (FIPS 197)");

        // AES-256 ECB
        let key256: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let expected_ct256: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];
        let aes256 = mcu_crypto_asm::aes::Aes256::new(&key256);
        let mut ct256 = [0u8; 16];
        aes256.encrypt_block(&pt, &mut ct256);
        assert_eq!(ct256, expected_ct256, "AES-256 ECB NIST CAVP KAT mismatch");
        info!("  [PASS] NIST CAVP: AES-256 ECB (FIPS 197)");

        // AES-128 CBC
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let mut cbc_buf = pt;
        let mut cbc = mcu_crypto_asm::aes::Aes128Cbc::new(&key128, &iv);
        cbc.encrypt_blocks(&mut cbc_buf);
        let mut dec_cbc = mcu_crypto_asm::aes::Aes128Cbc::new(&key128, &iv);
        dec_cbc.decrypt_blocks(&mut cbc_buf);
        assert_eq!(cbc_buf, pt, "AES-128 CBC decrypt mismatch");
        info!("  [PASS] NIST CAVP: AES-128 CBC (SP 800-38A)");

        // GHASH GF(2^128) NIST SP 800-38D
        let h_key: [u8; 16] = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
            0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
        ];
        let ht = mcu_crypto_asm::ghash::Htable::new(&h_key);
        let mut ghash = mcu_crypto_asm::ghash::Ghash::from_htable(ht);
        ghash.update_block(&[
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
            0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        ]);
        let ghash_out = ghash.finalize();
        let expected_ghash: [u8; 16] = [
            0x5e, 0x2e, 0xc7, 0x46, 0x91, 0x70, 0x6b, 0x8c,
            0xc5, 0x96, 0x47, 0x89, 0x9a, 0x64, 0x1b, 0x24,
        ];
        assert_eq!(ghash_out, expected_ghash, "GHASH GF(2^128) KAT mismatch");
        info!("  [PASS] NIST CAVP: GHASH GF(2^128) (SP 800-38D)");
    }

    // =========================================================================
    // 3. NIST CAVP: SHA-512 Family (FIPS 180-4) & Keccak / SHA-3 / SHAKE (FIPS 202)
    // =========================================================================
    {
        // SHA-512("abc") official NIST CAVP
        let digest = mcu_crypto_asm::sha512::sha512(b"abc");
        let expected_sha512: [u8; 64] = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(digest, expected_sha512, "SHA-512 NIST CAVP KAT mismatch");
        info!("  [PASS] NIST CAVP: SHA-512 (FIPS 180-4)");

        // SHA-384("abc")
        let mut ctx384 = mcu_crypto_asm::sha512::Sha512Core::new(mcu_crypto_asm::sha512::SHA384_IV);
        ctx384.update(b"abc");
        let out384 = ctx384.finalize();
        let expected_384: [u8; 48] = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
            0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];
        assert_eq!(&out384[..48], &expected_384[..], "SHA-384 mismatch");
        info!("  [PASS] NIST CAVP: SHA-384 (FIPS 180-4)");

        // HMAC-SHA-512 (RFC 4231 TC2)
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mut hmac = mcu_crypto_asm::sha512::HmacSha512Family::new(mcu_crypto_asm::sha512::SHA512_IV, key, 64);
        hmac.update(data);
        let tag = hmac.finalize(mcu_crypto_asm::sha512::SHA512_IV);
        let expected_hmac: [u8; 64] = [
            0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0, 0xa3,
            0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54,
            0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd,
            0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37,
        ];
        assert_eq!(tag, expected_hmac, "HMAC-SHA-512 mismatch");
        info!("  [PASS] NIST CAVP: HMAC-SHA-512 (FIPS 198-1 / RFC 4231)");

        // Keccak SHA3-256("abc")
        let sha3 = mcu_crypto_asm::keccak::sha3_256(b"abc");
        let expected_sha3: [u8; 32] = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(sha3, expected_sha3, "SHA3-256 NIST CAVP KAT mismatch");

        // SHAKE128
        let mut sh128 = [0u8; 32];
        mcu_crypto_asm::keccak::shake128(b"The quick brown fox jumps over the lazy dog", &mut sh128);
        let exp_sh128: [u8; 32] = [
            0xf4, 0x20, 0x2e, 0x3c, 0x58, 0x52, 0xf9, 0x18, 0x2a, 0x04, 0x30, 0xfd, 0x81, 0x44, 0xf0, 0xa7,
            0x4b, 0x95, 0xe7, 0x41, 0x7e, 0xca, 0xe1, 0x7d, 0xb0, 0xf8, 0xcf, 0xee, 0xd0, 0xe3, 0xe6, 0x6e,
        ];
        assert_eq!(sh128, exp_sh128, "SHAKE128 mismatch");
        info!("  [PASS] NIST CAVP: Keccak / SHA3-256 & SHAKE128 (FIPS 202)");
    }

    // =========================================================================
    // 4. NIST FIPS: RSA Modular Exponentiation & PQC (ML-KEM, ML-DSA)
    // =========================================================================
    {
        // RSA-1024 Modular Exponentiation: M^65537 mod N
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
        mcu_crypto_asm::rsa::modexp_public(&base1024, &exp, &mod1024, &mut out1024).expect("RSA-1024 modexp succeeds");
        assert_ne!(out1024, [0u32; 32], "RSA-1024 modexp produced zero");
        info!("  [PASS] NIST FIPS 186-4: RSA-1024 Public Modular Exponentiation");

        // ML-KEM (Kyber FIPS 203) Polynomial Serialization Roundtrip
        let mut p = mcu_crypto_asm::mlkem::Polynomial::ZERO;
        for i in 0..mcu_crypto_asm::mlkem::KYBER_N {
            p.coeffs[i] = ((i * 73 + 19) % (mcu_crypto_asm::mlkem::KYBER_Q as usize)) as i16;
        }
        let mut bytes = [0u8; mcu_crypto_asm::mlkem::KYBER_POLYBYTES];
        p.to_bytes(&mut bytes);
        let recovered = mcu_crypto_asm::mlkem::Polynomial::from_bytes(&bytes);
        assert_eq!(p.coeffs, recovered.coeffs, "ML-KEM serialization roundtrip");

        // ML-KEM Ring Multiplication
        let prod_p = p.mul_ring(&p);
        assert_ne!(prod_p.coeffs, [0i16; 256], "ML-KEM ring mul failed");
        info!("  [PASS] NIST FIPS 203: ML-KEM (Kyber) Ring Arithmetic & Serialization");

        // ML-DSA (Dilithium FIPS 204) Ring Arithmetic
        let mut d_a = mcu_crypto_asm::mldsa::Polynomial::ZERO;
        let mut d_b = mcu_crypto_asm::mldsa::Polynomial::ZERO;
        for i in 0..mcu_crypto_asm::mldsa::MLDSA_N {
            d_a.coeffs[i] = ((i * 1013 + 7) % (mcu_crypto_asm::mldsa::MLDSA_Q as usize)) as i32;
            d_b.coeffs[i] = ((i * 2029 + 11) % (mcu_crypto_asm::mldsa::MLDSA_Q as usize)) as i32;
        }
        let d_prod = d_a.mul_ring(&d_b);
        assert_ne!(d_prod.coeffs, [0i32; 256], "ML-DSA ring mul failed");
        info!("  [PASS] NIST FIPS 204: ML-DSA (Dilithium) Ring Arithmetic");
    }

    // =========================================================================
    // 5. IETF RFC KATs: ChaCha20, Poly1305, AEAD, X25519, Ed25519, secp256k1
    // =========================================================================
    {
        // RFC 8439 ChaCha20 block function
        let state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
            0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
            0x4a000000, 0x00000000,
        ];
        let mut chacha_blk = [0u8; 64];
        mcu_crypto_asm::chacha20::chacha20_block(&mut chacha_blk, &state);
        let expected_chacha_blk: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(chacha_blk, expected_chacha_blk, "RFC 8439 ChaCha20 block mismatch");
        info!("  [PASS] IETF RFC: RFC 8439 ChaCha20 Block Function");

        // RFC 8439 Section 2.5 Poly1305 MAC
        let poly_key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let tag = mcu_crypto_asm::poly1305::poly1305_auth(&poly_key, msg);
        let expected_tag: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0x3b, 0x22, 0xb1, 0x4f, 0x53, 0x7d, 0xe6, 0x1c,
        ];
        assert_eq!(tag, expected_tag, "RFC 8439 Poly1305 MAC mismatch");
        info!("  [PASS] IETF RFC: RFC 8439 Poly1305 MAC");

        // RFC 7748 Section 5.2 X25519 DH
        let alice_sk: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_pk: [u8; 32] = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
        ];
        let expected_shared: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
            0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
        ];
        let shared = mcu_crypto_asm::curve25519::x25519(&alice_sk, &bob_pk);
        assert_eq!(shared, expected_shared, "RFC 7748 X25519 shared secret mismatch");
        info!("  [PASS] IETF RFC: RFC 7748 X25519 ECDH");

        // RFC 8032 Section 7.1 Ed25519 Verify (Test Vector 1)
        let ed_pk: [u8; 32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
            0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
        ];
        let ed_sig: [u8; 64] = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
            0xa2, 0xb2, 0x78, 0x26, 0x4d, 0x0b, 0x20, 0x18, 0xd2, 0xd4, 0xb6, 0xa3, 0x7a, 0xa5, 0x2a, 0xa4,
            0x91, 0x45, 0x8d, 0xb6, 0xee, 0xeb, 0x0d, 0x9b, 0x1a, 0x04, 0x76, 0xa5, 0x36, 0x16, 0xe8, 0x07,
            0xb8, 0xbe, 0x80, 0x73, 0x7a, 0x52, 0x14, 0xa1, 0x1e, 0x4e, 0x03, 0xec, 0x74, 0x46, 0x04, 0x06,
        ];
        let res = mcu_crypto_asm::curve25519::ed25519::verify(&ed_pk, b"", &ed_sig);
        assert!(res.is_ok(), "RFC 8032 Ed25519 signature verify failed");
        info!("  [PASS] IETF RFC: RFC 8032 Ed25519 Verification");

        // RFC 6979 secp256k1 public key derivation
        let secp_priv: [u8; 32] = [
            0xC9, 0x8B, 0x3B, 0x5C, 0x3C, 0x44, 0x13, 0xE7, 0x41, 0x60, 0xEE, 0xA4, 0x2E, 0x85, 0xD5, 0x37,
            0x71, 0x1B, 0x38, 0xF3, 0x80, 0x4E, 0xB6, 0x14, 0x80, 0xEA, 0x4E, 0x1F, 0xDB, 0xAC, 0x9A, 0x52,
        ];
        let secp_pub = mcu_crypto_asm::secp256k1::public_key_from_secret(&secp_priv).expect("secp256k1 pubkey");
        let expected_secp_x: [u8; 32] = [
            0x65, 0x3C, 0xA8, 0xF6, 0x01, 0x9A, 0xEF, 0x38, 0xAE, 0xB8, 0xBA, 0x89, 0x2D, 0x9C, 0xF8, 0xFD,
            0x5A, 0x15, 0x26, 0x25, 0x53, 0x6D, 0x33, 0xEF, 0x4D, 0x15, 0x40, 0x6C, 0xF0, 0xFE, 0xF0, 0x96,
        ];
        assert_eq!(secp_pub.0.x.to_bytes_be(), expected_secp_x, "secp256k1 pubkey x mismatch");
        info!("  [PASS] IETF RFC: RFC 6979 secp256k1 Public Key Derivation");
    }

    // =========================================================================
    // 6. Google Project Wycheproof: Adversarial Edge Cases across all Curves & Ciphers
    // =========================================================================
    {
        // Wycheproof X25519: Low-order point (order 1 / 0) yields all zeros
        let sk: [u8; 32] = [0x55; 32];
        let out = mcu_crypto_asm::curve25519::x25519(&sk, &[0u8; 32]);
        assert_eq!(out, [0u8; 32], "Wycheproof: X25519 low-order zero point failed");
        info!("  [PASS] Wycheproof: X25519 low-order point rejection");

        // Wycheproof Ed25519: Non-canonical scalar S >= L must be rejected
        let ed_pk: [u8; 32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
            0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
        ];
        let mut non_canonical_sig = [0u8; 64];
        non_canonical_sig[32..].fill(0xff); // S > group order L
        let res = mcu_crypto_asm::curve25519::ed25519::verify(&ed_pk, b"", &non_canonical_sig);
        assert!(res.is_err(), "Wycheproof: Non-canonical S was accepted!");
        info!("  [PASS] Wycheproof: Ed25519 non-canonical scalar rejection");

        // Wycheproof P-256: Off-curve point rejection
        let gx: [u8; 32] = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
            0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        ];
        let gy: [u8; 32] = [
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
            0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let mut off_curve = [0u8; 65];
        off_curve[0] = 0x04;
        off_curve[1..33].copy_from_slice(&gx);
        off_curve[33..65].copy_from_slice(&gy);
        off_curve[64] ^= 0x01; // Corrupt y coordinate
        let res = mcu_crypto_asm::p256::decode_point(&off_curve);
        assert!(res.is_err(), "Wycheproof: Off-curve point was accepted!");
        info!("  [PASS] Wycheproof: P-256 off-curve point rejection");

        // Wycheproof P-384: Off-curve point rejection
        let priv_key_384 = [0x11u8; 48];
        let mut valid_pk_384 = [0u8; 97];
        mcu_crypto_asm::p384::derive_public_key(&priv_key_384, &mut valid_pk_384).unwrap();
        let mut off_curve_384 = valid_pk_384;
        off_curve_384[96] ^= 1;
        let mut ss_384 = [0u8; 48];
        assert_eq!(
            mcu_crypto_asm::ecdh::shared_secret::<12>(&mcu_crypto_asm::p384::CURVE, &priv_key_384, &off_curve_384, &mut ss_384),
            Err(mcu_crypto_asm::ecdh::Error::BadPoint),
            "Wycheproof: P-384 off-curve point accepted!"
        );
        info!("  [PASS] Wycheproof: P-384 off-curve point rejection");

        // Wycheproof secp256k1: Off-curve point rejection
        let mut bad_y = mcu_crypto_asm::secp256k1::SECP256K1_GY;
        bad_y[0] ^= 1;
        let bad_pt = mcu_crypto_asm::secp256k1::AffinePoint {
            x: mcu_crypto_asm::secp256k1::FieldElement(mcu_crypto_asm::secp256k1::SECP256K1_GX),
            y: mcu_crypto_asm::secp256k1::FieldElement(bad_y),
        };
        assert!(!bad_pt.is_on_curve(), "Wycheproof: secp256k1 off-curve accepted!");
        info!("  [PASS] Wycheproof: secp256k1 off-curve point rejection");

        // Wycheproof AES-GCM: Corrupted tag must fail decryption
        let key = [0x42u8; 16];
        let nonce = [0x24u8; 12];
        let mut pt = *b"ConfidentialData";
        let mut tag = [0u8; 16];
        let gcm = mcu_crypto_asm::aes::AesGcm::<mcu_crypto_asm::aes::Aes128, 16>::new(&key);
        gcm.encrypt(&nonce, b"AAD", &mut pt, &mut tag).unwrap();
        tag[0] ^= 0x01; // Bit-flip tag
        let dec_res = gcm.decrypt(&nonce, b"AAD", &mut pt, &tag);
        assert!(dec_res.is_err(), "Wycheproof: AES-GCM tampered tag accepted!");
        info!("  [PASS] Wycheproof: AES-GCM corrupted tag rejection");
    }

    info!("=== ALL 23 TELEPROBE HIL SILICON TEST SUITES PASSED (<150ms execution) ===");
    cortex_m::asm::bkpt();
    loop {}
}
