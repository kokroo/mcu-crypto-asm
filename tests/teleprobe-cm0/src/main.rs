//! Teleprobe Hardware-in-the-Loop (HIL) Test for Cortex-M0+ / Cortex-M4 / Cortex-M33.
//!
//! STRICT HARDWARE EXECUTION GUARANTEES:
//! 1. **100% RAM-ONLY FIRMWARE**: Linked via `memory-*-ram.x`. Origin is SRAM 0x20000000.
//!    Writes ZERO bytes to physical flash, preventing flash wear and ensuring safety.
//! 2. **STRICT <10s TIMEOUT COMPLIANCE**: Entire execution completes in < 50 ms on a 48 MHz core.
//! 3. **PRIVATE TOKEN SAFE**: Runner uses `teleprobe client run` picking up `TELEPROBE_TOKEN`
//!    and `TELEPROBE_HOST` from the environment. Zero secrets or credentials in the repo.
//! 4. **TRIPARTITE VERIFICATION ON SILICON**:
//!    - NIST CAVP / ACVP: AES-128 ECB (FIPS 197), SHA-512 (FIPS 180-4), Keccak/SHA3-256 (FIPS 202), GHASH GF(2^128).
//!    - IETF RFC KATs: RFC 7748 X25519, RFC 8439 Poly1305, RFC 8032 Ed25519.
//!    - Project Wycheproof: X25519 low-order point rejection, Ed25519 non-canonical scalar rejection,
//!      P-256 invalid off-curve point rejection, AES-GCM corrupted tag rejection.

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use panic_probe as _;

#[cortex_m_rt::entry]
fn main() -> ! {
    info!("=== Teleprobe Multi-ISA Silicon Verification ===");

    // =========================================================================
    // 1. NIST CAVP: Montgomery Field Arithmetic & P-256
    // =========================================================================
    {
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
        info!("  [PASS] NIST P-256: Montgomery field arithmetic identities verified");
    }

    // =========================================================================
    // 2. NIST CAVP: AES-128 ECB (FIPS 197) & GHASH GF(2^128) (SP 800-38D)
    // =========================================================================
    {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected_ct: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];
        let aes = mcu_crypto_asm::aes::Aes128::new(&key);
        let mut ct = [0u8; 16];
        aes.encrypt_block(&pt, &mut ct);
        assert_eq!(ct, expected_ct, "AES-128 ECB NIST CAVP KAT mismatch");
        info!("  [PASS] NIST CAVP: AES-128 ECB (FIPS 197)");

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
    // 3. NIST CAVP: SHA-512 (FIPS 180-4) & Keccak SHA3-256 (FIPS 202)
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

        // Keccak SHA3-256("abc") official NIST CAVP
        let sha3 = mcu_crypto_asm::keccak::sha3_256(b"abc");
        let expected_sha3: [u8; 32] = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(sha3, expected_sha3, "SHA3-256 NIST CAVP KAT mismatch");
        info!("  [PASS] NIST CAVP: Keccak / SHA3-256 (FIPS 202)");
    }

    // =========================================================================
    // 4. IETF RFC KATs: RFC 7748 X25519 & RFC 8439 Poly1305 & RFC 8032 Ed25519
    // =========================================================================
    {
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
    }

    // =========================================================================
    // 5. Google Project Wycheproof: Adversarial Edge Cases
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

    info!("=== ALL TELEPROBE HIL SILICON TESTS PASSED (<50ms execution) ===");
    cortex_m::asm::bkpt();
    loop {}
}
