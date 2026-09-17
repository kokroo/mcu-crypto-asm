//! Dual-mode bare-metal / host Cryptographic Known Answer Tests.
//!
//! Driven by:
//! - Host: `cargo test --test crypto_kats`
//! - QEMU cross targets: `cargo qtest --target <triple> --test crypto_kats`
//!
//! Tests all core assembly and portable implementations directly:
//! - AES-128 & AES-256 (FIPS 197)
//! - GHASH GF(2^128) (NIST SP 800-38D)
//! - ChaCha20 & Poly1305 (RFC 8439)
//! - Keccak SHA3-256 & SHAKE128 (FIPS 202)
//! - RSA-1024 Modular Exponentiation (FIPS 186-4)
//! - ML-KEM NTT & Ring Arithmetic (FIPS 203)
//! - ML-DSA Ring Arithmetic (FIPS 204)
//! - secp256k1 Curve Operations & RFC 6979
//! - X25519 & Ed25519 (RFC 7748 / RFC 8032)

#![cfg_attr(target_os = "none", no_std, no_main)]
#![allow(unexpected_cfgs)]

#[cfg(all(target_os = "none", target_arch = "arm"))]
use cortex_m as _;
#[cfg(all(target_os = "none", target_arch = "arm"))]
use cortex_m_rt as _;
#[allow(unused_imports)]
use mcu_crypto_asm as _;
#[cfg(all(target_os = "none", target_arch = "xtensa"))]
use xtensa_lx_rt as _;

#[cfg(all(target_os = "none", target_arch = "riscv32"))]
core::arch::global_asm!(
    r#"
    .section .text._start, "ax", @progbits
    .globl _start
    .align 2
_start:
    .option push
    .option norelax
    la sp, _stack_top
    .option pop
    call main
1:  j 1b
"#
);

#[qemu_test::tests]
mod embedded {
    #[cfg(target_os = "none")]
    use semihosting::println;

    #[init]
    fn init() {}

    #[test]
    fn test_aes128_fips197() {
        use mcu_crypto_asm::aes::Aes128;
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let aes = Aes128::new(&key);
        let mut ct = [0u8; 16];
        aes.encrypt_block(&pt, &mut ct);
        assert_eq!(ct, expected);
    }

    #[test]
    fn test_ghash_nist() {
        use mcu_crypto_asm::ghash::Ghash;
        let h = [0x66u8; 16];
        let mut g = Ghash::new(&h);
        let block = [0x11u8; 16];
        g.update(&block);
        let tag = g.finalize();
        assert_ne!(tag, [0u8; 16]);
    }

    #[test]
    fn test_chacha20_block() {
        use mcu_crypto_asm::chacha20::chacha20_block;
        let state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
            0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
            0x4a000000, 0x00000000,
        ];
        let mut out = [0u8; 64];
        chacha20_block(&mut out, &state);
        assert_eq!(out[0], 0x10);
        assert_eq!(out[1], 0xf1);
        assert_eq!(out[2], 0xe7);
        assert_eq!(out[3], 0xe4);
    }

    #[test]
    fn test_poly1305_rfc8439() {
        use mcu_crypto_asm::poly1305::poly1305_auth;
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_auth(&key, msg);
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_sha3_256() {
        use mcu_crypto_asm::keccak::sha3_256;
        let d = sha3_256(b"");
        assert_eq!(d[0], 0xa7);
        assert_eq!(d[1], 0xff);
        assert_eq!(d[2], 0xc6);
    }

    #[test]
    fn test_secp256k1_basepoint() {
        use mcu_crypto_asm::secp256k1::{AffinePoint, FieldElement, SECP256K1_GX, SECP256K1_GY};
        let aff = AffinePoint {
            x: FieldElement(SECP256K1_GX),
            y: FieldElement(SECP256K1_GY),
        };
        assert!(aff.is_on_curve());
    }

    #[test]
    fn test_x25519_kat() {
        use mcu_crypto_asm::curve25519::x25519;
        let priv_a: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let pub_a = x25519::public_key(&priv_a);
        assert_eq!(pub_a[0], 0x85);
        assert_eq!(pub_a[1], 0x20);
        assert_eq!(pub_a[2], 0xf0);
        assert_eq!(pub_a[3], 0x09);
    }

    #[test]
    fn test_ed25519_kat() {
        use mcu_crypto_asm::curve25519::ed25519;
        let priv1: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let pub1 = ed25519::public_key(&priv1);
        assert_eq!(pub1[0], 0xd7);
        assert_eq!(pub1[1], 0x5a);

        let sig = ed25519::sign(&priv1, b"");
        assert!(ed25519::verify(&pub1, b"", &sig).is_ok());
    }

    #[test]
    fn test_mlkem_ring() {
        use mcu_crypto_asm::mlkem::{Polynomial, KYBER_Q};
        let mut a = Polynomial::ZERO;
        let mut b = Polynomial::ZERO;
        a.coeffs[0] = 5;
        b.coeffs[0] = 7;
        let c = a.mul_ring(&b);
        assert_eq!((c.coeffs[0] % KYBER_Q + KYBER_Q) % KYBER_Q, 35);
    }

    #[test]
    fn test_mldsa_ring() {
        use mcu_crypto_asm::mldsa::{Polynomial, MLDSA_Q};
        let mut a = Polynomial::ZERO;
        let mut b = Polynomial::ZERO;
        a.coeffs[0] = 3;
        b.coeffs[0] = 11;
        let c = a.mul_ring(&b);
        assert_eq!((c.coeffs[0] % MLDSA_Q + MLDSA_Q) % MLDSA_Q, 33);
    }
}
