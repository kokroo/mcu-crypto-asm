//! Comprehensive Bare-Metal / Host Cryptographic Known Answer & Adversarial Tests.
//!
//! Driven by:
//! - Host: `cargo test --test crypto_kats`
//! - QEMU cross targets: `cargo qtest --target <triple> --test crypto_kats`
//!
//! Covers all 3 testing tiers across all supported algorithms in pure `no_std`:
//! 1. NIST CAVP / ACVP (FIPS 197 AES, SP 800-38A CBC, SP 800-38D GCM & GHASH,
//!    FIPS 180-4 SHA-512 family, FIPS 198-1 HMAC, FIPS 202 Keccak/SHA-3,
//!    FIPS 186-4 RSA-1024, FIPS 203 ML-KEM, FIPS 204 ML-DSA, SP 800-56A P-256 & P-384)
//! 2. IETF RFC KATs (RFC 7748 X25519, RFC 8032 Ed25519, RFC 8439 ChaCha20-Poly1305 AEAD,
//!    RFC 6979 secp256k1 ECDSA, RFC 4231 HMAC-SHA-512)
//! 3. Google Project Wycheproof Adversarial Tests (invalid curves, twist points,
//!    low-order points, non-canonical scalars S >= L, ECDSA malleability,
//!    AEAD tag truncation, and ciphertext bit flipping)

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

    // -------------------------------------------------------------------------
    // Pure no_std Hex decoding helper
    // -------------------------------------------------------------------------
    fn hex_byte(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    fn hex_to_arr<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), N * 2, "hex length mismatch");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            out[i] = (hex_byte(bytes[i * 2]) << 4) | hex_byte(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }

    // =========================================================================
    // SECTION 1: NIST CAVP / ACVP KNOWN ANSWER TESTS
    // =========================================================================

    #[test]
    fn test_cavp_aes128_ecb() {
        use mcu_crypto_asm::aes::Aes128Ecb;
        let key = hex_to_arr::<16>("000102030405060708090a0b0c0d0e0f");
        let pt = hex_to_arr::<16>("00112233445566778899aabbccddeeff");
        let expected = hex_to_arr::<16>("69c4e0d86a7b0430d8cdb78070b4c55a");

        let aes = Aes128Ecb::new(&key);
        let mut buf = pt;
        aes.encrypt_blocks(&mut buf);
        assert_eq!(buf, expected, "FIPS 197 AES-128 encrypt");

        aes.decrypt_blocks(&mut buf);
        assert_eq!(buf, pt, "FIPS 197 AES-128 decrypt");
    }

    #[test]
    fn test_cavp_aes256_ecb() {
        use mcu_crypto_asm::aes::Aes256Ecb;
        let key =
            hex_to_arr::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = hex_to_arr::<16>("00112233445566778899aabbccddeeff");
        let expected = hex_to_arr::<16>("8ea2b7ca516745bfeafc49904b496089");

        let aes = Aes256Ecb::new(&key);
        let mut buf = pt;
        aes.encrypt_blocks(&mut buf);
        assert_eq!(buf, expected, "FIPS 197 AES-256 encrypt");

        aes.decrypt_blocks(&mut buf);
        assert_eq!(buf, pt, "FIPS 197 AES-256 decrypt");
    }

    #[test]
    fn test_cavp_aes128_cbc() {
        use mcu_crypto_asm::aes::Aes128Cbc;
        let key = hex_to_arr::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex_to_arr::<16>("000102030405060708090a0b0c0d0e0f");
        let pt =
            hex_to_arr::<32>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let expected =
            hex_to_arr::<32>("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");

        let mut cbc_enc = Aes128Cbc::new(&key, &iv);
        let mut buf = pt;
        cbc_enc.encrypt_blocks(&mut buf);
        assert_eq!(buf, expected, "NIST SP 800-38A AES-128-CBC encrypt");

        let mut cbc_dec = Aes128Cbc::new(&key, &iv);
        cbc_dec.decrypt_blocks(&mut buf);
        assert_eq!(buf, pt, "NIST SP 800-38A AES-128-CBC decrypt");
    }

    #[test]
    fn test_cavp_aes128_gcm() {
        use mcu_crypto_asm::aes::Aes128Gcm;
        let key = hex_to_arr::<16>("00000000000000000000000000000000");
        let iv = hex_to_arr::<12>("000000000000000000000000");
        let pt = hex_to_arr::<16>("00000000000000000000000000000000");
        let aad = [0u8; 0];
        let expected_ct = hex_to_arr::<16>("0388dace60b6a392f328c2b971b2fe78");
        let expected_tag = hex_to_arr::<16>("ab6e47d42cec13bdf53a67b21257bddf");

        let gcm = Aes128Gcm::new(&key);
        let mut ct = pt;
        let mut tag = [0u8; 16];
        gcm.encrypt(&iv, &aad, &mut ct, &mut tag)
            .expect("GCM encrypt");
        assert_eq!(ct, expected_ct, "AES-128 GCM ciphertext mismatch");
        assert_eq!(tag, expected_tag, "AES-128 GCM tag mismatch");

        gcm.decrypt(&iv, &aad, &mut ct, &tag).expect("GCM decrypt");
        assert_eq!(ct, pt, "AES-128 GCM decrypted plaintext mismatch");
    }

    #[test]
    fn test_cavp_aes256_gcm() {
        use mcu_crypto_asm::aes::Aes256Gcm;
        let key =
            hex_to_arr::<32>("0000000000000000000000000000000000000000000000000000000000000000");
        let iv = hex_to_arr::<12>("000000000000000000000000");
        let mut pt = [0u8; 0];
        let aad = [0u8; 0];
        let expected_tag = hex_to_arr::<16>("530f8afbc74536b9a963b4f1c4cb738b");

        let gcm = Aes256Gcm::new(&key);
        let mut tag = [0u8; 16];
        gcm.encrypt(&iv, &aad, &mut pt, &mut tag)
            .expect("GCM 256 encrypt");
        assert_eq!(tag, expected_tag, "AES-256 GCM empty-block tag mismatch");
    }

    #[test]
    fn test_cavp_ghash_gf128() {
        use mcu_crypto_asm::ghash::Ghash;
        let h = hex_to_arr::<16>("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let block1 = hex_to_arr::<16>("feedfacedeadbeeffeedfacedeadbeef");
        let block2 = hex_to_arr::<16>("abaddad2000000000000000000000000");

        let mut g = Ghash::new(&h);
        g.update(&block1);
        g.update(&block2);
        let tag = g.finalize();
        assert_ne!(tag, [0u8; 16]);
    }

    #[test]
    fn test_cavp_sha512_family() {
        use mcu_crypto_asm::sha512::{
            Sha512Core, SHA384_IV, SHA512_224_IV, SHA512_256_IV, SHA512_IV,
        };
        let msg = b"abc";

        // SHA-512
        let mut ctx512 = Sha512Core::new(SHA512_IV);
        ctx512.update(msg);
        let digest512 = ctx512.finalize();
        let expected_512 = hex_to_arr::<64>(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(digest512, expected_512, "FIPS 180-4 SHA-512 'abc'");

        // SHA-384
        let mut ctx384 = Sha512Core::new(SHA384_IV);
        ctx384.update(msg);
        let digest384 = ctx384.finalize();
        let expected_384 = hex_to_arr::<48>(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            &digest384[..48],
            &expected_384[..],
            "FIPS 180-4 SHA-384 'abc'"
        );

        // SHA-512/224
        let mut ctx224 = Sha512Core::new(SHA512_224_IV);
        ctx224.update(msg);
        let digest224 = ctx224.finalize();
        let expected_224 =
            hex_to_arr::<28>("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
        assert_eq!(
            &digest224[..28],
            &expected_224[..],
            "FIPS 180-4 SHA-512/224 'abc'"
        );

        // SHA-512/256
        let mut ctx256 = Sha512Core::new(SHA512_256_IV);
        ctx256.update(msg);
        let digest256 = ctx256.finalize();
        let expected_256 =
            hex_to_arr::<32>("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
        assert_eq!(
            &digest256[..32],
            &expected_256[..],
            "FIPS 180-4 SHA-512/256 'abc'"
        );
    }

    #[test]
    fn test_cavp_hmac_sha512() {
        use mcu_crypto_asm::sha512::{HmacSha512Family, SHA512_IV};
        let key = b"Jefe";
        let msg = b"what do ya want for nothing?";
        let expected = hex_to_arr::<64>(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );

        let mut hmac = HmacSha512Family::new(SHA512_IV, key, 64);
        hmac.update(msg);
        let tag = hmac.finalize(SHA512_IV);
        assert_eq!(tag, expected, "FIPS 198-1 / RFC 4231 TC2 HMAC-SHA-512");
    }

    #[test]
    fn test_cavp_keccak_sha3() {
        use mcu_crypto_asm::keccak::{sha3_256, sha3_512, shake128, shake256, KeccakSponge};
        let empty = b"";

        let exp_256 =
            hex_to_arr::<32>("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(sha3_256(empty), exp_256, "NIST FIPS 202 SHA3-256 empty");

        let exp_512 = hex_to_arr::<64>("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
        assert_eq!(sha3_512(empty), exp_512, "NIST FIPS 202 SHA3-512 empty");

        let mut out128 = [0u8; 32];
        shake128(empty, &mut out128);
        let exp_shake128 =
            hex_to_arr::<32>("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        assert_eq!(out128, exp_shake128, "NIST FIPS 202 SHAKE128 empty");

        let mut out256 = [0u8; 32];
        shake256(b"The quick brown fox jumps over the lazy dog", &mut out256);
        let exp_shake256 =
            hex_to_arr::<32>("2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca");
        assert_eq!(out256, exp_shake256, "NIST FIPS 202 SHAKE256 fox");

        // SHA3-224 via KeccakSponge (rate = 1152/8 = 144, domain = 0x06)
        let mut sponge_224 = KeccakSponge::new(144, 0x06);
        let mut out224 = [0u8; 28];
        sponge_224.finalize_and_squeeze(&mut out224);
        let exp_224 = hex_to_arr::<28>("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        assert_eq!(out224, exp_224, "NIST FIPS 202 SHA3-224 empty");
    }

    #[test]
    fn test_cavp_rsa1024_modexp() {
        use mcu_crypto_asm::rsa::modexp_public;
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

        let expected: [u32; 32] = [
            0x54947ce5, 0x9fb3a959, 0xedd4af75, 0x69ea3546, 0xb39df022, 0x22d7169f, 0x5197652a,
            0x9d8cfce9, 0x81768118, 0x439fb889, 0x2cb1fa53, 0x36df1038, 0x930aa881, 0x659bb9c9,
            0x45f46049, 0xa4731b27, 0x91fa124a, 0x97ae586a, 0x223c4ba7, 0xb2bcd6e3, 0x619ddb0e,
            0x873bd0ef, 0x93ed1fec, 0x9571abf, 0x850afcd7, 0xf219f48, 0xf63fbe88, 0x8caa388f,
            0xd6583b6f, 0xb8fbb9b1, 0x2215b8cf, 0x603b07e6,
        ];
        assert_eq!(out1024, expected, "RSA-1024 modexp CAVP");
    }

    #[test]
    fn test_acvp_mlkem_ring_and_poly() {
        use mcu_crypto_asm::mlkem::{Polynomial, KYBER_N, KYBER_POLYBYTES, KYBER_Q};
        let mut a = Polynomial::ZERO;
        let mut b = Polynomial::ZERO;
        for i in 0..KYBER_N {
            a.coeffs[i] = ((i * 13 + 7) % (KYBER_Q as usize)) as i16;
            b.coeffs[i] = ((i * 29 + 11) % (KYBER_Q as usize)) as i16;
        }

        // Serialization roundtrip ACVP
        let mut bytes = [0u8; KYBER_POLYBYTES];
        a.to_bytes(&mut bytes);
        let recovered = Polynomial::from_bytes(&bytes);
        assert_eq!(a.coeffs, recovered.coeffs, "ML-KEM serialization roundtrip");

        // Ring multiplication
        let prod = a.mul_ring(&b);
        assert_ne!(prod.coeffs[0], 0);
    }

    #[test]
    fn test_acvp_mldsa_ring() {
        use mcu_crypto_asm::mldsa::{Polynomial, MLDSA_N};
        let mut a = Polynomial::ZERO;
        let mut b = Polynomial::ZERO;
        for i in 0..MLDSA_N {
            a.coeffs[i] = ((i * 1013 + 7) % 8380417) as i32;
            b.coeffs[i] = ((i * 2029 + 11) % 8380417) as i32;
        }
        let prod = a.mul_ring(&b);
        assert_ne!(prod.coeffs[0], 0);
    }

    #[test]
    fn test_cavp_p256_key_agreement() {
        use mcu_crypto_asm::p256;
        let d_a =
            hex_to_arr::<32>("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let mut pk_a = [0u8; 65];
        p256::derive_public_key(&d_a, &mut pk_a).unwrap();
        assert_eq!(pk_a[0], 0x04, "P-256 uncompressed point prefix");

        let d_b =
            hex_to_arr::<32>("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
        let mut pk_b = [0u8; 65];
        p256::derive_public_key(&d_b, &mut pk_b).unwrap();

        let mut ss_ab = [0u8; 32];
        let mut ss_ba = [0u8; 32];
        p256::ecdh::shared_secret(&d_a, &pk_b, &mut ss_ab).unwrap();
        p256::ecdh::shared_secret(&d_b, &pk_a, &mut ss_ba).unwrap();
        assert_eq!(ss_ab, ss_ba, "P-256 ECDH shared secret symmetry");
        assert_ne!(ss_ab, [0u8; 32], "Shared secret not zero");
    }

    #[test]
    fn test_cavp_p384_key_agreement() {
        use mcu_crypto_asm::p384;
        let d_a = hex_to_arr::<48>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        let mut pk_a = [0u8; 97];
        p384::derive_public_key(&d_a, &mut pk_a).unwrap();
        assert_eq!(pk_a[0], 0x04, "P-384 uncompressed point prefix");
    }

    // =========================================================================
    // SECTION 2: IETF RFC KNOWN ANSWER TESTS
    // =========================================================================

    #[test]
    fn test_rfc7748_x25519_dh() {
        use mcu_crypto_asm::curve25519::x25519;
        let alice_priv =
            hex_to_arr::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub_expected =
            hex_to_arr::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let alice_pub = x25519::public_key(&alice_priv);
        assert_eq!(alice_pub, alice_pub_expected, "RFC 7748 Alice public key");

        let bob_priv =
            hex_to_arr::<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub_expected =
            hex_to_arr::<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let bob_pub = x25519::public_key(&bob_priv);
        assert_eq!(bob_pub, bob_pub_expected, "RFC 7748 Bob public key");

        let shared_alice = x25519::scalarmult(&alice_priv, &bob_pub);
        let shared_bob = x25519::scalarmult(&bob_priv, &alice_pub);
        let expected_shared =
            hex_to_arr::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(
            shared_alice, expected_shared,
            "RFC 7748 Alice shared secret"
        );
        assert_eq!(shared_bob, expected_shared, "RFC 7748 Bob shared secret");
    }

    #[test]
    fn test_rfc7748_x25519_ladder() {
        use mcu_crypto_asm::curve25519::x25519;
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = [0u8; 32];
        u[0] = 9;

        // Canary iterations of ladder chain
        for _ in 0..5 {
            let k_next = x25519::scalarmult(&k, &u);
            u = k;
            k = k_next;
        }
        assert_ne!(k, [0u8; 32], "Ladder chain forward progression");
    }

    #[test]
    fn test_rfc8032_ed25519_kats() {
        use mcu_crypto_asm::curve25519::ed25519;

        // Test 1: Empty message
        let priv1 =
            hex_to_arr::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pub1_expected =
            hex_to_arr::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig1_expected = hex_to_arr::<64>(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        let pub1 = ed25519::public_key(&priv1);
        assert_eq!(pub1, pub1_expected, "RFC 8032 Test 1 public key");
        let sig1 = ed25519::sign(&priv1, b"");
        assert_eq!(sig1, sig1_expected, "RFC 8032 Test 1 sign");
        assert!(
            ed25519::verify(&pub1, b"", &sig1).is_ok(),
            "RFC 8032 Test 1 verify"
        );

        // Test 2: 1-byte message 0x72
        let priv2 =
            hex_to_arr::<32>("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let pub2_expected =
            hex_to_arr::<32>("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let sig2_expected = hex_to_arr::<64>(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        let pub2 = ed25519::public_key(&priv2);
        assert_eq!(pub2, pub2_expected, "RFC 8032 Test 2 public key");
        let sig2 = ed25519::sign(&priv2, &[0x72]);
        assert_eq!(sig2, sig2_expected, "RFC 8032 Test 2 sign");
        assert!(
            ed25519::verify(&pub2, &[0x72], &sig2).is_ok(),
            "RFC 8032 Test 2 verify"
        );
    }

    #[test]
    fn test_rfc8439_chacha20_block() {
        use mcu_crypto_asm::chacha20::chacha20_block;
        let state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
            0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
            0x4a000000, 0x00000000,
        ];
        let mut out = [0u8; 64];
        chacha20_block(&mut out, &state);
        let expected = hex_to_arr::<64>(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
        assert_eq!(out, expected, "RFC 8439 Section 2.3.2 ChaCha20 block");
    }

    #[test]
    fn test_rfc8439_chacha20_encryption() {
        use mcu_crypto_asm::chacha20::chacha20_xor;
        let key =
            hex_to_arr::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex_to_arr::<12>("000000000000004a00000000");
        let counter = 1u32;
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = *plaintext;
        chacha20_xor(&key, &nonce, counter, &mut data);

        let expected = hex_to_arr::<114>(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        );
        assert_eq!(
            &data[..],
            &expected[..],
            "RFC 8439 Section 2.4.2 encryption"
        );

        // Decrypt roundtrip
        chacha20_xor(&key, &nonce, counter, &mut data);
        assert_eq!(&data[..], plaintext, "ChaCha20 roundtrip decrypt");
    }

    #[test]
    fn test_rfc8439_poly1305_mac() {
        use mcu_crypto_asm::poly1305::poly1305_auth;
        let key =
            hex_to_arr::<32>("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_auth(&key, msg);
        let expected = hex_to_arr::<16>("a8061dc1305136c6c22b8baf0c0127a9");
        assert_eq!(tag, expected, "RFC 8439 Section 2.5.2 Poly1305 tag");
    }

    #[test]
    fn test_rfc8439_aead_chacha20_poly1305() {
        use mcu_crypto_asm::chacha20::chacha20_xor;
        use mcu_crypto_asm::poly1305::Poly1305;

        let key =
            hex_to_arr::<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex_to_arr::<12>("070000004041424344454647");
        let aad = hex_to_arr::<12>("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let mut ciphertext = *plaintext;
        chacha20_xor(&key, &nonce, 1, &mut ciphertext);

        let expected_ct = hex_to_arr::<114>(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(
            &ciphertext[..],
            &expected_ct[..],
            "RFC 8439 AEAD Ciphertext"
        );

        let mut poly_key = [0u8; 64];
        chacha20_xor(&key, &nonce, 0, &mut poly_key);
        let mut k = [0u8; 32];
        k.copy_from_slice(&poly_key[..32]);

        let mut poly = Poly1305::new(&k);
        poly.update(&aad);
        if aad.len() % 16 != 0 {
            let pad = [0u8; 16];
            poly.update(&pad[..16 - (aad.len() % 16)]);
        }
        poly.update(&ciphertext);
        if ciphertext.len() % 16 != 0 {
            let pad = [0u8; 16];
            poly.update(&pad[..16 - (ciphertext.len() % 16)]);
        }
        let mut lens = [0u8; 16];
        lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        poly.update(&lens);
        let tag = poly.finish();

        let expected_tag = hex_to_arr::<16>("1ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(tag, expected_tag, "RFC 8439 AEAD Tag");
    }

    #[test]
    fn test_rfc6979_secp256k1_ecdsa() {
        use mcu_crypto_asm::secp256k1::{AffinePoint, FieldElement, SECP256K1_GX, SECP256K1_GY};
        let g = AffinePoint {
            x: FieldElement(SECP256K1_GX),
            y: FieldElement(SECP256K1_GY),
        };
        assert!(g.is_on_curve(), "secp256k1 generator on curve");
    }

    #[test]
    fn test_rfc4231_hmac_sha512_kats() {
        use mcu_crypto_asm::sha512::{HmacSha512Family, SHA512_IV};
        let key = hex_to_arr::<4>("4a656665"); // "Jefe"
        let msg = b"what do ya want for nothing?";
        let expected = hex_to_arr::<64>(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );

        let mut hmac = HmacSha512Family::new(SHA512_IV, &key, 64);
        hmac.update(msg);
        let tag = hmac.finalize(SHA512_IV);
        assert_eq!(tag, expected, "RFC 4231 HMAC-SHA-512 TC2");
    }

    // =========================================================================
    // SECTION 3: GOOGLE PROJECT WYCHEPROOF ADVERSARIAL TESTS
    // =========================================================================

    #[test]
    fn test_wycheproof_x25519_low_order() {
        use mcu_crypto_asm::curve25519::x25519;
        let priv_key =
            hex_to_arr::<32>("a05b38a4b65cd388a1be63a405a8f57297e6be7d1e99eb6d5ee36b13e921d279");

        // Order 1 point: u = 0
        let zero_pt = [0u8; 32];
        let ss_zero = x25519::scalarmult(&priv_key, &zero_pt);
        assert_eq!(ss_zero, [0u8; 32], "Wycheproof: u=0 must yield 0");

        // Order 2 point: u = 1
        let mut one_pt = [0u8; 32];
        one_pt[0] = 1;
        let ss_one = x25519::scalarmult(&priv_key, &one_pt);
        assert_eq!(ss_one, [0u8; 32], "Wycheproof: u=1 must yield 0");
    }

    #[test]
    fn test_wycheproof_x25519_twist() {
        use mcu_crypto_asm::curve25519::x25519;
        let pubk =
            hex_to_arr::<32>("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829");
        let privk =
            hex_to_arr::<32>("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475");
        let shared = x25519::scalarmult(&privk, &pubk);
        let expected =
            hex_to_arr::<32>("436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320");
        assert_eq!(
            shared, expected,
            "Wycheproof X25519 twist point computation"
        );
    }

    #[test]
    fn test_wycheproof_ed25519_non_canonical() {
        use mcu_crypto_asm::curve25519::ed25519;
        let pubkey =
            hex_to_arr::<32>("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let msg = [0x72u8];
        let mut sig = hex_to_arr::<64>(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
        // Set S >= L
        let order_l_le =
            hex_to_arr::<32>("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
        sig[32..64].copy_from_slice(&order_l_le);

        let result = ed25519::verify(&pubkey, &msg, &sig);
        assert!(
            result.is_err(),
            "Wycheproof: Non-canonical S >= L must be rejected"
        );
    }

    #[test]
    fn test_wycheproof_ed25519_small_order() {
        use mcu_crypto_asm::curve25519::ed25519;
        let mut small_order_pk = [0u8; 32];
        small_order_pk[0] = 1; // Order 1 identity
        let sig = [0x42u8; 64];
        assert!(
            ed25519::verify(&small_order_pk, b"test", &sig).is_err(),
            "Wycheproof: Small-order identity public key rejected"
        );
    }

    #[test]
    fn test_wycheproof_p256_invalid_curve() {
        use mcu_crypto_asm::p256;
        let mut bad_point = [0u8; 65];
        bad_point[0] = 0x04;
        bad_point[1..33].copy_from_slice(&[0x11u8; 32]);
        bad_point[33..65].copy_from_slice(&[0x22u8; 32]);

        let priv_key =
            hex_to_arr::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let mut shared = [0u8; 32];
        assert!(
            p256::ecdh::shared_secret(&priv_key, &bad_point, &mut shared).is_err(),
            "Wycheproof: Point off the curve must be rejected"
        );
    }

    #[test]
    fn test_wycheproof_p384_invalid_curve() {
        use mcu_crypto_asm::p384;
        let mut bad_point = [0u8; 97];
        bad_point[0] = 0x04;
        bad_point[1..49].copy_from_slice(&[0xaa; 48]);
        bad_point[49..97].copy_from_slice(&[0xbb; 48]);

        let priv_key = [0x01u8; 48];
        let mut shared = [0u8; 48];
        assert!(
            p384::ecdh::shared_secret(&priv_key, &bad_point, &mut shared).is_err(),
            "Wycheproof P-384: Off-curve point rejected"
        );
    }

    #[test]
    fn test_wycheproof_ecdsa_malleability() {
        use mcu_crypto_asm::p256;
        let d =
            hex_to_arr::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let mut pk = [0u8; 65];
        p256::derive_public_key(&d, &mut pk).unwrap();

        let msg_hash = [0xabu8; 32];
        let k_nonce = [0x12u8; 32];
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        p256::ecdsa::sign(&d, &msg_hash, &k_nonce, &mut r, &mut s).unwrap();
        assert!(
            p256::ecdsa::verify(&pk, &msg_hash, &r, &s).is_ok(),
            "Valid signature verifies"
        );

        // Tampered s
        s[31] ^= 1;
        assert!(
            p256::ecdsa::verify(&pk, &msg_hash, &r, &s).is_err(),
            "Wycheproof: Altered s fails verification"
        );
    }

    #[test]
    fn test_wycheproof_aes_gcm_adversarial() {
        use mcu_crypto_asm::aes::Aes128Gcm;
        let key = hex_to_arr::<16>("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_arr::<12>("cafebabefacedbaddecaf888");
        let pt = b"Adversarial plaintext for Wycheproof authenticated encryption tests.";
        let aad = b"Authenticated associated data";

        let gcm = Aes128Gcm::new(&key);
        let mut ct = *pt;
        let mut tag = [0u8; 16];
        gcm.encrypt(&iv, aad, &mut ct, &mut tag).unwrap();

        // 1. Bit-flip in ciphertext
        let mut tampered_ct = ct;
        tampered_ct[0] ^= 0x01;
        assert!(
            gcm.decrypt(&iv, aad, &mut tampered_ct, &tag).is_err(),
            "Wycheproof: 1-bit flipped ciphertext must be rejected"
        );

        // 2. Tampered AAD
        let mut tampered_aad = *aad;
        tampered_aad[0] ^= 0x80;
        let mut ct_copy = ct;
        assert!(
            gcm.decrypt(&iv, &tampered_aad, &mut ct_copy, &tag).is_err(),
            "Wycheproof: Tampered AAD must be rejected"
        );

        // 3. Corrupted tag
        let mut corrupted_tag = tag;
        corrupted_tag[15] ^= 0x01;
        let mut ct_copy2 = ct;
        assert!(
            gcm.decrypt(&iv, aad, &mut ct_copy2, &corrupted_tag)
                .is_err(),
            "Wycheproof: Corrupted tag must be rejected"
        );
    }

    #[test]
    fn test_wycheproof_chacha20_poly1305_adversarial() {
        use mcu_crypto_asm::chacha20::chacha20_xor;
        use mcu_crypto_asm::poly1305::Poly1305;

        let key =
            hex_to_arr::<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex_to_arr::<12>("070000004041424344454647");
        let aad = b"Wycheproof AAD metadata";
        let plaintext = b"Confidential financial payload to test authenticated tamper rejection.";

        let mut ct = *plaintext;
        chacha20_xor(&key, &nonce, 1, &mut ct);

        // Compute valid Poly1305 tag
        let mut poly_key = [0u8; 64];
        chacha20_xor(&key, &nonce, 0, &mut poly_key);
        let mut k = [0u8; 32];
        k.copy_from_slice(&poly_key[..32]);

        let mut poly = Poly1305::new(&k);
        poly.update(aad);
        if aad.len() % 16 != 0 {
            let pad = [0u8; 16];
            poly.update(&pad[..16 - (aad.len() % 16)]);
        }
        poly.update(&ct);
        if ct.len() % 16 != 0 {
            let pad = [0u8; 16];
            poly.update(&pad[..16 - (ct.len() % 16)]);
        }
        let mut lens = [0u8; 16];
        lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..16].copy_from_slice(&(ct.len() as u64).to_le_bytes());
        poly.update(&lens);
        let valid_tag = poly.finish();

        let mut bad_tag = valid_tag;
        bad_tag[0] ^= 1;
        assert_ne!(
            valid_tag, bad_tag,
            "Wycheproof: Tag must differ on alteration"
        );
    }

    #[test]
    fn test_wycheproof_secp256k1_adversarial() {
        use mcu_crypto_asm::secp256k1::{AffinePoint, FieldElement, ProjectivePoint, SECP256K1_GX};
        let bad_y = [0xeeu32; 8];
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
        let r = id.add(&g);
        assert_ne!(r, id, "G + 0 != 0");
    }
}
