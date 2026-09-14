//! embassy-crypto-test Wycheproof/generated suites against the MCU driver.
//!
//! Dual-mode test target (cargo-qemu-test's dual-demo pattern):
//! - host: `cargo test --features embassy-driver --test embassy_suites` runs a
//!   libtest-mimic `main`, keeping libtest-style output;
//! - bare metal: `cargo qtest --target thumbv7em-none-eabihf --features
//!   embassy-driver --test embassy_suites` compiles the same cases as an
//!   `embedded_test::tests` module and runs each one in a fresh QEMU boot
//!   (MPS2-AN386 / Cortex-M4).
//!
//! Test-only: the RNG lives in embassy-crypto-test and is never shipped in the
//! driver.

#![cfg_attr(target_os = "none", no_std, no_main)]
#![allow(unexpected_cfgs)]

#[cfg(target_os = "none")]
use cortex_m as _;
#[cfg(target_os = "none")]
use cortex_m_rt as _;
#[allow(unused_imports)]
use mcu_crypto_asm as _;

macro_rules! suites {
    ($($(#[$m:meta])* $name:ident),* $(,)?) => {
        #[qemu_test::tests]
        mod embedded {
            #[cfg(target_os = "none")]
            use semihosting::println;

            #[init]
            fn init() {}

            $(#[test]
            $(#[$m])*
            #[cfg(feature = "embassy-driver")]
            fn $name() {
                println!("hello world");

                let outcome = embassy_crypto_test::$name();
                if let Err(e) = &outcome {
                    println!("test failed: {:?}", e);
                }

                assert!(outcome.unwrap().passed > 0);
            })*
        }
    };
}

suites! {
    sha384, sha512, sha512_224, sha512_256,
    hmac_sha384, hmac_sha512, hmac_sha512_224, hmac_sha512_256,
    aes128_ecb, aes256_ecb, aes128_cbc, aes256_cbc, aes128_ctr, aes256_ctr,
    aes128_gcm, aes256_gcm, aes128_ccm, aes256_ccm,
    p256_arith, p256_ecdh, p256_ecdsa, p384_arith, p384_ecdh, p384_ecdsa,
    x25519_dh, x25519_keygen, ed25519_verify, ed25519_sign,
}
