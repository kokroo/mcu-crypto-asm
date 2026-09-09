//! embassy-crypto-test Wycheproof/generated suites against the MCU driver.
//! Test-only: the RNG below lives here and is never shipped in the driver.
#![cfg(feature = "embassy-driver")]

// RNG is provided by embassy-crypto-test itself (it registers its own TestRng).

macro_rules! suites {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            let stats = embassy_crypto_test::$name().unwrap();
            println!("{}: passed={} skipped={}", stringify!($name), stats.passed, stats.skipped);
            assert!(stats.passed > 0);
        }
    )*};
}

suites! {
    sha384, sha512, sha512_224, sha512_256,
    hmac_sha384, hmac_sha512, hmac_sha512_224, hmac_sha512_256,
    aes128_ecb, aes256_ecb, aes128_cbc, aes256_cbc, aes128_ctr, aes256_ctr,
    aes128_gcm, aes256_gcm, aes128_ccm, aes256_ccm, aes128_cmac, aes256_cmac,
    p256_arith, p256_ecdh, p256_ecdsa, p384_arith, p384_ecdh, p384_ecdsa,
    x25519_dh, x25519_keygen, ed25519_verify, ed25519_sign,
}

/// Linkage root: without a reference to the driver, the linker garbage-collects
/// the embassy.rs object and every `_embassy_crypto_*` registration symbol
/// stays undefined.
#[test]
fn driver_link_root() {
    let _f: fn(
        &embassy_crypto::driver::P256Scalar,
        &embassy_crypto::driver::P256Scalar,
    ) -> embassy_crypto::driver::P256Scalar =
        <mcu_crypto_asm::embassy::McuCryptoAsmDriver as embassy_crypto::driver::P256Arith>::scalar_add;
}
