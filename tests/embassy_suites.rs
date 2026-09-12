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

#[cfg(feature = "embassy-driver")]
mod embassy_suites_tests {
    // Force cortex-m-rt onto the link line: rustc drops unused dev-dep rlibs,
    // and link.x needs its DefaultHandler_ trampoline.
    #[cfg(target_os = "none")]
    use cortex_m_rt as _;

    #[cfg(target_os = "none")]
    use embassy_crypto_test::Outcome;

    /// Shared verdict logic, allocation-free so it works on both sides: a suite
    /// must run to completion and cover at least one case.
    #[cfg(target_os = "none")]
    fn assert_suite(outcome: Outcome) {
        let stats = outcome.unwrap();
        assert!(stats.passed > 0);
    }

    // Single source of truth for the suite list: the macro emits one
    // libtest-mimic `Trial` per suite on host, and one `embedded_test` `#[test]`
    // per suite on bare metal.
    macro_rules! suites {
        ($($(#[$m:meta])* $name:ident),* $(,)?) => {
            #[cfg(not(target_os = "none"))]
            fn trials() -> Vec<libtest_mimic::Trial> {
                vec![$(
                    libtest_mimic::Trial::test(stringify!($name), move || {
                        let stats = embassy_crypto_test::$name().map_err(|f| {
                            format!("{} tcId={}: {}", f.suite, f.tc_id, f.what)
                        })?;
                        if stats.passed == 0 {
                            return Err("suite ran zero cases".into());
                        }
                        Ok(())
                    }),
                )*]
            }

            #[cfg(target_os = "none")]
            #[embedded_test::tests]
            mod embedded {
                #[init]
                fn init() {}

                $(#[test]
                $(#[$m])*
                fn $name() {
                    super::assert_suite(embassy_crypto_test::$name());
                })*
            }
        };
    }

    suites! {
        sha384, sha512, sha512_224, sha512_256,
        hmac_sha384, hmac_sha512, hmac_sha512_224, hmac_sha512_256,
        aes128_ecb, aes256_ecb, aes128_cbc, aes256_cbc, aes128_ctr, aes256_ctr,
        aes128_gcm, aes256_gcm, aes128_ccm, aes256_ccm,
        p256_ecdsa, p384_arith, p384_ecdh, p384_ecdsa,
        x25519_dh, x25519_keygen, ed25519_verify, ed25519_sign,
    }

    /// Linkage root: without a reference to the driver, the linker garbage-collects
    /// the embassy.rs object and every `_embassy_crypto_*` registration symbol
    /// stays undefined (this matters on the bare-metal link, where the suites find
    /// the MCU implementations through the registry).
    fn driver_link_root() {
        let _f: fn(
            &embassy_crypto::driver::P256Scalar,
            &embassy_crypto::driver::P256Scalar,
        ) -> embassy_crypto::driver::P256Scalar =
            <mcu_crypto_asm::embassy::McuCryptoAsmDriver as embassy_crypto::driver::P256Arith>::scalar_add;
    }

    #[cfg(target_os = "none")]
    #[embedded_test::tests]
    mod link_root {
        #[init]
        fn init() {}

        #[test]
        fn driver_link_root() {
            super::driver_link_root();
        }
    }

    #[cfg(not(target_os = "none"))]
    pub fn main() {
        let mut ts = trials();
        ts.push(libtest_mimic::Trial::test("driver_link_root", || {
            driver_link_root();
            Ok(())
        }));
        libtest_mimic::run(&libtest_mimic::Arguments::from_args(), ts).exit();
    }
}

/// Stub so `cargo test` works with the `embassy-driver` feature disabled.
/// The real `main` (libtest-mimic) above is cfg'd on the feature; this one
/// only exists when the file's inner cfg has emptied the crate.
#[cfg(not(target_os = "none"))]
fn main() {
    #[cfg(feature = "embassy-driver")]
    embassy_suites_tests::main();
}
