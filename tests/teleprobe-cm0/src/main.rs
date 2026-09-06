//! Teleprobe test for the Cortex-M0 P-256 assembly backend.
//!
//! Runs on nucleo-stm32c031c6 (Cortex-M0+ @ 48 MHz) via teleprobe.
//! Tests: Montgomery field arithmetic (mul, sqr, add, sub) and full ECDH.

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_time::Instant;
use panic_probe as _;

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let _p = embassy_stm32::init(Default::default());
    info!("=== CM0 P-256 Assembly Test ===");

    // ---------------------------------------------------------------
    // Test 1: Montgomery mul(R, R) = R^2 mod p
    // R_MONT * R_MONT = R^2 * R^-1 = R (should give R_MONT again? No.)
    // Actually: mul_mont(a, b) = a * b * R^-1 mod p.
    // So mul_mont(R, R) = R * R * R^-1 = R = R_MONT.
    // Wait, that's identity. Let me use a real KAT instead.
    //
    // mul_mont(R2, 1_in_mont) = R2 * R * R^-1 = R2
    // Actually simplest: mul_mont(a, R_MONT) = a * R * R^-1 = a.
    // So mul_mont(R2_MONT, R_MONT) should equal R2_MONT.
    // ---------------------------------------------------------------

    let r_mont = mcu_crypto_asm::params::p256::R_MONT;
    let r2_mont = mcu_crypto_asm::params::p256::R2_MONT;
    let p_mod = mcu_crypto_asm::params::p256::P;

    // Test mul_mont(R2, R_MONT) = R2 (since R_MONT is "1" in Montgomery)
    let mut out = [0u32; 8];
    mcu_crypto_asm::backend::mul_mont(&r2_mont, &r_mont, &p_mod, 1, &mut out);
    assert_eq!(out, r2_mont, "mul_mont(R2, 1_mont) != R2");
    info!("  [PASS] mul_mont(R2, 1_mont) = R2");

    // Test sqr_mont(R_MONT) = R_MONT (since 1^2 = 1 in Montgomery)
    mcu_crypto_asm::backend::sqr_mont(&r_mont, &p_mod, 1, &mut out);
    assert_eq!(out, r_mont, "sqr_mont(1_mont) != 1_mont");
    info!("  [PASS] sqr_mont(1_mont) = 1_mont");

    // Test add_mod(R_MONT, R_MONT) and round-trip: sub(add(R, R), R) == R
    mcu_crypto_asm::backend::add_mod(&r_mont, &r_mont, &p_mod, &mut out);
    let mut out2 = [0u32; 8];
    mcu_crypto_asm::backend::sub_mod(&out, &r_mont, &p_mod, &mut out2);
    assert_eq!(out2, r_mont, "add then sub identity failed");
    info!("  [PASS] sub(add(R, R), R) = R (add/sub identity)");

    // Test mul_mont(a, a) == sqr_mont(a) for a = R2_MONT
    let mut mul_result = [0u32; 8];
    let mut sqr_result = [0u32; 8];
    mcu_crypto_asm::backend::mul_mont(&r2_mont, &r2_mont, &p_mod, 1, &mut mul_result);
    mcu_crypto_asm::backend::sqr_mont(&r2_mont, &p_mod, 1, &mut sqr_result);
    assert_eq!(mul_result, sqr_result, "mul(a,a) != sqr(a)");
    info!("  [PASS] mul(R2, R2) == sqr(R2)");

    // ---------------------------------------------------------------
    // Test 2: Full P-256 ECDH key generation + shared secret
    // Uses the high-level assembly functions directly.
    // Emil's code uses little-endian byte order.
    // ---------------------------------------------------------------

    // A known private key (little-endian)
    let private_a: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut pub_a = [0u8; 64];

    let t0 = Instant::now();
    let ok = unsafe {
        mcu_crypto_asm::backend::cortex_m0::P256_ecdh_keygen(
            pub_a.as_mut_ptr(),
            private_a.as_ptr(),
        )
    };
    let keygen_us = t0.elapsed().as_micros();
    assert!(ok, "P256_ecdh_keygen failed for k=1");
    info!("  [PASS] P256_ecdh_keygen(k=1) succeeded in {} us", keygen_us);

    // k=1 * G should give the base point. In little-endian:
    // Gx (LE) = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
    // reversed byte order for LE:
    // The P256-cortex-ecdh lib uses LE bytes, so Gx[0..32] should be Gx in LE.
    // Gx BE: 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
    // Gx LE bytes: 96 c2 98 d8 45 39 a1 f4 a0 33 eb 2d 81 7d 03 77 f2 40 a4 63 e5 e6 bc f8 47 42 2c e1 f2 d1 17 6b
    let expected_gx_le: [u8; 32] = [
        0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4,
        0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
        0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8,
        0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b,
    ];
    assert_eq!(&pub_a[..32], &expected_gx_le, "k=1 * G: Gx mismatch");
    info!("  [PASS] k=1 * G = G (base point x-coordinate verified)");

    // Second key pair with k=2
    let private_b: [u8; 32] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut pub_b = [0u8; 64];
    let ok = unsafe {
        mcu_crypto_asm::backend::cortex_m0::P256_ecdh_keygen(
            pub_b.as_mut_ptr(),
            private_b.as_ptr(),
        )
    };
    assert!(ok, "P256_ecdh_keygen failed for k=2");
    info!("  [PASS] P256_ecdh_keygen(k=2) succeeded");

    // ECDH: shared_ab = private_a * pub_b
    let mut shared_ab = [0u8; 32];
    let ok = unsafe {
        mcu_crypto_asm::backend::cortex_m0::P256_ecdh_shared_secret(
            shared_ab.as_mut_ptr(),
            pub_b.as_ptr(),
            private_a.as_ptr(),
        )
    };
    assert!(ok, "ECDH shared_secret(a, pub_b) failed");

    // ECDH: shared_ba = private_b * pub_a
    let mut shared_ba = [0u8; 32];
    let ok = unsafe {
        mcu_crypto_asm::backend::cortex_m0::P256_ecdh_shared_secret(
            shared_ba.as_mut_ptr(),
            pub_a.as_ptr(),
            private_b.as_ptr(),
        )
    };
    assert!(ok, "ECDH shared_secret(b, pub_a) failed");

    assert_eq!(shared_ab, shared_ba, "ECDH shared secrets don't match!");
    info!("  [PASS] ECDH: shared_ab == shared_ba");

    // For k_a=1, k_b=2: shared = 1*2G = 2G, which is the same as pub_b x-coord
    assert_eq!(&shared_ab, &pub_b[..32], "shared secret != x(2G)");
    info!("  [PASS] ECDH shared secret = x(k_a * k_b * G) as expected");

    // ---------------------------------------------------------------
    // Benchmark: Time a full ECDH keygen
    // ---------------------------------------------------------------
    let private_bench: [u8; 32] = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
        0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
        0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
        0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
    ];
    let mut pub_bench = [0u8; 64];

    let t0 = Instant::now();
    let ok = unsafe {
        mcu_crypto_asm::backend::cortex_m0::P256_ecdh_keygen(
            pub_bench.as_mut_ptr(),
            private_bench.as_ptr(),
        )
    };
    let bench_us = t0.elapsed().as_micros();
    assert!(ok, "benchmark keygen failed");
    info!("  [BENCH] ECDH keygen: {} us", bench_us);

    info!("=== All CM0 P-256 tests PASSED ===");
    cortex_m::asm::bkpt();
}
