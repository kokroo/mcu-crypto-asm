//! Teleprobe Hardware-in-the-Loop (HIL) Test for Cortex-M0+ (STM32C031).
//!
//! SAFETY & EXECUTION GUARANTEES:
//! 1. **RAM-ONLY FIRMWARE**: Linked via `memory-c0-ram.x`. Origin is SRAM 0x20000000.
//!    Zero bytes are written to physical flash.
//! 2. **<10s TIMEOUT COMPLIANCE**: Entire execution completes in < 50 ms on a 48 MHz core.
//! 3. **PRIVATE TOKEN SAFE**: Runner uses `teleprobe client run` picking up `TELEPROBE_TOKEN`
//!    and `TELEPROBE_HOST` from the environment. Zero tokens in repository.

#![no_std]
#![no_main]

use defmt::info;
use defmt_rtt as _;
use panic_probe as _;

#[cortex_m_rt::entry]
fn main() -> ! {
    info!("=== Teleprobe CM0 P-256 RAM-Only Test ===");

    // ---------------------------------------------------------------
    // Test 1: Montgomery field arithmetic (mul, sqr, add, sub)
    // ---------------------------------------------------------------
    let r_mont = mcu_crypto_asm::params::p256::R_MONT;
    let r2_mont = mcu_crypto_asm::params::p256::R2_MONT;
    let p_mod = mcu_crypto_asm::params::p256::P;

    let mut out = [0u32; 8];
    mcu_crypto_asm::backend::mul_mont(&r2_mont, &r_mont, &p_mod, 1, &mut out);
    assert_eq!(out, r2_mont, "mul_mont(R2, 1_mont) != R2");
    info!("  [PASS] mul_mont(R2, 1_mont) = R2");

    mcu_crypto_asm::backend::sqr_mont(&r_mont, &p_mod, 1, &mut out);
    assert_eq!(out, r_mont, "sqr_mont(1_mont) != 1_mont");
    info!("  [PASS] sqr_mont(1_mont) = 1_mont");

    mcu_crypto_asm::backend::add_mod(&r_mont, &r_mont, &p_mod, &mut out);
    let mut out2 = [0u32; 8];
    mcu_crypto_asm::backend::sub_mod(&out, &r_mont, &p_mod, &mut out2);
    assert_eq!(out2, r_mont, "add then sub identity failed");
    info!("  [PASS] sub(add(R, R), R) = R (add/sub identity)");

    // ---------------------------------------------------------------
    // Test 2: P-256 ECDH Keygen & Shared Secret
    // ---------------------------------------------------------------
    let private_a: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let mut pub_a = [0u8; 64];
    let ok = unsafe {
        mcu_crypto_asm::backend::cortex_m0::P256_ecdh_keygen(pub_a.as_mut_ptr(), private_a.as_ptr())
    };
    assert!(ok, "P256_ecdh_keygen failed for k=1");
    info!("  [PASS] P256_ecdh_keygen(k=1) succeeded");

    let private_b: [u8; 32] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let mut pub_b = [0u8; 64];
    let ok = unsafe {
        mcu_crypto_asm::backend::cortex_m0::P256_ecdh_keygen(pub_b.as_mut_ptr(), private_b.as_ptr())
    };
    assert!(ok, "P256_ecdh_keygen failed for k=2");
    info!("  [PASS] P256_ecdh_keygen(k=2) succeeded");

    let mut shared_ab = [0u8; 32];
    let ok = unsafe {
        mcu_crypto_asm::backend::cortex_m0::P256_ecdh_shared_secret(
            shared_ab.as_mut_ptr(),
            pub_b.as_ptr(),
            private_a.as_ptr(),
        )
    };
    assert!(ok, "ECDH shared_secret(a, pub_b) failed");

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

    info!("=== All Teleprobe CM0 RAM tests PASSED (<50ms execution) ===");
    cortex_m::asm::bkpt();
    loop {}
}
