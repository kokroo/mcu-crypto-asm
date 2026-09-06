//! Cortex-M0 / Cortex-M0+ (ARMv6-M) backend for Curve25519.
//!
//! Uses Thomas Pornin's constant-time ARMv6-M assembly implementation (`pornin/x25519-cm0`).

use core::arch::global_asm;

global_asm!(include_str!("../../asm/cortex_m0_curve25519.S"), options(raw));

extern "C" {
    pub fn curve25519_scalarmult_cm0(
        result: *mut u8,
        scalar: *const u8,
        point: *const u8,
    );
    pub fn x25519(
        out: *mut u8,
        point: *const u8,
        scalar: *const u8,
    );
}

#[inline]
pub unsafe fn curve25519_scalarmult(
    result: *mut u8,
    scalar: *const u8,
    point: *const u8,
) {
    unsafe {
        curve25519_scalarmult_cm0(result, scalar, point);
    }
}
