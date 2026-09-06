//! Cortex-M0 / Cortex-M0+ (ARMv6-M) backend.
//!
//! Hand-written 16-bit Thumb-1 assembly from Emil Lenngren's `P256-cortex-ecdh`,
//! adapted for constant-time execution on pure ARMv6-M microcontrollers without
//! 64-bit hardware multiplier (`UMAAL` or `UMULL`).

use core::arch::global_asm;

global_asm!(include_str!("../../asm/cortex_m0_p256.S"), options(raw));

#[allow(dead_code)]
extern "C" {
    pub(crate) fn emill_cm0_p256_mul_mont(out: *mut u32, a: *const u32, b: *const u32);
    pub(crate) fn emill_cm0_p256_sqr_mont(out: *mut u32, a: *const u32);
    pub(crate) fn emill_cm0_p256_add_mod(out: *mut u32, a: *const u32, b: *const u32);
    pub(crate) fn emill_cm0_p256_sub_mod(out: *mut u32, a: *const u32, b: *const u32);
    pub(crate) fn emill_cm0_p256_from_mont(out: *mut u32, a: *const u32);
    pub(crate) fn emill_cm0_p256_to_mont(out: *mut u32, a: *const u32);

    pub fn P256_pointmult(
        result_point: *mut u8,
        point: *const u8,
        scalar: *const u8,
        include_y_in_result: bool,
    ) -> bool;
    pub fn P256_ecdh_keygen(result_my_public_point: *mut u8, private_key: *const u8) -> bool;
    pub fn P256_ecdh_shared_secret(
        result_point_x: *mut u8,
        others_public_point: *const u8,
        private_key: *const u8,
    ) -> bool;
}

#[inline]
pub fn try_mul_mont(a: &[u32], b: &[u32], p: &[u32], n0inv: u32, out: &mut [u32]) -> bool {
    if n0inv != 1 {
        return false;
    }
    debug_assert_eq!(b.len(), a.len());
    debug_assert_eq!(p.len(), a.len());
    debug_assert_eq!(out.len(), a.len());

    match a.len() {
        8 => unsafe {
            emill_cm0_p256_mul_mont(out.as_mut_ptr(), a.as_ptr(), b.as_ptr());
            true
        },
        _ => false,
    }
}

#[inline]
pub fn try_sqr_mont(a: &[u32], p: &[u32], n0inv: u32, out: &mut [u32]) -> bool {
    if n0inv != 1 {
        return false;
    }
    debug_assert_eq!(p.len(), a.len());
    debug_assert_eq!(out.len(), a.len());

    match a.len() {
        8 => unsafe {
            emill_cm0_p256_sqr_mont(out.as_mut_ptr(), a.as_ptr());
            true
        },
        _ => false,
    }
}

#[inline]
pub fn try_add_mod(a: &[u32], b: &[u32], p: &[u32], out: &mut [u32]) -> bool {
    debug_assert_eq!(b.len(), a.len());
    debug_assert_eq!(p.len(), a.len());
    debug_assert_eq!(out.len(), a.len());

    match a.len() {
        8 => unsafe {
            emill_cm0_p256_add_mod(out.as_mut_ptr(), a.as_ptr(), b.as_ptr());
            true
        },
        _ => false,
    }
}

#[inline]
pub fn try_sub_mod(a: &[u32], b: &[u32], p: &[u32], out: &mut [u32]) -> bool {
    debug_assert_eq!(b.len(), a.len());
    debug_assert_eq!(p.len(), a.len());
    debug_assert_eq!(out.len(), a.len());

    match a.len() {
        8 => unsafe {
            emill_cm0_p256_sub_mod(out.as_mut_ptr(), a.as_ptr(), b.as_ptr());
            true
        },
        _ => false,
    }
}
