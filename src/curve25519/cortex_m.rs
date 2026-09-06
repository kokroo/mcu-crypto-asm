//! Cortex-M4/M7/M33 assembly backend for Curve25519 / Ed25519.
//!
//! Uses UMAAL-optimized assembly routines from `embassy-rs/cortex25519`
//! (Emil Lenngren).

use core::arch::global_asm;

global_asm!(include_str!("../../asm/cortex_m_fe25519.S"), options(raw));
global_asm!(include_str!("../../asm/cortex_m_curve25519.S"), options(raw));
global_asm!(include_str!("../../asm/cortex_m_ed25519.S"), options(raw));

extern "C" {
    pub fn curve25519_scalarmult(
        result: *mut u8,
        scalar: *const u8,
        point: *const u8,
    );

    pub fn ed25519_scalarmult(
        result: *mut [u32; 32],
        scalar: *const [u8; 32],
        point: *const [u32; 32],
    );
    pub fn ed25519_decompress(result: *mut [u32; 32], point: *const [u8; 32]) -> bool;
    pub fn ed25519_compress(result: *mut [u8; 32], point: *const [u32; 32]);
    pub fn ed25519_neg(point: *mut [u32; 32]);
    pub fn ed25519_add(result: *mut [u32; 32], a: *const [u32; 32], b: *const [u32; 32]);
}
