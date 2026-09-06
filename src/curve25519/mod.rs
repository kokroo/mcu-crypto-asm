//! Curve25519 and Ed25519 cryptography.
//!
//! Hand-written ARMv7E-M / ARMv8-M assembly backend (`cortex25519` / Emil Lenngren)
//! utilizing single-cycle `UMAAL` to compute X25519 in ~548,000 cycles.

#[cfg(nistp_asm_cm4)]
pub mod cortex_m;

#[cfg(nistp_asm_cm0)]
pub mod cortex_m0;

pub mod ed25519;
pub mod portable;
pub mod x25519;

pub use x25519::scalarmult as x25519;
