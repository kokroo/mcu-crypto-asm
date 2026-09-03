//! Fast constant-time NIST P-256 / P-384 field arithmetic for 32-bit MCUs.
//!
//! # Why this exists
//!
//! Hand-optimised P-256 for Cortex-M4 already exists (Emill/P256-Cortex-M4,
//! MIT). Nothing comparable exists for **P-384 on any MCU**, or for **Xtensa
//! LX7** (ESP32-S2/S3), which has no ECC accelerator at all.
//!
//! # Design
//!
//! The performance of an ECC implementation on a 32-bit MCU is decided almost
//! entirely by one operation: modular multiplication. So the assembly surface
//! is deliberately tiny — [`backend`] exposes `mul_mont`, `add_mod`, `sub_mod`
//! and nothing else. Point arithmetic, the scalar-multiplication ladder and
//! ECDH are portable Rust shared by every curve and every target. (ECDSA is
//! not implemented yet.)
//!
//! Representation is Montgomery form with CIOS reduction. Both NIST primes
//! satisfy `p ≡ -1 (mod 2^32)`, so `n0' = -p^-1 mod 2^32 == 1` and the
//! per-word reduction multiplier is free. `gen/gen_params.py` asserts this.
//!
//! # Constant time
//!
//! No operation branches on, or indexes memory by, a secret. Verified three
//! ways, because no single method sufficed: a static audit of the generated
//! assembly (`tests/constant_time.rs`), cycle-accurate measurement on real
//! hardware (`harness/src/bin/ct.rs`), and diffing executed instruction traces
//! (`harness/src/bin/scantrace.rs`).
//!
//! ⚠ The `core::hint::black_box` calls on masks and flags are **load bearing**:
//! without them LLVM compiles the constant-time table scan into an early-exit
//! search whose trip count is the secret digit. See the README before editing
//! them.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod backend;
pub mod comb_tables;
pub mod params;

pub mod ecdh;
mod fe;
mod point;
pub mod scalar_mul;
pub use fe::{Fe, Params};
pub use point::{CurveParams, Point};
pub use scalar_mul::{mul_base_yielding, mul_scalar_yielding, CombMul, ScalarMul};

/// P-256 (secp256r1) field arithmetic.
pub mod p256 {
    use crate::{params::p256 as c, Fe, Params};

    /// Number of 32-bit limbs in a P-256 field element.
    pub const N: usize = c::N;

    /// Field parameters for P-256.
    pub const FIELD: Params = Params {
        n: c::N,
        p: &c::P,
        n0inv: c::N0INV,
        r2: &c::R2_MONT,
        one: &c::R_MONT,
    };

    /// A P-256 field element in Montgomery form.
    pub type FeP256 = Fe<{ c::N }>;

    /// A point on P-256.
    pub type PointP256 = crate::Point<{ c::N }>;

    /// Curve parameters for P-256.
    pub const CURVE: crate::CurveParams = crate::CurveParams {
        field: FIELD,
        b_mont: &c::B_MONT,
        gx_mont: &c::GX_MONT,
        gy_mont: &c::GY_MONT,
        order: &c::ORDER,
    };

    /// Construct a field element from a plain (non-Montgomery) integer.
    pub fn from_int(limbs: &[u32; N]) -> FeP256 {
        Fe::from_int(&FIELD, limbs)
    }

    /// `k * G` via the compile-time comb table. Much faster than the general
    /// [`crate::Point::mul_scalar`], but only valid for the base point.
    pub fn mul_base(k: &[u32; N]) -> PointP256 {
        crate::Point::mul_base(&CURVE, k, &crate::comb_tables::P256_COMB, COMB_D, COMB_T)
    }

    /// Bits per comb block for this curve.
    pub const COMB_D: usize = crate::comb_tables::P256_COMB_D;

    /// Number of comb tables for this curve.
    pub const COMB_T: usize = crate::comb_tables::P256_COMB_T;

    /// SEC1 public key from a private scalar.
    pub fn derive_public_key(secret: &[u8], out: &mut [u8]) -> Result<(), crate::ecdh::Error> {
        crate::ecdh::derive_public_key::<N>(
            &CURVE,
            secret,
            out,
            &crate::comb_tables::P256_COMB,
            COMB_D,
            COMB_T,
        )
    }

    /// SEC1 public key, yielding every `budget` point operations.
    pub async fn derive_public_key_yielding(
        secret: &[u8],
        out: &mut [u8],
        budget: u32,
    ) -> Result<(), crate::ecdh::Error> {
        crate::ecdh::derive_public_key_yielding::<N>(
            &CURVE,
            secret,
            out,
            &crate::comb_tables::P256_COMB,
            COMB_D,
            COMB_T,
            budget,
        )
        .await
    }
}

/// P-384 (secp384r1) field arithmetic.
pub mod p384 {
    use crate::{params::p384 as c, Fe, Params};

    /// Number of 32-bit limbs in a P-384 field element.
    pub const N: usize = c::N;

    /// Field parameters for P-384.
    pub const FIELD: Params = Params {
        n: c::N,
        p: &c::P,
        n0inv: c::N0INV,
        r2: &c::R2_MONT,
        one: &c::R_MONT,
    };

    /// A P-384 field element in Montgomery form.
    pub type FeP384 = Fe<{ c::N }>;

    /// A point on P-384.
    pub type PointP384 = crate::Point<{ c::N }>;

    /// Curve parameters for P-384.
    pub const CURVE: crate::CurveParams = crate::CurveParams {
        field: FIELD,
        b_mont: &c::B_MONT,
        gx_mont: &c::GX_MONT,
        gy_mont: &c::GY_MONT,
        order: &c::ORDER,
    };

    /// Construct a field element from a plain (non-Montgomery) integer.
    pub fn from_int(limbs: &[u32; N]) -> FeP384 {
        Fe::from_int(&FIELD, limbs)
    }

    /// `k * G` via the compile-time comb table. Much faster than the general
    /// [`crate::Point::mul_scalar`], but only valid for the base point.
    pub fn mul_base(k: &[u32; N]) -> PointP384 {
        crate::Point::mul_base(&CURVE, k, &crate::comb_tables::P384_COMB, COMB_D, COMB_T)
    }

    /// Bits per comb block for this curve.
    pub const COMB_D: usize = crate::comb_tables::P384_COMB_D;

    /// Number of comb tables for this curve.
    pub const COMB_T: usize = crate::comb_tables::P384_COMB_T;

    /// SEC1 public key from a private scalar.
    pub fn derive_public_key(secret: &[u8], out: &mut [u8]) -> Result<(), crate::ecdh::Error> {
        crate::ecdh::derive_public_key::<N>(
            &CURVE,
            secret,
            out,
            &crate::comb_tables::P384_COMB,
            COMB_D,
            COMB_T,
        )
    }

    /// SEC1 public key, yielding every `budget` point operations.
    pub async fn derive_public_key_yielding(
        secret: &[u8],
        out: &mut [u8],
        budget: u32,
    ) -> Result<(), crate::ecdh::Error> {
        crate::ecdh::derive_public_key_yielding::<N>(
            &CURVE,
            secret,
            out,
            &crate::comb_tables::P384_COMB,
            COMB_D,
            COMB_T,
            budget,
        )
        .await
    }
}
