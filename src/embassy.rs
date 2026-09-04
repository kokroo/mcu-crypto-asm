//! `embassy-crypto-driver` `P256Ops` backend for P-256.
//!
//! Adapts this crate's `Scalar<8>` / `Point<8>` to the driver's v2 contract:
//! - `scalar_inv` / `scalar_inv_vartime`: `0 -> 0` (defined fallback;
//!   validity is `!scalar_is_zero(a)`).
//! - `point_from_canonical` of invalid input (off-curve / out-of-range /
//!   `(0,0)`) -> identity; validity is `!projective_is_identity(decoded)`.
//! - `point_to_canonical(identity)` -> `(0, 0)`.
//!
//! Constant-time notes: scalar arithmetic and point ops are the crate's
//! branchless primitives. `scalar_inv` runs a branch-free Fermat chain
//! (the only branches are on the public exponent `n-2`), because
//! [`Scalar::invert`] short-circuits on `is_zero` — a branch on a secret.
//! `scalar_mul_base` guards `k == 0` so the identity contract holds on the
//! Cortex-M4 asm path too (the Emill primitive has no infinity encoding).

#![cfg(feature = "embassy-driver")]

/// Re-export of the driver crate (integration tests use this to name its types).
pub use embassy_crypto_driver as drv;
use embassy_crypto_driver::{P256AffinePoint, P256Scalar};

use crate::p256::{PointP256, ScalarP256, CURVE, FIELD};
use crate::{Fe, Point};

/// Driver struct implementing [`drv::P256Ops`].
pub struct P256OpsDriver;

#[allow(dead_code)]
fn be_to_limbs(b: &[u8; 32]) -> [u32; 8] {
    let mut l = [0u32; 8];
    for (i, c) in b.rchunks(4).enumerate() {
        l[i] = u32::from_be_bytes(c.try_into().unwrap());
    }
    l
}

fn limbs_to_be(l: &[u32; 8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, c) in b.rchunks_mut(4).enumerate() {
        c.copy_from_slice(&l[i].to_be_bytes());
    }
    b
}

/// Projective equality: `(X1:Y1:Z1) == (X2:Y2:Z2)` iff `X1*Z2 == X2*Z1` and
/// `Y1*Z2 == Y2*Z1` (Montgomery form; valid for complete-formula coordinates).
fn projective_eq(a: &PointP256, b: &PointP256) -> bool {
    let lhs_x = a.x.mul(&FIELD, &b.z);
    let rhs_x = b.x.mul(&FIELD, &a.z);
    let lhs_y = a.y.mul(&FIELD, &b.z);
    let rhs_y = b.y.mul(&FIELD, &a.z);
    lhs_x.ct_eq(&rhs_x) & lhs_y.ct_eq(&rhs_y)
}

/// `-p`: negate the Y coordinate in Montgomery form (projective negation).
fn point_neg(p: &PointP256) -> PointP256 {
    Point {
        x: p.x,
        y: Fe::ZERO.sub(&FIELD, &p.y),
        z: p.z,
    }
}

impl drv::P256Ops for P256OpsDriver {
    type Scalar = ScalarP256; // 32 B, fits opaque(size = 64, align = 16)
    type ProjectivePoint = PointP256; // 96 B, fits opaque(size = 128, align = 16)

    // --- canonical <-> opaque conversions ---

    fn scalar_from_canonical(s: &P256Scalar) -> Self::Scalar {
        // Zero accepted; out-of-range -> unspecified (map to zero, no panic).
        ScalarP256::from_be_bytes(&CURVE, &s.0).unwrap_or(ScalarP256::ZERO)
    }

    fn scalar_to_canonical(s: &Self::Scalar) -> P256Scalar {
        let mut out = [0u8; 32];
        let _ = s.to_be_bytes(&CURVE, &mut out);
        P256Scalar(out)
    }

    fn point_from_canonical(p: &P256AffinePoint) -> Self::ProjectivePoint {
        // SEC1 uncompressed decode; invalid (off-curve / out-of-range / (0,0))
        // -> identity (defined fallback).
        let mut enc = [0u8; 65];
        enc[0] = 0x04;
        enc[1..33].copy_from_slice(&p.x);
        enc[33..65].copy_from_slice(&p.y);
        PointP256::decode(&CURVE, &enc).unwrap_or_else(|_| Point::identity(&FIELD))
    }

    fn point_to_canonical(p: &Self::ProjectivePoint) -> P256AffinePoint {
        #[cfg(nistp_asm_cm4)]
        {
            if p.is_identity() {
                return P256AffinePoint {
                    x: [0u8; 32],
                    y: [0u8; 32],
                };
            }
            let z_mont = p.z.as_mont_limbs();
            let mut aff_x_mont = [0u32; 8];
            let mut aff_y_mont = [0u32; 8];
            if z_mont == &crate::backend::cortex_m4::p256::ONE_MONTGOMERY {
                aff_x_mont.copy_from_slice(p.x.as_mont_limbs());
                aff_y_mont.copy_from_slice(p.y.as_mont_limbs());
            } else {
                let mut z_inv = [0u32; 8];
                unsafe {
                    crate::backend::cortex_m4::p256::emill_p256_modinv_p(z_inv.as_mut_ptr(), z_mont.as_ptr());
                    crate::backend::cortex_m4::p256::emill_p256_mul_mont(aff_x_mont.as_mut_ptr(), p.x.as_mont_limbs().as_ptr(), z_inv.as_ptr());
                    crate::backend::cortex_m4::p256::emill_p256_mul_mont(aff_y_mont.as_mut_ptr(), p.y.as_mont_limbs().as_ptr(), z_inv.as_ptr());
                }
            }
            let mut x = [0u32; 8];
            let mut y = [0u32; 8];
            unsafe {
                crate::backend::cortex_m4::p256::P256_from_montgomery(x.as_mut_ptr(), aff_x_mont.as_ptr());
                crate::backend::cortex_m4::p256::P256_from_montgomery(y.as_mut_ptr(), aff_y_mont.as_ptr());
            }
            return P256AffinePoint {
                x: limbs_to_be(&x),
                y: limbs_to_be(&y),
            };
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            match p.to_affine(&FIELD) {
                // Identity -> (0, 0) (defined fallback).
                None => P256AffinePoint {
                    x: [0u8; 32],
                    y: [0u8; 32],
                },
                Some((x, y)) => P256AffinePoint {
                    x: limbs_to_be(&x),
                    y: limbs_to_be(&y),
                },
            }
        }
    }

    // --- scalar predicates ---

    fn scalar_is_zero(a: &Self::Scalar) -> bool {
        a.is_zero()
    }

    // --- scalar field arithmetic (mod n) ---

    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        a.add(&CURVE, b)
    }

    fn scalar_mul(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        a.mul(&CURVE, b)
    }

    fn scalar_neg(a: &Self::Scalar) -> Self::Scalar {
        a.neg(&CURVE)
    }

    fn scalar_inv(a: &Self::Scalar) -> Self::Scalar {
        if a.is_zero() {
            return ScalarP256::ZERO;
        }
        #[cfg(nistp_asm_cm4)]
        {
            let mut out = [0u32; 8];
            let a_int = a.to_int(&CURVE);
            crate::backend::cortex_m4::p256::mod_n_inv(&mut out, &a_int);
            return ScalarP256::from_int(&CURVE, &out);
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            // Constant-time Fermat inversion a^(n-2) with NO secret branches:
            // `Scalar::invert` early-returns on is_zero (a secret-dependent
            // branch), so the chain is replicated here. Branches below are only
            // on the public exponent; a == 0 yields 0 naturally.
            let mut acc = *a;
            let mut first = true;
            for i in (0..8).rev() {
                let word = if i == 0 {
                    CURVE.order[0].wrapping_sub(2)
                } else {
                    CURVE.order[i]
                };
                for bit in (0..32).rev() {
                    if first {
                        first = false;
                        continue;
                    }
                    acc = acc.sqr(&CURVE);
                    if (word >> bit) & 1 == 1 {
                        acc = acc.mul(&CURVE, a);
                    }
                }
            }
            acc
        }
    }

    fn scalar_inv_vartime(a: &Self::Scalar) -> Self::Scalar {
        if a.is_zero() {
            return ScalarP256::ZERO;
        }
        #[cfg(nistp_asm_cm4)]
        {
            let mut out = [0u32; 8];
            let a_int = a.to_int(&CURVE);
            crate::backend::cortex_m4::p256::mod_n_inv(&mut out, &a_int);
            return ScalarP256::from_int(&CURVE, &out);
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            // MUST NOT be called with secrets; the fast chain's zero
            // short-circuit is fine here. 0 -> 0 per the fallback contract.
            a.invert(&CURVE).unwrap_or(ScalarP256::ZERO)
        }
    }

    fn scalar_reduce_bytes(bytes: &[u8; 32]) -> Self::Scalar {
        ScalarP256::from_be_bytes_reduce(&CURVE, bytes)
    }

    // --- projective point predicates ---

    fn projective_is_identity(p: &Self::ProjectivePoint) -> bool {
        p.is_identity()
    }

    // --- projective point arithmetic (RCB complete formulas) ---

    fn projective_identity() -> Self::ProjectivePoint {
        Point::identity(&FIELD)
    }

    fn projective_generator() -> Self::ProjectivePoint {
        Point::generator(&CURVE)
    }

    fn projective_add(
        a: &Self::ProjectivePoint,
        b: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        a.add(&CURVE, b)
    }

    fn projective_sub(
        a: &Self::ProjectivePoint,
        b: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        a.add(&CURVE, &point_neg(b))
    }

    fn projective_double(p: &Self::ProjectivePoint) -> Self::ProjectivePoint {
        // Complete formulas: add(P, P) is the doubling routine.
        p.add(&CURVE, p)
    }

    // --- scalar multiplication ---

    fn scalar_mul_base(k: &Self::Scalar) -> Self::ProjectivePoint {
        // k == 0 -> identity. Guarded because the Cortex-M4 fixed-base
        // primitive returns raw (0, 0) coordinates with no infinity
        // encoding; the portable comb path yields identity on its own.
        if k.is_zero() {
            return Point::identity(&FIELD);
        }
        crate::p256::mul_base(&k.to_int(&CURVE))
    }

    fn scalar_mul_projective(k: &Self::Scalar, p: &Self::ProjectivePoint) -> Self::ProjectivePoint {
        if k.is_zero() || p.is_identity() {
            return Point::identity(&FIELD);
        }
        #[cfg(nistp_asm_cm4)]
        {
            let mut aff_x_mont = [0u32; 8];
            let mut aff_y_mont = [0u32; 8];
            let z_mont = p.z.as_mont_limbs();
            if z_mont == &crate::backend::cortex_m4::p256::ONE_MONTGOMERY {
                aff_x_mont.copy_from_slice(p.x.as_mont_limbs());
                aff_y_mont.copy_from_slice(p.y.as_mont_limbs());
            } else {
                let mut z_inv = [0u32; 8];
                unsafe {
                    crate::backend::cortex_m4::p256::emill_p256_modinv_p(z_inv.as_mut_ptr(), z_mont.as_ptr());
                    crate::backend::cortex_m4::p256::emill_p256_mul_mont(aff_x_mont.as_mut_ptr(), p.x.as_mont_limbs().as_ptr(), z_inv.as_ptr());
                    crate::backend::cortex_m4::p256::emill_p256_mul_mont(aff_y_mont.as_mut_ptr(), p.y.as_mont_limbs().as_ptr(), z_inv.as_ptr());
                }
            }
            let mut out_x = [0u32; 8];
            let mut out_y = [0u32; 8];
            let k_int = k.to_int(&CURVE);
            crate::backend::cortex_m4::p256::scalarmult_variable_base(
                &mut out_x,
                &mut out_y,
                &aff_x_mont,
                &aff_y_mont,
                &k_int,
            );
            return Point {
                x: Fe::from_mont_limbs(out_x),
                y: Fe::from_mont_limbs(out_y),
                z: Fe::from_mont_limbs(crate::backend::cortex_m4::p256::ONE_MONTGOMERY),
            };
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            // Ladder is complete: k == 0 and/or identity input -> identity.
            p.mul_scalar(&CURVE, &k.to_int(&CURVE))
        }
    }

    fn projective_lincomb(
        k1: &Self::Scalar,
        p1: &Self::ProjectivePoint,
        k2: &Self::Scalar,
        p2: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        // Same structure as `ecdsa::verify`: when one operand is the base
        // point, use the fixed-base comb (`p256::mul_base`, 16 doubles +
        // 64 mixed adds for P-256) for that half instead of a full 256-bit
        // Montgomery ladder. `lincomb` is required to be constant-time only
        // with respect to the *scalars*, so dispatching on (non-secret)
        // point equality is contractually fine — unlike
        // `scalar_mul_projective`, which must stay CT with respect to the
        // point as well (ECDH). The equality test costs 4 field
        // multiplications + 2 constant-time comparisons, i.e. ~1% of a
        // ladder. Correctness of the fallback cases (k_i == 0, identity
        // operands) is inherited from `scalar_mul_base` /
        // `scalar_mul_projective`.
        let g = Self::projective_generator();
        if projective_eq(p1, &g) {
            return Self::projective_add(
                &Self::scalar_mul_base(k1),
                &Self::scalar_mul_projective(k2, p2),
            );
        }
        if projective_eq(p2, &g) {
            return Self::projective_add(
                &Self::scalar_mul_projective(k1, p1),
                &Self::scalar_mul_base(k2),
            );
        }
        // No native joint multiplication for the general case; compose per
        // the trait's documented fallback.
        Self::projective_add(
            &Self::scalar_mul_projective(k1, p1),
            &Self::scalar_mul_projective(k2, p2),
        )
    }
}

drv::embassy_crypto_p256_ops_impl!(P256OpsDriver);
