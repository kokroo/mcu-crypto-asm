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

use crate::p256::{PointP256, CURVE, FIELD};
#[cfg(not(nistp_asm_cm4))]
use crate::p256::ScalarP256;
use crate::{Fe, Point};

/// Driver struct implementing [`drv::P256Ops`].
pub struct P256OpsDriver;

/// P-256 scalar represented as 8 little-endian 32-bit limbs in `[0, n-1]`.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256ScalarLimbs(pub [u32; 8]);

impl P256ScalarLimbs {
    pub const ZERO: Self = Self([0; 8]);
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);

    #[inline]
    pub fn is_zero(&self) -> bool {
        let mut acc = 0u32;
        for &w in &self.0 {
            acc |= w;
        }
        acc == 0
    }
}

fn be_to_limbs(b: &[u8; 32]) -> [u32; 8] {
    let mut l = [0u32; 8];
    for (i, c) in b.rchunks_exact(4).enumerate() {
        l[i] = u32::from_be_bytes(c.try_into().unwrap());
    }
    l
}

fn limbs_to_be(l: &[u32; 8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, c) in b.rchunks_exact_mut(4).enumerate() {
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
    type Scalar = P256ScalarLimbs; // 32 B, fits opaque(size = 64, align = 16)
    type ProjectivePoint = PointP256; // 96 B, fits opaque(size = 128, align = 16)

    // --- canonical <-> opaque conversions ---

    fn scalar_from_canonical(s: &P256Scalar) -> Self::Scalar {
        let limbs = be_to_limbs(&s.0);
        #[cfg(nistp_asm_cm4)]
        {
            let is_zero = {
                let mut acc = 0u32;
                for &w in &limbs {
                    acc |= w;
                }
                acc == 0
            };
            if is_zero {
                return P256ScalarLimbs::ZERO;
            }
            let valid = unsafe { crate::backend::cortex_m4::p256::P256_check_range_n(limbs.as_ptr()) };
            if valid != 0 {
                P256ScalarLimbs(limbs)
            } else {
                P256ScalarLimbs::ZERO
            }
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            if let Ok(sc) = ScalarP256::from_be_bytes(&CURVE, &s.0) {
                P256ScalarLimbs(sc.to_int(&CURVE))
            } else {
                P256ScalarLimbs::ZERO
            }
        }
    }

    fn scalar_to_canonical(s: &Self::Scalar) -> P256Scalar {
        P256Scalar(limbs_to_be(&s.0))
    }

    fn point_from_canonical(p: &P256AffinePoint) -> Self::ProjectivePoint {
        #[cfg(nistp_asm_cm4)]
        {
            let x = be_to_limbs(&p.x);
            let y = be_to_limbs(&p.y);
            unsafe {
                if crate::backend::cortex_m4::p256::P256_check_range_p(x.as_ptr()) == 0
                    || crate::backend::cortex_m4::p256::P256_check_range_p(y.as_ptr()) == 0
                {
                    return Point::identity(&FIELD);
                }
                let mut x_mont = [0u32; 8];
                let mut y_mont = [0u32; 8];
                crate::backend::cortex_m4::p256::P256_to_montgomery(x_mont.as_mut_ptr(), x.as_ptr());
                crate::backend::cortex_m4::p256::P256_to_montgomery(y_mont.as_mut_ptr(), y.as_ptr());
                if crate::backend::cortex_m4::p256::P256_point_is_on_curve(x_mont.as_ptr(), y_mont.as_ptr()) == 0 {
                    return Point::identity(&FIELD);
                }
                Point {
                    x: Fe::from_mont_limbs(x_mont),
                    y: Fe::from_mont_limbs(y_mont),
                    z: Fe::from_mont_limbs(crate::backend::cortex_m4::p256::ONE_MONTGOMERY),
                }
            }
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            let mut enc = [0u8; 65];
            enc[0] = 0x04;
            enc[1..33].copy_from_slice(&p.x);
            enc[33..65].copy_from_slice(&p.y);
            PointP256::decode(&CURVE, &enc).unwrap_or_else(|_| Point::identity(&FIELD))
        }
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
        #[cfg(nistp_asm_cm4)]
        {
            let mut out = [0u32; 8];
            unsafe {
                crate::backend::cortex_m4::p256::P256_add_mod_n(out.as_mut_ptr(), a.0.as_ptr(), b.0.as_ptr());
            }
            P256ScalarLimbs(out)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            let sa = ScalarP256::from_int(&CURVE, &a.0);
            let sb = ScalarP256::from_int(&CURVE, &b.0);
            P256ScalarLimbs(sa.add(&CURVE, &sb).to_int(&CURVE))
        }
    }

    fn scalar_mul(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        #[cfg(nistp_asm_cm4)]
        {
            let mut out = [0u32; 8];
            unsafe {
                crate::backend::cortex_m4::p256::P256_mul_mod_n(out.as_mut_ptr(), a.0.as_ptr(), b.0.as_ptr());
            }
            P256ScalarLimbs(out)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            let sa = ScalarP256::from_int(&CURVE, &a.0);
            let sb = ScalarP256::from_int(&CURVE, &b.0);
            P256ScalarLimbs(sa.mul(&CURVE, &sb).to_int(&CURVE))
        }
    }

    fn scalar_neg(a: &Self::Scalar) -> Self::Scalar {
        #[cfg(nistp_asm_cm4)]
        {
            if a.is_zero() {
                return P256ScalarLimbs::ZERO;
            }
            let mut out = [0u32; 8];
            unsafe {
                crate::backend::cortex_m4::p256::P256_negate_mod_n_if(out.as_mut_ptr(), a.0.as_ptr(), 1);
            }
            P256ScalarLimbs(out)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            let sa = ScalarP256::from_int(&CURVE, &a.0);
            P256ScalarLimbs(sa.neg(&CURVE).to_int(&CURVE))
        }
    }

    fn scalar_inv(a: &Self::Scalar) -> Self::Scalar {
        if a.is_zero() {
            return P256ScalarLimbs::ZERO;
        }
        #[cfg(nistp_asm_cm4)]
        {
            let mut out = [0u32; 8];
            crate::backend::cortex_m4::p256::mod_n_inv(&mut out, &a.0);
            P256ScalarLimbs(out)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            let sa = ScalarP256::from_int(&CURVE, &a.0);
            let mut acc = sa;
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
                        acc = acc.mul(&CURVE, &sa);
                    }
                }
            }
            P256ScalarLimbs(acc.to_int(&CURVE))
        }
    }

    fn scalar_inv_vartime(a: &Self::Scalar) -> Self::Scalar {
        if a.is_zero() {
            return P256ScalarLimbs::ZERO;
        }
        #[cfg(nistp_asm_cm4)]
        {
            let mut out = [0u32; 8];
            unsafe {
                crate::backend::cortex_m4::p256::P256_mod_n_inv_vartime(out.as_mut_ptr(), a.0.as_ptr());
            }
            P256ScalarLimbs(out)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            let sa = ScalarP256::from_int(&CURVE, &a.0);
            match sa.invert(&CURVE) {
                Some(inv) => P256ScalarLimbs(inv.to_int(&CURVE)),
                None => P256ScalarLimbs::ZERO,
            }
        }
    }

    fn scalar_reduce_bytes(bytes: &[u8; 32]) -> Self::Scalar {
        #[cfg(nistp_asm_cm4)]
        {
            let limbs = be_to_limbs(bytes);
            let mut out = [0u32; 8];
            unsafe {
                crate::backend::cortex_m4::p256::P256_reduce_mod_n_32bytes(
                    out.as_mut_ptr(),
                    limbs.as_ptr(),
                );
            }
            P256ScalarLimbs(out)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            let s = ScalarP256::from_be_bytes_reduce(&CURVE, bytes);
            P256ScalarLimbs(s.to_int(&CURVE))
        }
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
        p.add(&CURVE, p)
    }

    // --- scalar multiplication ---

    fn scalar_mul_base(k: &Self::Scalar) -> Self::ProjectivePoint {
        if k.is_zero() {
            return Point::identity(&FIELD);
        }
        crate::p256::mul_base(&k.0)
    }

    fn scalar_mul_projective(k: &Self::Scalar, p: &Self::ProjectivePoint) -> Self::ProjectivePoint {
        if k.is_zero() || p.is_identity() {
            return Point::identity(&FIELD);
        }
        #[cfg(nistp_asm_cm4)]
        {
            let mut in_j = [[0u32; 8]; 3];
            crate::backend::cortex_m4::p256::homogeneous_to_jacobian(
                &mut in_j,
                p.x.as_mont_limbs(),
                p.y.as_mont_limbs(),
                p.z.as_mont_limbs(),
            );
            let mut out_j = [[0u32; 8]; 3];
            crate::backend::cortex_m4::p256::scalarmult_variable_base_jacobian(
                &mut out_j,
                &in_j,
                &k.0,
            );
            let mut out_x = [0u32; 8];
            let mut out_y = [0u32; 8];
            let mut out_z = [0u32; 8];
            crate::backend::cortex_m4::p256::jacobian_to_homogeneous(
                &mut out_x,
                &mut out_y,
                &mut out_z,
                &out_j,
            );
            Point {
                x: Fe::from_mont_limbs(out_x),
                y: Fe::from_mont_limbs(out_y),
                z: Fe::from_mont_limbs(out_z),
            }
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            p.mul_scalar(&CURVE, &k.0)
        }
    }

    fn projective_lincomb(
        k1: &Self::Scalar,
        p1: &Self::ProjectivePoint,
        k2: &Self::Scalar,
        p2: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        let p1_id = p1.is_identity();
        let p2_id = p2.is_identity();
        if p1_id && p2_id {
            return Point::identity(&FIELD);
        }
        if p1_id {
            return Self::scalar_mul_projective(k2, p2);
        }
        if p2_id {
            return Self::scalar_mul_projective(k1, p1);
        }
        if k1.is_zero() && k2.is_zero() {
            return Point::identity(&FIELD);
        }
        if k1.is_zero() {
            return Self::scalar_mul_projective(k2, p2);
        }
        if k2.is_zero() {
            return Self::scalar_mul_projective(k1, p1);
        }

        #[cfg(nistp_asm_cm4)]
        {
            let g = Self::projective_generator();
            let p1_is_g = projective_eq(p1, &g);
            let p2_is_g = projective_eq(p2, &g);

            let mut p1_j = [[0u32; 8]; 3];
            let mut p2_j = [[0u32; 8]; 3];

            if !p1_is_g {
                crate::backend::cortex_m4::p256::homogeneous_to_jacobian(
                    &mut p1_j,
                    p1.x.as_mont_limbs(),
                    p1.y.as_mont_limbs(),
                    p1.z.as_mont_limbs(),
                );
            }
            if !p2_is_g {
                crate::backend::cortex_m4::p256::homogeneous_to_jacobian(
                    &mut p2_j,
                    p2.x.as_mont_limbs(),
                    p2.y.as_mont_limbs(),
                    p2.z.as_mont_limbs(),
                );
            }

            let mut out_j = [[0u32; 8]; 3];
            crate::backend::cortex_m4::p256::lincomb_jacobian(
                &mut out_j,
                &k1.0,
                &p1_j,
                p1_is_g,
                &k2.0,
                &p2_j,
                p2_is_g,
            );

            let mut out_x = [0u32; 8];
            let mut out_y = [0u32; 8];
            let mut out_z = [0u32; 8];
            crate::backend::cortex_m4::p256::jacobian_to_homogeneous(
                &mut out_x,
                &mut out_y,
                &mut out_z,
                &out_j,
            );
            Point {
                x: Fe::from_mont_limbs(out_x),
                y: Fe::from_mont_limbs(out_y),
                z: Fe::from_mont_limbs(out_z),
            }
        }
        #[cfg(not(nistp_asm_cm4))]
        {
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
            Self::projective_add(
                &Self::scalar_mul_projective(k1, p1),
                &Self::scalar_mul_projective(k2, p2),
            )
        }
    }
}

drv::embassy_crypto_p256_ops_impl!(P256OpsDriver);

