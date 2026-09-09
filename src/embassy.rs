//! `embassy-crypto-driver` elliptic-curve backend for P-256 and P-384.

use drv::{P256Point, P256Scalar, P256Signature, P384Point, P384Scalar};
use embassy_crypto as reg;
/// Re-export of the driver crate (integration tests use this to name its types).
use embassy_crypto::driver as drv;

use crate::p256::{PointP256, ScalarP256, CURVE as P256_CURVE, FIELD as P256_FIELD};
use crate::p384::{PointP384, ScalarP384, CURVE as P384_CURVE, FIELD as P384_FIELD};
use crate::{Params, Point, Scalar};

/// Driver implementation registered with `embassy-crypto-driver`.
pub struct McuCryptoAsmDriver;

// ---------------------------------------------------------------------------
// Canonical conversions
// ---------------------------------------------------------------------------

fn p256_scalar_from_canonical(k: &P256Scalar) -> Option<ScalarP256> {
    Scalar::from_be_bytes(&P256_CURVE, &k.0).ok()
}

#[allow(dead_code)]
fn p256_scalar_to_canonical(k: &ScalarP256) -> P256Scalar {
    let mut out = P256Scalar([0u8; 32]);
    let _ = k.to_be_bytes(&P256_CURVE, &mut out.0);
    out
}

#[allow(dead_code)]
fn p384_scalar_from_canonical(k: &P384Scalar) -> Option<ScalarP384> {
    Scalar::from_be_bytes(&P384_CURVE, &k.0).ok()
}

#[allow(dead_code)]
fn p384_scalar_to_canonical(k: &ScalarP384) -> P384Scalar {
    let mut out = P384Scalar([0u8; 48]);
    let _ = k.to_be_bytes(&P384_CURVE, &mut out.0);
    out
}

#[allow(dead_code)]
fn p256_point_from_canonical(p: &P256Point) -> Option<PointP256> {
    let mut enc = [0u8; 65];
    enc[0] = 0x04;
    enc[1..33].copy_from_slice(&p.x);
    enc[33..65].copy_from_slice(&p.y);
    PointP256::decode(&P256_CURVE, &enc).ok()
}

#[allow(dead_code)]
fn p256_point_to_canonical(p: &PointP256) -> Option<P256Point> {
    match p.to_affine(&P256_FIELD) {
        Some((x, y)) => Some(P256Point {
            x: limbs_to_be_256(&x),
            y: limbs_to_be_256(&y),
        }),
        None => None,
    }
}

#[allow(dead_code)]
fn p256_point_to_canonical_opt(p: &PointP256) -> Option<P256Point> {
    if p.is_identity() {
        None
    } else {
        p256_point_to_canonical(p)
    }
}

#[allow(dead_code)]
fn p384_point_from_canonical(p: &P384Point) -> Option<PointP384> {
    let mut enc = [0u8; 97];
    enc[0] = 0x04;
    enc[1..49].copy_from_slice(&p.x);
    enc[49..97].copy_from_slice(&p.y);
    PointP384::decode(&P384_CURVE, &enc).ok()
}

#[allow(dead_code)]
fn p384_point_to_canonical(p: &PointP384) -> P384Point {
    match p.to_affine(&P384_FIELD) {
        Some((x, y)) => P384Point {
            x: limbs_to_be_384(&x),
            y: limbs_to_be_384(&y),
        },
        None => P384Point {
            x: [0u8; 48],
            y: [0u8; 48],
        },
    }
}

#[allow(dead_code)]
fn p384_point_to_canonical_opt(p: &PointP384) -> Option<P384Point> {
    if p.is_identity() {
        None
    } else {
        Some(p384_point_to_canonical(p))
    }
}

#[inline]
#[allow(dead_code)]
fn be_to_limbs_256(b: &[u8; 32], out: &mut [u32; 8]) {
    for (i, chunk) in b.rchunks_exact(4).enumerate() {
        out[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
}

#[inline]
fn limbs_to_be_256(limbs: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in out.rchunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
}

#[inline]
fn limbs_to_be_384(limbs: &[u32; 12]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (i, chunk) in out.rchunks_exact_mut(4).enumerate() {
        chunk.copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
}

/// Projective equality: `(X1:Y1:Z1) == (X2:Y2:Z2)` iff `X1*Z2 == X2*Z1` and
/// `Y1*Z2 == Y2*Z1` (Montgomery form; valid for complete-formula coordinates).
#[allow(dead_code)]
fn projective_eq<const N: usize>(a: &Point<N>, b: &Point<N>, field: &Params) -> bool {
    let lhs_x = a.x.mul(field, &b.z);
    let rhs_x = b.x.mul(field, &a.z);
    let lhs_y = a.y.mul(field, &b.z);
    let rhs_y = b.y.mul(field, &a.z);
    lhs_x.ct_eq(&rhs_x) & lhs_y.ct_eq(&rhs_y)
}

#[cfg(nistp_asm_cm4)]
#[allow(dead_code)]
const P256_GENERATOR_AFFINE: P256Point = P256Point {
    x: [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ],
    y: [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ],
};

#[cfg(nistp_asm_cm4)]
#[allow(dead_code)]
fn jacobian_to_canonical_affine(out_j: &[[u32; 8]; 3]) -> Option<P256Point> {
    let mut is_zero = true;
    for &w in &out_j[2] {
        if w != 0 {
            is_zero = false;
            break;
        }
    }
    if is_zero {
        return None;
    }

    let mut aff_mont_x = [0u32; 8];
    let mut aff_mont_y = [0u32; 8];
    unsafe {
        crate::backend::cortex_m4::p256::P256_jacobian_to_affine(
            aff_mont_x.as_mut_ptr(),
            aff_mont_y.as_mut_ptr(),
            out_j.as_ptr() as *const u32,
        );
        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        crate::backend::cortex_m4::p256::P256_from_montgomery(x.as_mut_ptr(), aff_mont_x.as_ptr());
        crate::backend::cortex_m4::p256::P256_from_montgomery(y.as_mut_ptr(), aff_mont_y.as_ptr());
        Some(P256Point {
            x: limbs_to_be_256(&x),
            y: limbs_to_be_256(&y),
        })
    }
}

#[cfg(nistp_asm_cm4)]
#[allow(dead_code)]
fn affine_to_jacobian(p: &P256Point) -> Option<[[u32; 8]; 3]> {
    let mut px = [0u32; 8];
    let mut py = [0u32; 8];
    be_to_limbs_256(&p.x, &mut px);
    be_to_limbs_256(&p.y, &mut py);
    unsafe {
        if crate::backend::cortex_m4::p256::P256_check_range_p(px.as_ptr()) == 0
            || crate::backend::cortex_m4::p256::P256_check_range_p(py.as_ptr()) == 0
        {
            return None;
        }
        let mut px_mont = [0u32; 8];
        let mut py_mont = [0u32; 8];
        crate::backend::cortex_m4::p256::P256_to_montgomery(px_mont.as_mut_ptr(), px.as_ptr());
        crate::backend::cortex_m4::p256::P256_to_montgomery(py_mont.as_mut_ptr(), py.as_ptr());
        if crate::backend::cortex_m4::p256::P256_point_is_on_curve(
            px_mont.as_ptr(),
            py_mont.as_ptr(),
        ) == 0
        {
            return None;
        }
        Some([
            px_mont,
            py_mont,
            crate::backend::cortex_m4::p256::ONE_MONTGOMERY,
        ])
    }
}

// ---------------------------------------------------------------------------
// Small constant-time helpers used by signing
// ---------------------------------------------------------------------------

/// Return `a < b` for little-endian unsigned limbs, without data-dependent branches.
fn less_than<const N: usize>(a: &[u32; N], b: &[u32]) -> bool {
    let mut borrow = 0u32;
    for i in 0..N {
        let (r1, b1) = a[i].overflowing_sub(b[i]);
        let (_, b2) = r1.overflowing_sub(borrow);
        borrow = (b1 as u32) | (b2 as u32);
    }
    borrow == 1
}

/// Floor(`order` / 2), as little-endian limbs.
fn half_order<const N: usize>(order: &[u32]) -> [u32; N] {
    debug_assert_eq!(order.len(), N);
    let mut half = [0u32; N];
    let mut carry = 0u32;
    for i in (0..N).rev() {
        half[i] = (order[i] >> 1) | carry;
        carry = order[i] << 31;
    }
    half
}

/// Best-effort wipe of temporary scalar encodings.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(&mut *buf);
}

/// Normalize an ECDSA `s` value to low-S without branching on the secret value.
fn p256_low_s(s: &[u8; 32]) -> Result<[u8; 32], drv::Error> {
    let scalar =
        ScalarP256::from_be_bytes_nonzero(&P256_CURVE, s).map_err(|_| drv::Error::InvalidInput)?;
    let negated = scalar.neg(&P256_CURVE);
    let scalar_limbs = scalar.to_int(&P256_CURVE);
    let half = half_order::<8>(P256_CURVE.order);
    let mask = core::hint::black_box(0u32.wrapping_sub(less_than(&half, &scalar_limbs) as u32));

    let mut out = scalar;
    for i in 0..8 {
        out.v[i] = scalar.v[i] ^ ((scalar.v[i] ^ negated.v[i]) & mask);
    }

    let mut bytes = [0u8; 32];
    let _ = out.to_be_bytes(&P256_CURVE, &mut bytes);
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// P-256 scalar multiplication
// ---------------------------------------------------------------------------

impl McuCryptoAsmDriver {
    fn p256_mul_base(k: &P256Scalar) -> Result<P256Point, drv::Error> {
        let k_sc = p256_scalar_from_canonical(k).unwrap_or(ScalarP256::ZERO);
        if k_sc.is_zero() {
            return Err(drv::Error::InvalidInput);
        }
        #[cfg(nistp_asm_cm4)]
        {
            let mut aff_mont_x = [0u32; 8];
            let mut aff_mont_y = [0u32; 8];
            crate::backend::cortex_m4::p256::scalarmult_fixed_base(
                &mut aff_mont_x,
                &mut aff_mont_y,
                &k_sc.to_int(&P256_CURVE),
            );
            let mut x = [0u32; 8];
            let mut y = [0u32; 8];
            unsafe {
                crate::backend::cortex_m4::p256::P256_from_montgomery(
                    x.as_mut_ptr(),
                    aff_mont_x.as_ptr(),
                );
                crate::backend::cortex_m4::p256::P256_from_montgomery(
                    y.as_mut_ptr(),
                    aff_mont_y.as_ptr(),
                );
            }
            Ok(P256Point {
                x: limbs_to_be_256(&x),
                y: limbs_to_be_256(&y),
            })
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            p256_point_to_canonical(&crate::p256::mul_base(&k_sc.to_int(&P256_CURVE)))
                .ok_or(drv::Error::InvalidInput)
        }
    }

    #[allow(dead_code)]
    fn p256_mul_affine(k: P256Scalar, p: P256Point) -> Result<P256Point, drv::Error> {
        let k_sc = p256_scalar_from_canonical(&k).unwrap_or(ScalarP256::ZERO);
        if k_sc.is_zero() {
            return Err(drv::Error::InvalidInput);
        }
        #[cfg(nistp_asm_cm4)]
        {
            let in_j = match affine_to_jacobian(&p) {
                Some(j) => j,
                None => return Err(drv::Error::InvalidInput),
            };
            let mut out_j = [[0u32; 8]; 3];
            crate::backend::cortex_m4::p256::scalarmult_variable_base_jacobian(
                &mut out_j,
                &in_j,
                &k_sc.to_int(&P256_CURVE),
            );
            jacobian_to_canonical_affine(&out_j).ok_or(drv::Error::InvalidInput)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            let pt = p256_point_from_canonical(&p).unwrap_or_else(|| Point::identity(&P256_FIELD));
            if pt.is_identity() {
                return Err(drv::Error::InvalidInput);
            }
            p256_point_to_canonical(&pt.mul_scalar(&P256_CURVE, &k_sc.to_int(&P256_CURVE)))
                .ok_or(drv::Error::InvalidInput)
        }
    }
}
//
// drv::p256_scalar_mul_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// P-384 scalar multiplication
// ---------------------------------------------------------------------------

// impl drv::P384ScalarMul for McuCryptoAsmDriver {
//     fn mul_base(k: P384Scalar) -> P384AffinePoint {
//         let k = p384_scalar_from_canonical(&k).unwrap_or(ScalarP384::ZERO);
//         if k.is_zero() {
//             return P384AffinePoint {
//                 x: [0u8; 48],
//                 y: [0u8; 48],
//             };
//         }
//         p384_point_to_canonical(&crate::p384::mul_base(&k.to_int(&P384_CURVE)))
//     }
//
//     fn mul_affine(k: P384Scalar, p: P384AffinePoint) -> P384AffinePoint {
//         let k = p384_scalar_from_canonical(&k).unwrap_or(ScalarP384::ZERO);
//         let p = p384_point_from_canonical(&p).unwrap_or_else(|| Point::identity(&P384_FIELD));
//         if k.is_zero() || p.is_identity() {
//             return P384AffinePoint {
//                 x: [0u8; 48],
//                 y: [0u8; 48],
//             };
//         }
//         p384_point_to_canonical(&p.mul_scalar(&P384_CURVE, &k.to_int(&P384_CURVE)))
//     }
// }
//
// drv::p384_scalar_mul_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// Scalar inversion
// ---------------------------------------------------------------------------

// impl drv::P256ScalarInvert for McuCryptoAsmDriver {
//     fn invert(k: P256Scalar) -> P256Scalar {
//         let k_sc = p256_scalar_from_canonical(&k).unwrap_or(ScalarP256::ZERO);
//         if k_sc.is_zero() {
//             return P256Scalar([0u8; 32]);
//         }
//         #[cfg(nistp_asm_cm4)]
//         {
//             let mut out = [0u32; 8];
//             crate::backend::cortex_m4::p256::mod_n_inv(&mut out, &k_sc.to_int(&P256_CURVE));
//             P256Scalar(limbs_to_be_256(&out))
//         }
//         #[cfg(not(nistp_asm_cm4))]
//         {
//             p256_scalar_to_canonical(&k_sc.invert(&P256_CURVE).unwrap_or(ScalarP256::ZERO))
//         }
//     }
//
//     fn invert_vartime(k: P256Scalar) -> P256Scalar {
//         let k_sc = p256_scalar_from_canonical(&k).unwrap_or(ScalarP256::ZERO);
//         if k_sc.is_zero() {
//             return P256Scalar([0u8; 32]);
//         }
//         #[cfg(nistp_asm_cm4)]
//         {
//             let mut out = [0u32; 8];
//             let limbs = k_sc.to_int(&P256_CURVE);
//             unsafe {
//                 crate::backend::cortex_m4::p256::P256_mod_n_inv_vartime(
//                     out.as_mut_ptr(),
//                     limbs.as_ptr(),
//                 );
//             }
//             P256Scalar(limbs_to_be_256(&out))
//         }
//         #[cfg(not(nistp_asm_cm4))]
//         {
//             Self::invert(k)
//         }
//     }
// }
//
// drv::p256_scalar_invert_impl!(McuCryptoAsmDriver);
//
// impl drv::P384ScalarInvert for McuCryptoAsmDriver {
//     fn invert(k: P384Scalar) -> P384Scalar {
//         let k = p384_scalar_from_canonical(&k).unwrap_or(ScalarP384::ZERO);
//         p384_scalar_to_canonical(&k.invert(&P384_CURVE).unwrap_or(ScalarP384::ZERO))
//     }
//
//     fn invert_vartime(k: P384Scalar) -> P384Scalar {
//         Self::invert(k)
//     }
// }
//
// drv::p384_scalar_invert_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// Double-base linear combinations
// ---------------------------------------------------------------------------

// impl drv::P256Lincomb for McuCryptoAsmDriver {
//     fn lincomb(k1: P256Scalar, p1: P256Point, k2: P256Scalar, p2: P256Point) -> Option<P256Point> {
//         let k1_sc = p256_scalar_from_canonical(&k1).unwrap_or(ScalarP256::ZERO);
//         let k2_sc = p256_scalar_from_canonical(&k2).unwrap_or(ScalarP256::ZERO);
//         let k1_zero = k1_sc.is_zero();
//         let k2_zero = k2_sc.is_zero();
//         if k1_zero && k2_zero {
//             return None;
//         }
//         if k1_zero {
//             let r = <Self as P256ScalarMul>::mul_affine(k2, p2);
//             return if r == P256Point::default() {
//                 None
//             } else {
//                 Some(r)
//             };
//         }
//         if k2_zero {
//             let r = <Self as P256ScalarMul>::mul_affine(k1, p1);
//             return if r == P256Point::default() {
//                 None
//             } else {
//                 Some(r)
//             };
//         }
//
//         #[cfg(nistp_asm_cm4)]
//         {
//             let p1_is_g = p1 == P256_GENERATOR_AFFINE;
//             let p2_is_g = p2 == P256_GENERATOR_AFFINE;
//
//             let mut p1_j = [[0u32; 8]; 3];
//             let mut p2_j = [[0u32; 8]; 3];
//
//             if !p1_is_g {
//                 p1_j = affine_to_jacobian(&p1)?;
//             }
//             if !p2_is_g {
//                 p2_j = affine_to_jacobian(&p2)?;
//             }
//
//             let mut out_j = [[0u32; 8]; 3];
//             crate::backend::cortex_m4::p256::lincomb_jacobian(
//                 &mut out_j,
//                 &k1_sc.to_int(&P256_CURVE),
//                 &p1_j,
//                 p1_is_g,
//                 &k2_sc.to_int(&P256_CURVE),
//                 &p2_j,
//                 p2_is_g,
//             );
//
//             let aff = jacobian_to_canonical_affine(&out_j);
//             if aff == P256Point::default() {
//                 None
//             } else {
//                 Some(aff)
//             }
//         }
//         #[cfg(not(nistp_asm_cm4))]
//         {
//             let p1 = p256_point_from_canonical(&p1).unwrap_or_else(|| Point::identity(&P256_FIELD));
//             let p2 = p256_point_from_canonical(&p2).unwrap_or_else(|| Point::identity(&P256_FIELD));
//
//             let result = Point::lincomb(
//                 &P256_CURVE,
//                 &k1_sc.to_int(&P256_CURVE),
//                 &p1,
//                 &k2_sc.to_int(&P256_CURVE),
//                 &p2,
//             );
//
//             p256_point_to_canonical_opt(&result)
//         }
//     }
// }
//
// drv::p256_lincomb_impl!(McuCryptoAsmDriver);
//
// impl drv::P384Lincomb for McuCryptoAsmDriver {
//     fn lincomb(
//         k1: P384Scalar,
//         p1: P384AffinePoint,
//         k2: P384Scalar,
//         p2: P384AffinePoint,
//     ) -> Option<P384AffinePoint> {
//         let k1 = p384_scalar_from_canonical(&k1).unwrap_or(ScalarP384::ZERO);
//         let k2 = p384_scalar_from_canonical(&k2).unwrap_or(ScalarP384::ZERO);
//         let p1 = p384_point_from_canonical(&p1).unwrap_or_else(|| Point::identity(&P384_FIELD));
//         let p2 = p384_point_from_canonical(&p2).unwrap_or_else(|| Point::identity(&P384_FIELD));
//
//         let result = Point::lincomb(
//             &P384_CURVE,
//             &k1.to_int(&P384_CURVE),
//             &p1,
//             &k2.to_int(&P384_CURVE),
//             &p2,
//         );
//
//         p384_point_to_canonical_opt(&result)
//     }
// }
//
// drv::p384_lincomb_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// High-level P-256 operations
// ---------------------------------------------------------------------------

impl drv::P256Ecdh for McuCryptoAsmDriver {
    fn public_key(k: &P256Scalar) -> Result<P256Point, drv::Error> {
        if ScalarP256::from_be_bytes_nonzero(&P256_CURVE, &k.0).is_err() {
            return Err(drv::Error::InvalidKey);
        }

        Self::p256_mul_base(k)
    }

    fn shared_secret(k: &P256Scalar, peer: &P256Point) -> Result<[u8; 32], drv::Error> {
        if ScalarP256::from_be_bytes_nonzero(&P256_CURVE, &k.0).is_err() {
            return Err(drv::Error::InvalidKey);
        }

        let mut peer_enc = [0u8; 65];
        peer_enc[0] = 0x04;
        peer_enc[1..33].copy_from_slice(&peer.x);
        peer_enc[33..65].copy_from_slice(&peer.y);

        let mut out = [0u8; 32];
        let result = crate::p256::ecdh::shared_secret(&k.0, &peer_enc, &mut out);

        result.map_err(|e| match e {
            crate::ecdh::Error::BadScalar => drv::Error::InvalidKey,
            crate::ecdh::Error::BadPoint | crate::ecdh::Error::BadLength => {
                drv::Error::InvalidInput
            }
        })?;
        Ok(out)
    }
}

reg::p256_ecdh_impl!(McuCryptoAsmDriver);

impl drv::P256Ecdsa for McuCryptoAsmDriver {
    fn public_key(k: &P256Scalar) -> Result<P256Point, drv::Error> {
        if ScalarP256::from_be_bytes_nonzero(&P256_CURVE, &k.0).is_err() {
            return Err(drv::Error::InvalidKey);
        }

        Self::p256_mul_base(k)
    }

    fn sign(k: &P256Scalar, digest: &[u8; 32]) -> Result<P256Signature, drv::Error> {
        if ScalarP256::from_be_bytes_nonzero(&P256_CURVE, &k.0).is_err() {
            return Err(drv::Error::InvalidKey);
        }

        let mut nonce = [0u8; 32];
        drv::RngImpl::fill_bytes(&mut nonce)?;

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        let result = crate::p256::ecdsa::sign(&k.0, digest, &nonce, &mut r, &mut s);
        wipe(&mut nonce);
        result.map_err(|_| drv::Error::InvalidInput)?;

        s = p256_low_s(&s)?;
        Ok(P256Signature {
            r: P256Scalar(r),
            s: P256Scalar(s),
        })
    }

    fn verify(q: &P256Point, digest: &[u8; 32], sig: &P256Signature) -> Result<(), drv::Error> {
        let mut q_enc = [0u8; 65];
        q_enc[0] = 0x04;
        q_enc[1..33].copy_from_slice(&q.x);
        q_enc[33..65].copy_from_slice(&q.y);

        crate::p256::ecdsa::verify(&q_enc, digest, &sig.r.0, &sig.s.0).map_err(|e| match e {
            crate::ecdsa::Error::BadSignature => drv::Error::InvalidSignature,
            crate::ecdsa::Error::BadScalar => drv::Error::InvalidSignature,
            crate::ecdsa::Error::BadPoint | crate::ecdsa::Error::BadLength => {
                drv::Error::InvalidInput
            }
        })
    }
}

reg::p256_ecdsa_impl!(McuCryptoAsmDriver);
