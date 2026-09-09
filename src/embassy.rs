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

// ---------------------------------------------------------------------------
// AES driver support
// ---------------------------------------------------------------------------
//
// All AES modes here are built on the crate's fixsliced AES core, which is
// encryption-only (Adomnicai's CHES 2020 fixslicing defines no inverse
// transforms). That covers every `embassy-crypto-driver` AES trait except
// ECB and CBC, whose `decrypt_blocks` requires the raw inverse cipher. Those
// two traits are intentionally not registered; firmware that needs them
// should fall back to `embassy-crypto`'s software AES for those modes.
//
// Mode implementations follow NIST SP 800-38A (CTR), SP 800-38B (CMAC),
// SP 800-38C / RFC 3610 (CCM) and SP 800-38D (GCM).

use crate::aes::{Aes128, Aes256};
use crate::ghash::{Ghash, Htable};

/// Facade over the two fixsliced AES cores so the mode helpers below are
/// generic over the key size.
trait AesEncrypt {
    fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]);
    fn encrypt_two_blocks(
        &self,
        p0: &[u8; 16],
        p1: &[u8; 16],
        c0: &mut [u8; 16],
        c1: &mut [u8; 16],
    );
}

impl AesEncrypt for Aes128 {
    #[inline]
    fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]) {
        Aes128::encrypt_block(self, ptext, ctext);
    }
    #[inline]
    fn encrypt_two_blocks(
        &self,
        p0: &[u8; 16],
        p1: &[u8; 16],
        c0: &mut [u8; 16],
        c1: &mut [u8; 16],
    ) {
        Aes128::encrypt_two_blocks(self, p0, p1, c0, c1);
    }
}

impl AesEncrypt for Aes256 {
    #[inline]
    fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]) {
        Aes256::encrypt_block(self, ptext, ctext);
    }
    #[inline]
    fn encrypt_two_blocks(
        &self,
        p0: &[u8; 16],
        p1: &[u8; 16],
        c0: &mut [u8; 16],
        c1: &mut [u8; 16],
    ) {
        Aes256::encrypt_two_blocks(self, p0, p1, c0, c1);
    }
}

#[inline]
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// Increment the rightmost 32 bits of the counter block (GCM, SP 800-38D).
#[inline]
fn inc32(blk: &mut [u8; 16]) {
    let c = u32::from_be_bytes(blk[12..16].try_into().unwrap()).wrapping_add(1);
    blk[12..16].copy_from_slice(&c.to_be_bytes());
}

/// Increment the full 128-bit big-endian counter (CTR, SP 800-38A).
#[inline]
fn inc128(blk: &mut [u8; 16]) {
    for i in (0..16).rev() {
        let (v, carry) = blk[i].overflowing_add(1);
        blk[i] = v;
        if !carry {
            break;
        }
    }
}

/// XOR `data` with the keystream `E(counter)`, `E(inc(counter))`, ... in
/// place, processing two blocks per call where possible.
fn ctr_apply<E: AesEncrypt>(
    aes: &E,
    counter: &mut [u8; 16],
    inc: fn(&mut [u8; 16]),
    data: &mut [u8],
) {
    let mut chunks = data.chunks_exact_mut(32);
    for pair in &mut chunks {
        let (l, r) = pair.split_at_mut(16);
        let c0: &mut [u8; 16] = l.try_into().unwrap();
        let c1: &mut [u8; 16] = r.try_into().unwrap();
        let (m0, m1) = (*c0, *c1);
        let mut k0 = [0u8; 16];
        let mut k1 = [0u8; 16];
        let b0 = *counter;
        inc(counter);
        let b1 = *counter;
        inc(counter);
        aes.encrypt_two_blocks(&b0, &b1, &mut k0, &mut k1);
        for i in 0..16 {
            c0[i] = m0[i] ^ k0[i];
            c1[i] = m1[i] ^ k1[i];
        }
    }
    let rem = chunks.into_remainder();
    let mut chunks16 = rem.chunks_exact_mut(16);
    for blk in &mut chunks16 {
        let b: &mut [u8; 16] = blk.try_into().unwrap();
        let m = *b;
        let mut k = [0u8; 16];
        let ctr = *counter;
        inc(counter);
        aes.encrypt_block(&ctr, &mut k);
        for i in 0..16 {
            b[i] = m[i] ^ k[i];
        }
    }
    let tail = chunks16.into_remainder();
    if !tail.is_empty() {
        let mut k = [0u8; 16];
        let ctr = *counter;
        inc(counter);
        aes.encrypt_block(&ctr, &mut k);
        for i in 0..tail.len() {
            tail[i] ^= k[i];
        }
    }
}

// ---------------------------------------------------------------------------
// GCM (NIST SP 800-38D)
// ---------------------------------------------------------------------------

/// GHASH subkey table: H = E_K(0^128).
fn gcm_htable<E: AesEncrypt>(aes: &E) -> Htable {
    let mut h = [0u8; 16];
    aes.encrypt_block(&[0u8; 16], &mut h);
    let ht = Htable::new(&h);
    wipe(&mut h);
    ht
}

/// Feed `data` into GHASH, zero-padding a trailing partial block.
fn ghash_update_padded(g: &mut Ghash, data: &[u8]) {
    let mut chunks = data.chunks_exact(16);
    for blk in &mut chunks {
        g.update_block(blk.try_into().unwrap());
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut blk = [0u8; 16];
        blk[..rem.len()].copy_from_slice(rem);
        g.update_block(&blk);
    }
}

/// The closing `[len(A)]_64 || [len(C)]_64` block of the GHASH input.
fn gcm_length_block(aad_len: usize, ct_len: usize) -> [u8; 16] {
    let mut blk = [0u8; 16];
    blk[0..8].copy_from_slice(&((aad_len as u64).wrapping_mul(8)).to_be_bytes());
    blk[8..16].copy_from_slice(&((ct_len as u64).wrapping_mul(8)).to_be_bytes());
    blk
}

/// Derive J0 from the nonce (SP 800-38D section 5.2).
fn gcm_j0<E: AesEncrypt>(_aes: &E, htable: &Htable, nonce: &[u8]) -> Result<[u8; 16], drv::Error> {
    if nonce.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        Ok(j0)
    } else {
        if nonce.is_empty() {
            return Err(drv::Error::InvalidInput);
        }
        let mut g = Ghash::from_htable(*htable);
        ghash_update_padded(&mut g, nonce);
        g.update_block(&gcm_length_block(0, nonce.len()));
        Ok(g.finalize())
    }
}

/// GCM authentication tag: `GHASH(A || pad || C || pad || len) ^ E_K(J0)`.
fn gcm_tag<E: AesEncrypt>(
    aes: &E,
    htable: &Htable,
    j0: &[u8; 16],
    aad: &[u8],
    ct: &[u8],
) -> [u8; 16] {
    let mut g = Ghash::from_htable(*htable);
    ghash_update_padded(&mut g, aad);
    ghash_update_padded(&mut g, ct);
    g.update_block(&gcm_length_block(aad.len(), ct.len()));
    let mut s = g.finalize();
    let mut e_j0 = [0u8; 16];
    aes.encrypt_block(j0, &mut e_j0);
    xor_block(&mut s, &e_j0);
    wipe(&mut e_j0);
    s
}

/// First data counter block: inc32(J0).
#[inline]
fn gcm_ctr_start(j0: &[u8; 16]) -> [u8; 16] {
    let mut c = *j0;
    inc32(&mut c);
    c
}

macro_rules! impl_gcm {
    ($trait:ident, $reg_macro:ident, $aes:ident, $ctx:ident, $key_len:expr) => {
        /// Key schedule for the AES-GCM driver. The raw key is kept so the
        /// `Clone` bound on the driver's opaque context can be honored (the
        /// fixsliced cores are not themselves `Clone`).
        pub struct $ctx {
            aes: $aes,
            key: [u8; $key_len],
        }

        impl Clone for $ctx {
            fn clone(&self) -> Self {
                $ctx {
                    aes: $aes::new(&self.key),
                    key: self.key,
                }
            }
        }

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len]) -> Self::Context {
                $ctx {
                    aes: $aes::new(key),
                    key: *key,
                }
            }

            fn encrypt(
                ctx: &Self::Context,
                nonce: &[u8; 12],
                aad: &[u8],
                buffer: drv::InOutBuf<'_, '_, u8>,
                tag: &mut [u8; 16],
            ) -> Result<(), drv::Error> {
                let htable = gcm_htable(&ctx.aes);
                let j0 = gcm_j0(&ctx.aes, &htable, nonce)?;
                let mut buf = buffer.into_out_with_copied_in();
                let mut ctr = gcm_ctr_start(&j0);
                ctr_apply(&ctx.aes, &mut ctr, inc32, &mut buf);
                let mut t = gcm_tag(&ctx.aes, &htable, &j0, aad, &buf);
                tag.copy_from_slice(&t);
                wipe(&mut t);
                Ok(())
            }

            fn decrypt(
                ctx: &Self::Context,
                nonce: &[u8; 12],
                aad: &[u8],
                buffer: drv::InOutBuf<'_, '_, u8>,
                tag: &[u8; 16],
            ) -> Result<(), drv::Error> {
                let htable = gcm_htable(&ctx.aes);
                let j0 = gcm_j0(&ctx.aes, &htable, nonce)?;
                let mut buf = buffer.into_out_with_copied_in();
                let mut t = gcm_tag(&ctx.aes, &htable, &j0, aad, &buf);
                let mut diff = 0u8;
                for i in 0..16 {
                    diff |= t[i] ^ tag[i];
                }
                wipe(&mut t);
                if diff != 0 {
                    // Never release unauthenticated plaintext.
                    for b in buf.iter_mut() {
                        *b = 0;
                    }
                    return Err(drv::Error::InvalidSignature);
                }
                let mut ctr = gcm_ctr_start(&j0);
                ctr_apply(&ctx.aes, &mut ctr, inc32, &mut buf);
                Ok(())
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

impl_gcm!(Aes128Gcm, aes128_gcm_impl, Aes128, Aes128GcmContext, 16);
impl_gcm!(Aes256Gcm, aes256_gcm_impl, Aes256, Aes256GcmContext, 32);

// ---------------------------------------------------------------------------
// CTR (NIST SP 800-38A)
// ---------------------------------------------------------------------------

macro_rules! impl_ctr {
    ($trait:ident, $reg_macro:ident, $aes:ident, $ctx:ident, $key_len:expr) => {
        /// Streaming keystream state for the AES-CTR driver.
        #[derive(Clone)]
        pub struct $ctx {
            aes: $aes,
            counter: [u8; 16],
            keystream: [u8; 16],
            /// Number of keystream bytes already consumed from `keystream`;
            /// 16 means the buffer is exhausted and a fresh block is needed.
            pos: usize,
        }

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len], iv: &[u8; 16]) -> Self::Context {
                $ctx {
                    aes: $aes::new(key),
                    counter: *iv,
                    keystream: [0u8; 16],
                    pos: 16,
                }
            }

            fn apply_keystream(ctx: &mut Self::Context, buf: drv::InOutBuf<'_, '_, u8>) {
                let data = buf.into_out_with_copied_in();
                let mut offset = 0;
                while offset < data.len() {
                    if ctx.pos == 16 {
                        if data.len() - offset >= 32 {
                            // Bulk path: two fixsliced blocks per call.
                            ctr_apply(&ctx.aes, &mut ctx.counter, inc128, &mut data[offset..]);
                            return;
                        }
                        ctx.aes.encrypt_block(&ctx.counter, &mut ctx.keystream);
                        inc128(&mut ctx.counter);
                        ctx.pos = 0;
                    }
                    let n = core::cmp::min(16 - ctx.pos, data.len() - offset);
                    for j in 0..n {
                        data[offset + j] ^= ctx.keystream[ctx.pos + j];
                    }
                    ctx.pos += n;
                    offset += n;
                }
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

impl_ctr!(Aes128Ctr, aes128_ctr_impl, Aes128, Aes128CtrContext, 16);
impl_ctr!(Aes256Ctr, aes256_ctr_impl, Aes256, Aes256CtrContext, 32);

// ---------------------------------------------------------------------------
// CMAC (NIST SP 800-38B)
// ---------------------------------------------------------------------------

/// GF(2^128) doubling (multiply by x; reduction polynomial
/// x^128 + x^7 + x^2 + x + 1).
#[inline]
fn cmac_double(blk: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let carry = blk[0] >> 7;
    for i in 0..15 {
        out[i] = (blk[i] << 1) | (blk[i + 1] >> 7);
    }
    out[15] = blk[15] << 1;
    if carry != 0 {
        out[15] ^= 0x87;
    }
    out
}

/// Streaming CMAC state shared by both key sizes. Only subkey K1 is stored;
/// K2 = dbl(K1) is derived in `finalize`. The raw key is stored by the
/// wrapping context so `Clone` can be honored.
struct CmacState<E> {
    aes: E,
    state: [u8; 16],
    buffer: [u8; 16],
    buf_len: usize,
    k1: [u8; 16],
}

impl<E: AesEncrypt> CmacState<E> {
    fn new(aes: E) -> Self {
        let mut l = [0u8; 16];
        aes.encrypt_block(&[0u8; 16], &mut l);
        let k1 = cmac_double(&l);
        wipe(&mut l);
        Self {
            aes,
            state: [0u8; 16],
            buffer: [0u8; 16],
            buf_len: 0,
            k1,
        }
    }

    /// Compress one full block into the CBC-MAC chain.
    fn mac_feed(&mut self, blk: &[u8; 16]) {
        let mut x = *blk;
        xor_block(&mut x, &self.state);
        self.aes.encrypt_block(&x, &mut self.state);
    }

    /// Buffer input, always holding back the final block (which may turn out
    /// to be complete or need padding).
    fn update(&mut self, mut data: &[u8]) {
        loop {
            if self.buf_len == 16 {
                if data.is_empty() {
                    return;
                }
                let blk = self.buffer;
                self.mac_feed(&blk);
                self.buf_len = 0;
            }
            if data.is_empty() {
                return;
            }
            let n = core::cmp::min(16 - self.buf_len, data.len());
            self.buffer[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
        }
    }

    fn finalize(self) -> [u8; 16] {
        let k2 = cmac_double(&self.k1);
        let (blk, key) = if self.buf_len == 16 {
            (self.buffer, self.k1)
        } else {
            let mut b = self.buffer;
            for i in self.buf_len..16 {
                b[i] = 0;
            }
            b[self.buf_len] = 0x80;
            (b, k2)
        };
        let mut x = blk;
        xor_block(&mut x, &key);
        xor_block(&mut x, &self.state);
        let mut out = [0u8; 16];
        self.aes.encrypt_block(&x, &mut out);
        out
    }

    fn reset(&mut self) {
        self.state = [0u8; 16];
        self.buf_len = 0;
    }
}

macro_rules! impl_cmac {
    ($trait:ident, $reg_macro:ident, $aes:ident, $ctx:ident, $key_len:expr) => {
        /// Context for the AES-CMAC driver.
        pub struct $ctx {
            inner: CmacState<$aes>,
            key: [u8; $key_len],
        }

        impl Clone for $ctx {
            fn clone(&self) -> Self {
                $ctx {
                    inner: CmacState::new($aes::new(&self.key)),
                    key: self.key,
                }
            }
        }

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len]) -> Self::Context {
                $ctx {
                    inner: CmacState::new($aes::new(key)),
                    key: *key,
                }
            }

            fn update(ctx: &mut Self::Context, data: &[u8]) {
                ctx.inner.update(data);
            }

            fn finalize(ctx: Self::Context, out: &mut [u8; 16]) {
                *out = ctx.inner.finalize();
            }

            fn reset(ctx: &mut Self::Context) {
                ctx.inner.reset();
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

impl_cmac!(Aes128Cmac, aes128_cmac_impl, Aes128, Aes128CmacContext, 16);
//  impl_cmac!(Aes256Cmac, aes256cmac_impl, Aes256, Aes256CmacContext, 32);

// ---------------------------------------------------------------------------
// CCM (NIST SP 800-38C / RFC 3610)
// ---------------------------------------------------------------------------

/// Validate nonce/tag sizes; returns `(q, t)` on success.
fn ccm_params(nonce_len: usize, tag_len: usize) -> Result<(usize, usize), drv::Error> {
    if nonce_len < 7 || nonce_len > 13 {
        return Err(drv::Error::InvalidInput);
    }
    match tag_len {
        4 | 6 | 8 | 10 | 12 | 14 | 16 => {}
        _ => return Err(drv::Error::InvalidInput),
    }
    Ok((15 - nonce_len, tag_len))
}

/// The message length must fit the q-byte big-endian length field.
fn ccm_check_len(q: usize, msg_len: usize) -> Result<(), drv::Error> {
    if q < 8 && (msg_len as u128) >= (1u128 << (8 * q)) {
        return Err(drv::Error::InvalidInput);
    }
    Ok(())
}

/// CBC-MAC block processor: buffers partial input and zero-pads at section
/// boundaries via `feed_padded`.
struct CcmMac<'a, E> {
    aes: &'a E,
    y: [u8; 16],
    blk: [u8; 16],
    len: usize,
}

impl<'a, E: AesEncrypt> CcmMac<'a, E> {
    fn new(aes: &'a E) -> Self {
        Self {
            aes,
            y: [0u8; 16],
            blk: [0u8; 16],
            len: 0,
        }
    }

    fn feed_block(&mut self, blk: &[u8; 16]) {
        let mut x = *blk;
        xor_block(&mut x, &self.y);
        self.aes.encrypt_block(&x, &mut self.y);
    }

    fn feed(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let n = core::cmp::min(16 - self.len, data.len());
            self.blk[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len == 16 {
                let b = self.blk;
                self.feed_block(&b);
                self.len = 0;
            }
        }
    }

    /// Zero-pad and flush a trailing partial block.
    fn feed_padded(&mut self) {
        if self.len > 0 {
            for i in self.len..16 {
                self.blk[i] = 0;
            }
            let b = self.blk;
            self.feed_block(&b);
            self.len = 0;
        }
    }
}

/// CCM CBC-MAC over `B0 || aad-encoding || msg`, with the final message
/// block zero-padded as required.
fn ccm_cbc_mac<E: AesEncrypt>(
    aes: &E,
    q: usize,
    t: usize,
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
) -> Result<[u8; 16], drv::Error> {
    ccm_check_len(q, msg.len())?;

    let mut mac = CcmMac::new(aes);

    // B0: flags || nonce || msg length (q bytes, big-endian).
    let mut b0 = [0u8; 16];
    b0[0] =
        (if aad.is_empty() { 0u8 } else { 0x40 }) | ((((t - 2) / 2) as u8) << 3) | (q - 1) as u8;
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    let mlen = (msg.len() as u128).to_be_bytes();
    b0[16 - q..16].copy_from_slice(&mlen[16 - q..16]);
    mac.feed_block(&b0);

    if !aad.is_empty() {
        let mut hdr = [0u8; 16];
        let off;
        if aad.len() < 0xFF00 {
            hdr[0..2].copy_from_slice(&(aad.len() as u16).to_be_bytes());
            off = 2;
        } else if aad.len() < (1usize << 32) {
            hdr[0] = 0xFF;
            hdr[1] = 0xFE;
            hdr[2..6].copy_from_slice(&(aad.len() as u32).to_be_bytes());
            off = 6;
        } else {
            return Err(drv::Error::InvalidInput);
        }
        let n = core::cmp::min(16 - off, aad.len());
        hdr[off..off + n].copy_from_slice(&aad[..n]);
        mac.feed(&hdr[..off + n]);
        mac.feed(&aad[n..]);
        mac.feed_padded();
    }

    mac.feed(msg);
    mac.feed_padded();

    Ok(mac.y)
}

/// Format a CCM counter block `A_i = flags(q-1) || nonce || i`, with `i`
/// occupying the last q bytes as a big-endian integer.
fn ccm_ctr_block(q: usize, nonce: &[u8], ctr: u64) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = (q - 1) as u8;
    a[1..1 + nonce.len()].copy_from_slice(nonce);
    let c = ctr.to_be_bytes();
    a[16 - q..16].copy_from_slice(&c[8 - q..8]);
    a
}

/// CCM CTR crypt, starting at counter value `start`.
fn ccm_ctr_crypt<E: AesEncrypt>(aes: &E, q: usize, nonce: &[u8], start: u64, data: &mut [u8]) {
    let mut ctr = start;
    let mut offset = 0;
    while offset < data.len() {
        let a = ccm_ctr_block(q, nonce, ctr);
        ctr = ctr.wrapping_add(1);
        let mut k = [0u8; 16];
        aes.encrypt_block(&a, &mut k);
        let n = core::cmp::min(16, data.len() - offset);
        for j in 0..n {
            data[offset + j] ^= k[j];
        }
        offset += n;
    }
}

macro_rules! impl_ccm {
    ($trait:ident, $reg_macro:ident, $aes:ident, $ctx:ident, $key_len:expr) => {
        /// Context for the AES-CCM driver. Only the key schedule is needed:
        /// CCM's CBC-MAC and CTR encryption both derive from E_K alone.
        pub struct $ctx {
            aes: $aes,
            key: [u8; $key_len],
        }

        impl Clone for $ctx {
            fn clone(&self) -> Self {
                $ctx {
                    aes: $aes::new(&self.key),
                    key: self.key,
                }
            }
        }

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len]) -> Self::Context {
                $ctx {
                    aes: $aes::new(key),
                    key: *key,
                }
            }

            fn encrypt(
                ctx: &Self::Context,
                nonce: &[u8],
                aad: &[u8],
                buffer: drv::InOutBuf<'_, '_, u8>,
                tag: &mut [u8],
            ) -> Result<(), drv::Error> {
                let (q, t) = ccm_params(nonce.len(), tag.len())?;
                let mut buf = buffer.into_out_with_copied_in();
                let mac = ccm_cbc_mac(&ctx.aes, q, t, nonce, aad, &buf)?;
                ccm_ctr_crypt(&ctx.aes, q, nonce, 1, &mut buf);
                let mut s0 = [0u8; 16];
                ctx.aes.encrypt_block(&ccm_ctr_block(q, nonce, 0), &mut s0);
                for i in 0..t {
                    tag[i] = mac[i] ^ s0[i];
                }
                wipe(&mut s0);
                Ok(())
            }

            fn decrypt(
                ctx: &Self::Context,
                nonce: &[u8],
                aad: &[u8],
                buffer: drv::InOutBuf<'_, '_, u8>,
                tag: &[u8],
            ) -> Result<(), drv::Error> {
                let (q, t) = ccm_params(nonce.len(), tag.len())?;
                // Authenticate the ciphertext before releasing any plaintext.
                let mac = ccm_cbc_mac(&ctx.aes, q, t, nonce, aad, buffer.get_in())?;
                let mut s0 = [0u8; 16];
                ctx.aes.encrypt_block(&ccm_ctr_block(q, nonce, 0), &mut s0);
                let mut diff = 0u8;
                for i in 0..t {
                    diff |= mac[i] ^ s0[i] ^ tag[i];
                }
                wipe(&mut s0);
                if diff != 0 {
                    return Err(drv::Error::InvalidSignature);
                }
                let mut buf = buffer.into_out_with_copied_in();
                ccm_ctr_crypt(&ctx.aes, q, nonce, 1, &mut buf);
                Ok(())
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

impl_ccm!(Aes128Ccm, aes128_ccm_impl, Aes128, Aes128CcmContext, 16);
impl_ccm!(Aes256Ccm, aes256_ccm_impl, Aes256, Aes256CcmContext, 32);
reg::p256_ecdsa_impl!(McuCryptoAsmDriver);
