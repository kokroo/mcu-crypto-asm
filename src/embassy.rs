//! `embassy-crypto-driver` elliptic-curve backend for P-256 and P-384.

use drv::{P256Point, P256Scalar, P256Signature, P384Point, P384Scalar, P384Signature};
use embassy_crypto as reg;
/// Re-export of the driver crate (integration tests use this to name its types).
use embassy_crypto::driver as drv;

use crate::p256::{PointP256, ScalarP256, CURVE as P256_CURVE, FIELD as P256_FIELD};
use crate::p384::{PointP384, ScalarP384, CURVE as P384_CURVE, FIELD as P384_FIELD};
use crate::{CurveParams, Fe, Params, Point, Scalar};

/// Driver implementation registered with `embassy-crypto-driver`.
pub struct McuCryptoAsmDriver;

// ---------------------------------------------------------------------------
// Canonical conversions
// ---------------------------------------------------------------------------

fn p256_scalar_from_canonical(k: &P256Scalar) -> Option<ScalarP256> {
    Scalar::from_be_bytes(&P256_CURVE, &k.0).ok()
}

fn p256_scalar_to_canonical(k: &ScalarP256) -> P256Scalar {
    let mut out = P256Scalar([0u8; 32]);
    let _ = k.to_be_bytes(&P256_CURVE, &mut out.0);
    out
}

fn p384_scalar_from_canonical(k: &P384Scalar) -> Option<ScalarP384> {
    Scalar::from_be_bytes(&P384_CURVE, &k.0).ok()
}

fn p384_scalar_to_canonical(k: &ScalarP384) -> P384Scalar {
    let mut out = P384Scalar([0u8; 48]);
    let _ = k.to_be_bytes(&P384_CURVE, &mut out.0);
    out
}

fn p256_point_from_canonical(p: &P256Point) -> Option<PointP256> {
    let mut enc = [0u8; 65];
    enc[0] = 0x04;
    enc[1..33].copy_from_slice(&p.x);
    enc[33..65].copy_from_slice(&p.y);
    PointP256::decode(&P256_CURVE, &enc).ok()
}

fn p256_point_to_canonical(p: &PointP256) -> Option<P256Point> {
    p.to_affine(&P256_FIELD).map(|(x, y)| P256Point {
        x: limbs_to_be_256(&x),
        y: limbs_to_be_256(&y),
    })
}

fn p384_point_from_canonical(p: &P384Point) -> Option<PointP384> {
    let mut enc = [0u8; 97];
    enc[0] = 0x04;
    enc[1..49].copy_from_slice(&p.x);
    enc[49..97].copy_from_slice(&p.y);
    PointP384::decode(&P384_CURVE, &enc).ok()
}

fn p384_point_to_canonical(p: &PointP384) -> Option<P384Point> {
    p.to_affine(&P384_FIELD).map(|(x, y)| P384Point {
        x: limbs_to_be_384(&x),
        y: limbs_to_be_384(&y),
    })
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
fn low_s<const N: usize, const B: usize>(
    s: &[u8; B],
    c: &CurveParams,
) -> Result<[u8; B], drv::Error> {
    let scalar = Scalar::<N>::from_be_bytes_nonzero(c, s).map_err(|_| drv::Error::InvalidInput)?;
    let negated = scalar.neg(c);
    let scalar_limbs = scalar.to_int(c);
    let half = half_order::<N>(c.order);
    let mask = core::hint::black_box(0u32.wrapping_sub(less_than(&half, &scalar_limbs) as u32));

    let mut out = scalar;
    for i in 0..N {
        out.v[i] = scalar.v[i] ^ ((scalar.v[i] ^ negated.v[i]) & mask);
    }

    let mut bytes = [0u8; B];
    let _ = out.to_be_bytes(c, &mut bytes);
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

        // `peer` is untrusted: the trait contract reports a bad peer as
        // `InvalidKey`, not `InvalidInput`.
        result.map_err(|_| drv::Error::InvalidKey)?;
        Ok(out)
    }
}

#[cfg(feature = "embassy-crypto-p256-ecdh")]
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

        // The nonce is drawn from the registered Rng driver by rejection sampling into [1, n).
        let mut nonce = [0u8; 32];
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        let mut result: Result<(), crate::ecdsa::Error> = Err(crate::ecdsa::Error::BadScalar);
        for _ in 0..8 {
            embassy_crypto::rng_fill_bytes(&mut nonce);
            result = crate::p256::ecdsa::sign(&k.0, digest, &nonce, &mut r, &mut s);
            if result.is_ok() {
                break;
            }
            result = Err(crate::ecdsa::Error::BadScalar);
        }
        wipe(&mut nonce);
        result.map_err(|_| drv::Error::InvalidInput)?;

        s = low_s::<8, 32>(&s, &P256_CURVE)?;
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

        // Contract: any verification failure is `InvalidSignature`, except an
        // invalid `q`, which is `InvalidKey`.
        crate::p256::ecdsa::verify(&q_enc, digest, &sig.r.0, &sig.s.0).map_err(|e| match e {
            crate::ecdsa::Error::BadPoint => drv::Error::InvalidKey,
            _ => drv::Error::InvalidSignature,
        })
    }
}

#[cfg(feature = "embassy-crypto-p256-ecdsa")]
reg::p256_ecdsa_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// P-256 scalar/point arithmetic
// ---------------------------------------------------------------------------

impl drv::P256Arith for McuCryptoAsmDriver {
    type Point = PointP256;

    fn scalar_add(a: &P256Scalar, b: &P256Scalar) -> P256Scalar {
        let a = p256_scalar_from_canonical(a).unwrap_or(ScalarP256::ZERO);
        let b = p256_scalar_from_canonical(b).unwrap_or(ScalarP256::ZERO);
        p256_scalar_to_canonical(&a.add(&P256_CURVE, &b))
    }

    fn scalar_sub(a: &P256Scalar, b: &P256Scalar) -> P256Scalar {
        let a = p256_scalar_from_canonical(a).unwrap_or(ScalarP256::ZERO);
        let b = p256_scalar_from_canonical(b).unwrap_or(ScalarP256::ZERO);
        p256_scalar_to_canonical(&a.sub(&P256_CURVE, &b))
    }

    fn scalar_mul(a: &P256Scalar, b: &P256Scalar) -> P256Scalar {
        let a = p256_scalar_from_canonical(a).unwrap_or(ScalarP256::ZERO);
        let b = p256_scalar_from_canonical(b).unwrap_or(ScalarP256::ZERO);
        p256_scalar_to_canonical(&a.mul(&P256_CURVE, &b))
    }

    fn scalar_invert(a: &P256Scalar) -> P256Scalar {
        let a = p256_scalar_from_canonical(a).unwrap_or(ScalarP256::ZERO);
        p256_scalar_to_canonical(&a.invert(&P256_CURVE).unwrap_or(ScalarP256::ZERO))
    }

    fn point_identity() -> Self::Point {
        Point::identity(&P256_FIELD)
    }

    fn point_from_affine(p: &P256Point) -> Option<Self::Point> {
        p256_point_from_canonical(p)
    }

    fn point_from_affine_unchecked(p: &P256Point) -> Self::Point {
        p256_point_from_canonical(p).unwrap_or_else(|| Point::identity(&P256_FIELD))
    }

    fn point_to_affine(p: &Self::Point) -> Option<P256Point> {
        p256_point_to_canonical(p)
    }

    fn point_is_identity(p: &Self::Point) -> bool {
        p.is_identity()
    }

    fn point_neg(p: &Self::Point) -> Self::Point {
        Point {
            x: p.x,
            y: Fe::ZERO.sub(&P256_FIELD, &p.y),
            z: p.z,
        }
    }

    fn point_add(p: &Self::Point, q: &Self::Point) -> Self::Point {
        p.add(&P256_CURVE, q)
    }

    fn point_mul(k: &P256Scalar, p: &Self::Point) -> Self::Point {
        let k = p256_scalar_from_canonical(k).unwrap_or(ScalarP256::ZERO);
        p.mul_scalar(&P256_CURVE, &k.to_int(&P256_CURVE))
    }

    fn point_mul_base(k: &P256Scalar) -> Self::Point {
        let k = p256_scalar_from_canonical(k).unwrap_or(ScalarP256::ZERO);
        crate::p256::mul_base(&k.to_int(&P256_CURVE))
    }

    fn point_lincomb(
        a: &P256Scalar,
        p: &Self::Point,
        b: &P256Scalar,
        q: &Self::Point,
    ) -> Self::Point {
        let a = p256_scalar_from_canonical(a).unwrap_or(ScalarP256::ZERO);
        let b = p256_scalar_from_canonical(b).unwrap_or(ScalarP256::ZERO);
        Point::lincomb(
            &P256_CURVE,
            &a.to_int(&P256_CURVE),
            p,
            &b.to_int(&P256_CURVE),
            q,
        )
    }

    fn point_lincomb_vartime(
        a: &P256Scalar,
        p: &Self::Point,
        b: &P256Scalar,
        q: &Self::Point,
    ) -> Self::Point {
        Self::point_lincomb(a, p, b, q)
    }
}

#[cfg(feature = "embassy-crypto-p256-arith")]
reg::p256_arith_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// High-level P-384 operations
// ---------------------------------------------------------------------------

impl drv::P384Arith for McuCryptoAsmDriver {
    type Point = PointP384;

    fn scalar_add(a: &P384Scalar, b: &P384Scalar) -> P384Scalar {
        let a = p384_scalar_from_canonical(a).unwrap_or(ScalarP384::ZERO);
        let b = p384_scalar_from_canonical(b).unwrap_or(ScalarP384::ZERO);
        p384_scalar_to_canonical(&a.add(&P384_CURVE, &b))
    }

    fn scalar_sub(a: &P384Scalar, b: &P384Scalar) -> P384Scalar {
        let a = p384_scalar_from_canonical(a).unwrap_or(ScalarP384::ZERO);
        let b = p384_scalar_from_canonical(b).unwrap_or(ScalarP384::ZERO);
        p384_scalar_to_canonical(&a.sub(&P384_CURVE, &b))
    }

    fn scalar_mul(a: &P384Scalar, b: &P384Scalar) -> P384Scalar {
        let a = p384_scalar_from_canonical(a).unwrap_or(ScalarP384::ZERO);
        let b = p384_scalar_from_canonical(b).unwrap_or(ScalarP384::ZERO);
        p384_scalar_to_canonical(&a.mul(&P384_CURVE, &b))
    }

    fn scalar_invert(a: &P384Scalar) -> P384Scalar {
        let a = p384_scalar_from_canonical(a).unwrap_or(ScalarP384::ZERO);
        p384_scalar_to_canonical(&a.invert(&P384_CURVE).unwrap_or(ScalarP384::ZERO))
    }

    fn point_identity() -> Self::Point {
        Point::identity(&P384_FIELD)
    }

    fn point_from_affine(p: &P384Point) -> Option<Self::Point> {
        p384_point_from_canonical(p)
    }

    fn point_from_affine_unchecked(p: &P384Point) -> Self::Point {
        p384_point_from_canonical(p).unwrap_or_else(|| Point::identity(&P384_FIELD))
    }

    fn point_to_affine(p: &Self::Point) -> Option<P384Point> {
        p384_point_to_canonical(p)
    }

    fn point_is_identity(p: &Self::Point) -> bool {
        p.is_identity()
    }

    fn point_neg(p: &Self::Point) -> Self::Point {
        Point {
            x: p.x,
            y: Fe::ZERO.sub(&P384_FIELD, &p.y),
            z: p.z,
        }
    }

    fn point_add(p: &Self::Point, q: &Self::Point) -> Self::Point {
        p.add(&P384_CURVE, q)
    }

    fn point_mul(k: &P384Scalar, p: &Self::Point) -> Self::Point {
        let k = p384_scalar_from_canonical(k).unwrap_or(ScalarP384::ZERO);
        p.mul_scalar(&P384_CURVE, &k.to_int(&P384_CURVE))
    }

    fn point_mul_base(k: &P384Scalar) -> Self::Point {
        let k = p384_scalar_from_canonical(k).unwrap_or(ScalarP384::ZERO);
        crate::p384::mul_base(&k.to_int(&P384_CURVE))
    }

    fn point_lincomb(
        a: &P384Scalar,
        p: &Self::Point,
        b: &P384Scalar,
        q: &Self::Point,
    ) -> Self::Point {
        let a = p384_scalar_from_canonical(a).unwrap_or(ScalarP384::ZERO);
        let b = p384_scalar_from_canonical(b).unwrap_or(ScalarP384::ZERO);
        Point::lincomb(
            &P384_CURVE,
            &a.to_int(&P384_CURVE),
            p,
            &b.to_int(&P384_CURVE),
            q,
        )
    }

    fn point_lincomb_vartime(
        a: &P384Scalar,
        p: &Self::Point,
        b: &P384Scalar,
        q: &Self::Point,
    ) -> Self::Point {
        Self::point_lincomb(a, p, b, q)
    }
}

#[cfg(feature = "embassy-crypto-p384-arith")]
reg::p384_arith_impl!(McuCryptoAsmDriver);

impl drv::P384Ecdh for McuCryptoAsmDriver {
    fn public_key(k: &P384Scalar) -> Result<P384Point, drv::Error> {
        let k_sc = p384_scalar_from_canonical(k).ok_or(drv::Error::InvalidKey)?;
        p384_point_to_canonical(&crate::p384::mul_base(&k_sc.to_int(&P384_CURVE)))
            .ok_or(drv::Error::InvalidInput)
    }

    fn shared_secret(k: &P384Scalar, peer: &P384Point) -> Result<[u8; 48], drv::Error> {
        if ScalarP384::from_be_bytes_nonzero(&P384_CURVE, &k.0).is_err() {
            return Err(drv::Error::InvalidKey);
        }

        let mut peer_enc = [0u8; 97];
        peer_enc[0] = 0x04;
        peer_enc[1..49].copy_from_slice(&peer.x);
        peer_enc[49..97].copy_from_slice(&peer.y);

        let mut out = [0u8; 48];
        crate::p384::ecdh::shared_secret(&k.0, &peer_enc, &mut out)
            .map_err(|_| drv::Error::InvalidKey)?;
        Ok(out)
    }
}

#[cfg(feature = "embassy-crypto-p384-ecdh")]
reg::p384_ecdh_impl!(McuCryptoAsmDriver);

impl drv::P384Ecdsa for McuCryptoAsmDriver {
    fn public_key(k: &P384Scalar) -> Result<P384Point, drv::Error> {
        let k_sc = p384_scalar_from_canonical(k).ok_or(drv::Error::InvalidKey)?;
        p384_point_to_canonical(&crate::p384::mul_base(&k_sc.to_int(&P384_CURVE)))
            .ok_or(drv::Error::InvalidInput)
    }

    fn sign(k: &P384Scalar, digest: &[u8; 48]) -> Result<P384Signature, drv::Error> {
        if ScalarP384::from_be_bytes_nonzero(&P384_CURVE, &k.0).is_err() {
            return Err(drv::Error::InvalidKey);
        }

        // The nonce is drawn from the registered Rng driver by rejection sampling into [1, n).
        let mut nonce = [0u8; 48];
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        let mut result: Result<(), crate::ecdsa::Error> = Err(crate::ecdsa::Error::BadScalar);
        for _ in 0..8 {
            embassy_crypto::rng_fill_bytes(&mut nonce);
            result = crate::p384::ecdsa::sign(&k.0, digest, &nonce, &mut r, &mut s);
            if result.is_ok() {
                break;
            }
            result = Err(crate::ecdsa::Error::BadScalar);
        }
        wipe(&mut nonce);
        result.map_err(|_| drv::Error::InvalidInput)?;

        s = low_s::<12, 48>(&s, &P384_CURVE)?;
        Ok(P384Signature {
            r: P384Scalar(r),
            s: P384Scalar(s),
        })
    }

    fn verify(q: &P384Point, digest: &[u8; 48], sig: &P384Signature) -> Result<(), drv::Error> {
        let mut q_enc = [0u8; 97];
        q_enc[0] = 0x04;
        q_enc[1..49].copy_from_slice(&q.x);
        q_enc[49..97].copy_from_slice(&q.y);

        // Contract: any verification failure is `InvalidSignature`, except an
        // invalid `q`, which is `InvalidKey`.
        crate::p384::ecdsa::verify(&q_enc, digest, &sig.r.0, &sig.s.0).map_err(|e| match e {
            crate::ecdsa::Error::BadPoint => drv::Error::InvalidKey,
            _ => drv::Error::InvalidSignature,
        })
    }
}

#[cfg(feature = "embassy-crypto-p384-ecdsa")]
reg::p384_ecdsa_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// AES driver support
// ---------------------------------------------------------------------------

use crate::aes::AesError;

macro_rules! impl_gcm {
    ($trait:ident, $reg_macro:ident, $ctx:ident, $inner:ident, $key_len:expr) => {
        pub type $ctx = crate::aes::$inner;

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len]) -> Self::Context {
                $ctx::new(key)
            }

            fn encrypt(
                ctx: &Self::Context,
                nonce: &[u8; 12],
                aad: &[u8],
                buffer: drv::InOutBuf<'_, '_, u8>,
                tag: &mut [u8; 16],
            ) -> Result<(), drv::Error> {
                let mut buf = buffer.into_out_with_copied_in();
                ctx.encrypt(nonce, aad, &mut buf, tag).map_err(|e| match e {
                    AesError::InvalidInput => drv::Error::InvalidInput,
                    AesError::InvalidSignature => drv::Error::InvalidSignature,
                })
            }

            fn decrypt(
                ctx: &Self::Context,
                nonce: &[u8; 12],
                aad: &[u8],
                buffer: drv::InOutBuf<'_, '_, u8>,
                tag: &[u8; 16],
            ) -> Result<(), drv::Error> {
                let mut buf = buffer.into_out_with_copied_in();
                ctx.decrypt(nonce, aad, &mut buf, tag).map_err(|e| match e {
                    AesError::InvalidInput => drv::Error::InvalidInput,
                    AesError::InvalidSignature => drv::Error::InvalidSignature,
                })
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

#[cfg(feature = "embassy-crypto-aes128-gcm")]
impl_gcm!(Aes128Gcm, aes128_gcm_impl, Aes128GcmContext, Aes128Gcm, 16);
#[cfg(feature = "embassy-crypto-aes256-gcm")]
impl_gcm!(Aes256Gcm, aes256_gcm_impl, Aes256GcmContext, Aes256Gcm, 32);

// ---------------------------------------------------------------------------
// CTR (NIST SP 800-38A)
// ---------------------------------------------------------------------------

macro_rules! impl_ctr {
    ($trait:ident, $reg_macro:ident, $ctx:ident, $inner:ident, $key_len:expr) => {
        pub type $ctx = crate::aes::$inner;

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len], iv: &[u8; 16]) -> Self::Context {
                $ctx::init(key, iv)
            }

            fn apply_keystream(ctx: &mut Self::Context, buf: drv::InOutBuf<'_, '_, u8>) {
                ctx.apply_keystream(buf.into_out_with_copied_in());
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

#[cfg(feature = "embassy-crypto-aes128-ctr")]
impl_ctr!(Aes128Ctr, aes128_ctr_impl, Aes128CtrContext, Aes128Ctr, 16);
#[cfg(feature = "embassy-crypto-aes256-ctr")]
impl_ctr!(Aes256Ctr, aes256_ctr_impl, Aes256CtrContext, Aes256Ctr, 32);

// ---------------------------------------------------------------------------
// CMAC (NIST SP 800-38B)
// ---------------------------------------------------------------------------

macro_rules! impl_cmac {
    ($trait:ident, $reg_macro:ident, $ctx:ident, $inner:ident, $key_len:expr) => {
        pub type $ctx = crate::aes::$inner;

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len]) -> Self::Context {
                $ctx::new(key)
            }

            fn update(ctx: &mut Self::Context, data: &[u8]) {
                ctx.update(data);
            }

            fn finalize(ctx: Self::Context, out: &mut [u8; 16]) {
                ctx.finalize(out);
            }

            fn reset(ctx: &mut Self::Context) {
                ctx.reset();
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

#[cfg(feature = "embassy-crypto-aes128-cmac")]
impl_cmac!(
    Aes128Cmac,
    aes128_cmac_impl,
    Aes128CmacContext,
    Aes128Cmac,
    16
);
#[cfg(all(target_pointer_width = "64", feature = "embassy-crypto-aes256-cmac"))]
impl_cmac!(
    Aes256Cmac,
    aes256_cmac_impl,
    Aes256CmacContext,
    Aes256Cmac,
    32
);

// ---------------------------------------------------------------------------
// CCM (NIST SP 800-38C / RFC 3610)
// ---------------------------------------------------------------------------

macro_rules! impl_ccm {
    ($trait:ident, $reg_macro:ident, $ctx:ident, $inner:ident, $key_len:expr) => {
        pub type $ctx = crate::aes::$inner;

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len]) -> Self::Context {
                $ctx::new(key)
            }

            fn encrypt(
                ctx: &Self::Context,
                nonce: &[u8],
                aad: &[u8],
                buffer: drv::InOutBuf<'_, '_, u8>,
                tag: &mut [u8],
            ) -> Result<(), drv::Error> {
                let mut buf = buffer.into_out_with_copied_in();
                ctx.encrypt(nonce, aad, &mut buf, tag).map_err(|e| match e {
                    AesError::InvalidInput => drv::Error::InvalidInput,
                    AesError::InvalidSignature => drv::Error::InvalidSignature,
                })
            }

            fn decrypt(
                ctx: &Self::Context,
                nonce: &[u8],
                aad: &[u8],
                buffer: drv::InOutBuf<'_, '_, u8>,
                tag: &[u8],
            ) -> Result<(), drv::Error> {
                let mut buf = buffer.into_out_with_copied_in();
                ctx.decrypt(nonce, aad, &mut buf, tag).map_err(|e| match e {
                    AesError::InvalidInput => drv::Error::InvalidInput,
                    AesError::InvalidSignature => drv::Error::InvalidSignature,
                })
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

#[cfg(feature = "embassy-crypto-aes128-ccm")]
impl_ccm!(Aes128Ccm, aes128_ccm_impl, Aes128CcmContext, Aes128Ccm, 16);
#[cfg(feature = "embassy-crypto-aes256-ccm")]
impl_ccm!(Aes256Ccm, aes256_ccm_impl, Aes256CcmContext, Aes256Ccm, 32);
// ---------------------------------------------------------------------------
// X25519 (RFC 7748)
// ---------------------------------------------------------------------------

impl drv::X25519 for McuCryptoAsmDriver {
    fn public_key(k: &drv::X25519SecretKey) -> Result<drv::X25519PublicKey, drv::Error> {
        Ok(drv::X25519PublicKey(crate::curve25519::x25519::public_key(
            &k.0,
        )))
    }

    fn shared_secret(
        k: &drv::X25519SecretKey,
        peer: &drv::X25519PublicKey,
    ) -> Result<[u8; 32], drv::Error> {
        // X25519 accepts every 32-byte string as a peer key; rejecting the
        // all-zero shared secret (low-order peer) is the public API's job.
        Ok(crate::curve25519::x25519::scalarmult(&k.0, &peer.0))
    }
}

#[cfg(feature = "embassy-crypto-x25519")]
reg::x25519_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032)
// ---------------------------------------------------------------------------

impl drv::Ed25519 for McuCryptoAsmDriver {
    fn public_key(k: &drv::Ed25519SecretKey) -> Result<drv::Ed25519PublicKey, drv::Error> {
        Ok(drv::Ed25519PublicKey(
            crate::curve25519::ed25519::public_key(&k.0),
        ))
    }

    fn sign(k: &drv::Ed25519SecretKey, msg: &[u8]) -> Result<drv::Ed25519Signature, drv::Error> {
        Ok(drv::Ed25519Signature(crate::curve25519::ed25519::sign(
            &k.0, msg,
        )))
    }

    fn verify(
        a: &drv::Ed25519PublicKey,
        msg: &[u8],
        sig: &drv::Ed25519Signature,
    ) -> Result<(), drv::Error> {
        crate::curve25519::ed25519::verify(&a.0, msg, &sig.0).map_err(|e| match e {
            crate::curve25519::ed25519::SignatureError::InvalidKey => drv::Error::InvalidKey,
            crate::curve25519::ed25519::SignatureError::InvalidSignature => {
                drv::Error::InvalidSignature
            }
        })
    }
}

#[cfg(feature = "embassy-crypto-ed25519")]
reg::ed25519_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// AES ECB / CBC
// ---------------------------------------------------------------------------

macro_rules! impl_ecb {
    ($trait:ident, $reg_macro:ident, $ctx:ident, $inner:ident, $key_len:expr) => {
        pub type $ctx = crate::aes::$inner;

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len]) -> Self::Context {
                $ctx::new(key)
            }

            fn encrypt_blocks(ctx: &Self::Context, blocks: drv::InOutBuf<'_, '_, u8>) {
                let buf = blocks.into_out_with_copied_in();
                ctx.encrypt_blocks(buf);
            }

            fn decrypt_blocks(ctx: &Self::Context, blocks: drv::InOutBuf<'_, '_, u8>) {
                let buf = blocks.into_out_with_copied_in();
                ctx.decrypt_blocks(buf);
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

macro_rules! impl_cbc {
    ($trait:ident, $reg_macro:ident, $ctx:ident, $inner:ident, $key_len:expr) => {
        pub type $ctx = crate::aes::$inner;

        impl drv::$trait for McuCryptoAsmDriver {
            type EncryptContext = $ctx;
            type DecryptContext = $ctx;

            fn encrypt_init(key: &[u8; $key_len], iv: &[u8; 16]) -> Self::EncryptContext {
                $ctx::new(key, iv)
            }

            fn decrypt_init(key: &[u8; $key_len], iv: &[u8; 16]) -> Self::DecryptContext {
                Self::encrypt_init(key, iv)
            }

            fn encrypt_blocks(ctx: &mut Self::EncryptContext, blocks: drv::InOutBuf<'_, '_, u8>) {
                let buf = blocks.into_out_with_copied_in();
                ctx.encrypt_blocks(buf);
            }

            fn decrypt_blocks(ctx: &mut Self::DecryptContext, blocks: drv::InOutBuf<'_, '_, u8>) {
                let buf = blocks.into_out_with_copied_in();
                ctx.decrypt_blocks(buf);
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

#[cfg(feature = "embassy-crypto-aes128-ecb")]
impl_ecb!(Aes128Ecb, aes128_ecb_impl, Aes128EcbContext, Aes128Ecb, 16);
#[cfg(feature = "embassy-crypto-aes256-ecb")]
impl_ecb!(Aes256Ecb, aes256_ecb_impl, Aes256EcbContext, Aes256Ecb, 32);
#[cfg(feature = "embassy-crypto-aes128-cbc")]
impl_cbc!(Aes128Cbc, aes128_cbc_impl, Aes128CbcContext, Aes128Cbc, 16);
#[cfg(feature = "embassy-crypto-aes256-cbc")]
impl_cbc!(Aes256Cbc, aes256_cbc_impl, Aes256CbcContext, Aes256Cbc, 32);

// ---------------------------------------------------------------------------
// SHA-512 family (FIPS 180-4)
// ---------------------------------------------------------------------------

pub use crate::sha512::{HmacSha512Family, Sha512Core, SHA512_224_IV, SHA512_256_IV};

macro_rules! impl_sha512_family {
    ($trait:ident, $reg_macro:ident, $out_len:expr, $iv:expr) => {
        impl drv::$trait for McuCryptoAsmDriver {
            type Context = Sha512Core;

            fn init() -> Self::Context {
                Sha512Core::new($iv)
            }

            fn update(ctx: &mut Self::Context, data: &[u8]) {
                ctx.update(data);
            }

            fn finalize(ctx: Self::Context, out: &mut [u8; $out_len]) {
                let digest = ctx.finalize();
                out.copy_from_slice(&digest[..$out_len]);
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

#[cfg(feature = "embassy-crypto-sha512")]
impl_sha512_family!(Sha512, sha512_impl, 64, crate::sha512::SHA512_IV);
#[cfg(feature = "embassy-crypto-sha384")]
impl_sha512_family!(Sha384, sha384_impl, 48, crate::sha512::SHA384_IV);
#[cfg(feature = "embassy-crypto-sha512-224")]
impl_sha512_family!(Sha512_224, sha512_224_impl, 28, SHA512_224_IV);
#[cfg(feature = "embassy-crypto-sha512-256")]
impl_sha512_family!(Sha512_256, sha512_256_impl, 32, SHA512_256_IV);

// ---------------------------------------------------------------------------
// HMAC-SHA512 family (RFC 2104)
// ---------------------------------------------------------------------------

macro_rules! impl_hmac_sha512_family {
    ($trait:ident, $reg_macro:ident, $out_len:expr, $iv:expr) => {
        impl drv::$trait for McuCryptoAsmDriver {
            type Context = HmacSha512Family;

            fn init(key: &[u8]) -> Self::Context {
                HmacSha512Family::new($iv, key, $out_len)
            }

            fn update(ctx: &mut Self::Context, data: &[u8]) {
                ctx.update(data);
            }

            fn finalize(ctx: Self::Context, out: &mut [u8; $out_len]) {
                let tag = ctx.finalize($iv);
                out.copy_from_slice(&tag[..$out_len]);
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

#[cfg(feature = "embassy-crypto-hmac-sha512")]
impl_hmac_sha512_family!(HmacSha512, hmac_sha512_impl, 64, crate::sha512::SHA512_IV);
#[cfg(feature = "embassy-crypto-hmac-sha384")]
impl_hmac_sha512_family!(HmacSha384, hmac_sha384_impl, 48, crate::sha512::SHA384_IV);
#[cfg(feature = "embassy-crypto-hmac-sha512-224")]
impl_hmac_sha512_family!(HmacSha512_224, hmac_sha512_224_impl, 28, SHA512_224_IV);
#[cfg(feature = "embassy-crypto-hmac-sha512-256")]
impl_hmac_sha512_family!(HmacSha512_256, hmac_sha512_256_impl, 32, SHA512_256_IV);
