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
    match p.to_affine(&P256_FIELD) {
        Some((x, y)) => Some(P256Point {
            x: limbs_to_be_256(&x),
            y: limbs_to_be_256(&y),
        }),
        None => None,
    }
}

fn p384_point_from_canonical(p: &P384Point) -> Option<PointP384> {
    let mut enc = [0u8; 97];
    enc[0] = 0x04;
    enc[1..49].copy_from_slice(&p.x);
    enc[49..97].copy_from_slice(&p.y);
    PointP384::decode(&P384_CURVE, &enc).ok()
}

fn p384_point_to_canonical(p: &PointP384) -> Option<P384Point> {
    match p.to_affine(&P384_FIELD) {
        Some((x, y)) => Some(P384Point {
            x: limbs_to_be_384(&x),
            y: limbs_to_be_384(&y),
        }),
        None => None,
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

reg::p384_ecdsa_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// AES driver support
// ---------------------------------------------------------------------------
//
// GCM, CTR, CMAC and CCM are built on the crate's fixsliced AES core. ECB and
// CBC (below, after the SHA-512 family sections) use a plain-Rust AES: the
// fixsliced core defines no inverse transforms, and the ECB/CBC driver
// contexts are too small to hold both a fixsliced schedule and a conventional
// one. The inverse cipher derives its S-box by inversion in GF(2^8) — no
// transcribed tables — and correctness takes priority over speed for ECB/CBC
// on an MCU.
//
// Mode implementations follow NIST SP 800-38A (CTR, CBC, ECB), SP 800-38B
// (CMAC), SP 800-38C / RFC 3610 (CCM) and SP 800-38D (GCM).
//
use crate::aes::{Aes128, Aes256};
use crate::ghash::{Ghash, Htable};

/// Facade over the two fixsliced AES cores so the mode helpers below are
/// generic over the key size.
trait AesEncrypt {
    fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]);
    #[allow(dead_code)]
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
        aes.encrypt_block(&b0, &mut k0);
        let b1 = *counter;
        inc(counter);
        aes.encrypt_block(&b1, &mut k1);
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
                            // Bulk path: process whole 16-byte multiples only.
                            // ctr_apply's sub-16 tail generates a keystream
                            // block and discards its unused bytes; the counter
                            // advances but ctx.pos stays 16, so the next call
                            // would resume at the wrong stream offset.
                            let bulk = (data.len() - offset) & !15;
                            ctr_apply(
                                &ctx.aes,
                                &mut ctx.counter,
                                inc128,
                                &mut data[offset..offset + bulk],
                            );
                            offset += bulk;
                            if offset == data.len() {
                                return;
                            }
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
#[cfg(target_pointer_width = "64")]
impl_cmac!(Aes256Cmac, aes256_cmac_impl, Aes256, Aes256CmacContext, 32);

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
        } else if aad.len() as u64 <= u32::MAX as u64 {
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
                // CCM's CBC-MAC is defined over the plaintext, so decrypt
                // first, then authenticate the recovered plaintext.
                let mut buf = buffer.into_out_with_copied_in();
                ccm_ctr_crypt(&ctx.aes, q, nonce, 1, &mut buf);
                let mac = ccm_cbc_mac(&ctx.aes, q, t, nonce, aad, &buf)?;
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
                Ok(())
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

impl_ccm!(Aes128Ccm, aes128_ccm_impl, Aes128, Aes128CcmContext, 16);
impl_ccm!(Aes256Ccm, aes256_ccm_impl, Aes256, Aes256CcmContext, 32);
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

reg::x25519_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032)
// ---------------------------------------------------------------------------

/// Clamp the first half of the hashed Ed25519 seed (RFC 8032 section 5.1.5).
fn ed25519_prune(h: &mut [u8; 32]) {
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
}

/// Little-endian bytes -> 4 x u64 limbs.
fn le_limbs_256(b: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    }
    out
}

/// `k * a + r` on 256-bit little-endian integers as a 64-byte little-endian
/// value for reduction mod L by the caller. `k * a + r < L^2 + L < 2^512`, so
/// the result always fits.
fn mul_add_256le(k: &[u8; 32], a: &[u8; 32], r: &[u8; 32]) -> [u8; 64] {
    let kl = le_limbs_256(k);
    let al = le_limbs_256(a);

    // 4x4 u64 schoolbook multiply -> 512-bit product.
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = t[i + j] as u128 + kl[i] as u128 * al[j] as u128 + carry;
            t[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut idx = i + 4;
        while carry != 0 {
            let cur = t[idx] as u128 + carry;
            t[idx] = cur as u64;
            carry = cur >> 64;
            idx += 1;
        }
    }

    // Add r into the low half, propagating into the high half.
    let rl = le_limbs_256(r);
    let mut carry = 0u128;
    for i in 0..4 {
        let cur = t[i] as u128 + rl[i] as u128 + carry;
        t[i] = cur as u64;
        carry = cur >> 64;
    }
    let mut idx = 4;
    while carry != 0 {
        let cur = t[idx] as u128 + carry;
        t[idx] = cur as u64;
        carry = cur >> 64;
        idx += 1;
    }

    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..i * 8 + 8].copy_from_slice(&t[i].to_le_bytes());
    }
    out
}

/// True if `p` has order dividing 8 (three doublings reach the identity).
fn ed25519_is_small_order(
    p: crate::curve25519::ed25519::EdwardsPoint,
    identity: &crate::curve25519::ed25519::EdwardsPoint,
) -> bool {
    let mut t = p + p;
    t = t + t;
    t = t + t;
    t.compress().0 == identity.compress().0
}

impl drv::Ed25519 for McuCryptoAsmDriver {
    fn public_key(k: &drv::Ed25519SecretKey) -> Result<drv::Ed25519PublicKey, drv::Error> {
        use crate::curve25519::ed25519::{Scalar, ED25519_BASEPOINT_POINT};

        let mut h = crate::sha512::sha512(&k.0);
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&h[..32]);
        ed25519_prune(&mut a_bytes);
        wipe(&mut h);
        let a = Scalar::from_bytes_mod_order(a_bytes);

        Ok(drv::Ed25519PublicKey(
            (a * ED25519_BASEPOINT_POINT).compress().0,
        ))
    }

    fn sign(k: &drv::Ed25519SecretKey, msg: &[u8]) -> Result<drv::Ed25519Signature, drv::Error> {
        use crate::curve25519::ed25519::{Scalar, ED25519_BASEPOINT_POINT};

        let mut h = crate::sha512::sha512(&k.0);
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&h[..32]);
        ed25519_prune(&mut a_bytes);
        let prefix: [u8; 32] = h[32..64].try_into().unwrap();
        wipe(&mut h);

        let a = Scalar::from_bytes_mod_order(a_bytes);
        let apk = (a * ED25519_BASEPOINT_POINT).compress().0;

        // r = H(prefix || msg) mod L (RFC 8032 section 5.1.6). Deterministic:
        // no random source is used.
        let mut hr = crate::sha512::Sha512::new();
        hr.update(&prefix);
        hr.update(msg);
        let r_hash = hr.finalize();
        let r = Scalar::from_bytes_mod_order_wide(&r_hash);

        let r_enc = (r * ED25519_BASEPOINT_POINT).compress().0;

        // k = H(R || A || msg) mod L.
        let mut hk = crate::sha512::Sha512::new();
        hk.update(&r_enc);
        hk.update(&apk);
        hk.update(msg);
        let k_hash = hk.finalize();
        let k = Scalar::from_bytes_mod_order_wide(&k_hash);

        // S = (r + k * a) mod L, via a 512-bit wide reduction.
        let s_wide = mul_add_256le(k.as_bytes(), &a_bytes, r.as_bytes());
        let s = Scalar::from_bytes_mod_order_wide(&s_wide);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_enc);
        sig[32..].copy_from_slice(s.as_bytes());
        Ok(drv::Ed25519Signature(sig))
    }

    fn verify(
        a: &drv::Ed25519PublicKey,
        msg: &[u8],
        sig: &drv::Ed25519Signature,
    ) -> Result<(), drv::Error> {
        use crate::curve25519::ed25519::{CompressedEdwardsY, Scalar, ED25519_BASEPOINT_POINT};

        // An undecodable public key is `InvalidKey`; every other failure mode
        // (bad R encoding, S not canonical per RFC 8032 section 8.4, or a
        // verification mismatch) is `InvalidSignature`.
        let a_pt = CompressedEdwardsY(a.0)
            .decompress()
            .ok_or(drv::Error::InvalidKey)?;
        let r_bytes: [u8; 32] = sig.0[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = sig.0[32..].try_into().unwrap();
        let r_pt = CompressedEdwardsY(r_bytes)
            .decompress()
            .ok_or(drv::Error::InvalidSignature)?;
        // Strict verification (RFC 8032 section 8.4 / Wycheproof): reject
        // small-order public keys and R values before the equation check.
        let identity = r_pt + (-r_pt);
        if ed25519_is_small_order(a_pt, &identity) {
            return Err(drv::Error::InvalidKey);
        }
        if ed25519_is_small_order(r_pt, &identity) {
            return Err(drv::Error::InvalidSignature);
        }
        let s = Scalar::from_canonical_bytes(s_bytes).ok_or(drv::Error::InvalidSignature)?;

        let mut hk = crate::sha512::Sha512::new();
        hk.update(&r_bytes);
        hk.update(&a.0);
        hk.update(msg);
        let k_hash = hk.finalize();
        let k = Scalar::from_bytes_mod_order_wide(&k_hash);

        // [S]B == R + [k]A. Only public data; may be variable-time. Edwards
        // points are compared by their canonical compressed encoding: the
        // derived PartialEq compares raw projective coordinates, which differ
        // for equal points in different (X, Y, Z, T) representations.
        if (s * ED25519_BASEPOINT_POINT).compress().0 == (r_pt + k * a_pt).compress().0 {
            Ok(())
        } else {
            Err(drv::Error::InvalidSignature)
        }
    }
}

reg::ed25519_impl!(McuCryptoAsmDriver);

// ---------------------------------------------------------------------------
// AES ECB / CBC, including the raw inverse cipher (FIPS 197)
// ---------------------------------------------------------------------------

/// GF(2^8) multiply by x (reduction polynomial x^8 + x^4 + x^3 + x + 1).
fn aes_xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1B)
}

/// GF(2^8) multiply (Russian peasant).
fn aes_gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = aes_xtime(a);
        b >>= 1;
    }
    p
}

/// Derive the AES S-box and inverse S-box (FIPS 197 section 5.1.1): the
/// multiplicative inverse in GF(2^8) followed by the affine transform, with
/// the inverse table as the elementwise inverse permutation. Computed per
/// call site so the driver contexts only store the round keys.
fn aes_sboxes() -> ([u8; 256], [u8; 256]) {
    // exp/log tables for GF(2^8) with generator 3.
    let mut exp = [0u8; 255];
    let mut log = [0u8; 256];
    let mut x = 1u8;
    for i in 0..255 {
        exp[i] = x;
        log[x as usize] = i as u8;
        x = aes_gmul(x, 3);
    }

    let mut sbox = [0u8; 256];
    let mut isbox = [0u8; 256];
    for a in 0..256usize {
        let inv = if a == 0 {
            0
        } else {
            exp[(255 - log[a] as usize) % 255]
        };
        // Affine transform: b = inv ^ rotl(inv,1) ^ ... ^ rotl(inv,4) ^ 0x63.
        let mut b = inv;
        let mut t = inv;
        for _ in 0..4 {
            t = (t << 1) | (t >> 7);
            b ^= t;
        }
        b ^= 0x63;
        sbox[a] = b;
        isbox[b as usize] = a as u8;
    }
    (sbox, isbox)
}

/// FIPS 197 key expansion. `rk` must be `16 * (ROUNDS + 1)` bytes; `NK` is
/// the key length in 32-bit words (4 or 8).
fn aes_expand_key<const NK: usize, const ROUNDS: usize>(
    key: &[u8],
    rk: &mut [u8],
    sbox: &[u8; 256],
) {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    rk[..NK * 4].copy_from_slice(&key[..NK * 4]);
    let mut bytes = NK * 4;
    let mut rcon = 0usize;
    let mut temp = [0u8; 4];
    while bytes < 16 * (ROUNDS + 1) {
        temp.copy_from_slice(&rk[bytes - 4..bytes]);
        if bytes % (NK * 4) == 0 {
            // RotWord, then SubWord, then the round constant.
            temp.rotate_left(1);
            for b in temp.iter_mut() {
                *b = sbox[*b as usize];
            }
            temp[0] ^= RCON[rcon];
            rcon += 1;
        } else if NK > 6 && bytes % (NK * 4) == 16 {
            for b in temp.iter_mut() {
                *b = sbox[*b as usize];
            }
        }
        for i in 0..4 {
            rk[bytes + i] = rk[bytes - NK * 4 + i] ^ temp[i];
        }
        bytes += 4;
    }
}

fn aes_add_round_key(block: &mut [u8; 16], rk: &[u8]) {
    for i in 0..16 {
        block[i] ^= rk[i];
    }
}

fn aes_sub_bytes(block: &mut [u8; 16], sbox: &[u8; 256]) {
    for b in block.iter_mut() {
        *b = sbox[*b as usize];
    }
}

fn aes_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    s[0] = t[0];
    s[4] = t[4];
    s[8] = t[8];
    s[12] = t[12];
    s[1] = t[5];
    s[5] = t[9];
    s[9] = t[13];
    s[13] = t[1];
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    s[3] = t[15];
    s[7] = t[3];
    s[11] = t[7];
    s[15] = t[11];
}

fn aes_inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    s[0] = t[0];
    s[4] = t[4];
    s[8] = t[8];
    s[12] = t[12];
    s[1] = t[13];
    s[5] = t[1];
    s[9] = t[5];
    s[13] = t[9];
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    s[3] = t[7];
    s[7] = t[11];
    s[11] = t[15];
    s[15] = t[3];
}

fn aes_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = aes_gmul(a0, 2) ^ aes_gmul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ aes_gmul(a1, 2) ^ aes_gmul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ aes_gmul(a2, 2) ^ aes_gmul(a3, 3);
        s[i + 3] = aes_gmul(a0, 3) ^ a1 ^ a2 ^ aes_gmul(a3, 2);
    }
}

fn aes_inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = aes_gmul(a0, 14) ^ aes_gmul(a1, 11) ^ aes_gmul(a2, 13) ^ aes_gmul(a3, 9);
        s[i + 1] = aes_gmul(a0, 9) ^ aes_gmul(a1, 14) ^ aes_gmul(a2, 11) ^ aes_gmul(a3, 13);
        s[i + 2] = aes_gmul(a0, 13) ^ aes_gmul(a1, 9) ^ aes_gmul(a2, 14) ^ aes_gmul(a3, 11);
        s[i + 3] = aes_gmul(a0, 11) ^ aes_gmul(a1, 13) ^ aes_gmul(a2, 9) ^ aes_gmul(a3, 14);
    }
}

fn aes_encrypt_block(block: &mut [u8; 16], rk: &[u8], rounds: usize, sbox: &[u8; 256]) {
    aes_add_round_key(block, &rk[..16]);
    for r in 1..rounds {
        aes_sub_bytes(block, sbox);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, &rk[16 * r..16 * r + 16]);
    }
    aes_sub_bytes(block, sbox);
    aes_shift_rows(block);
    aes_add_round_key(block, &rk[16 * rounds..16 * rounds + 16]);
}

fn aes_decrypt_block(block: &mut [u8; 16], rk: &[u8], rounds: usize, isbox: &[u8; 256]) {
    aes_add_round_key(block, &rk[16 * rounds..16 * rounds + 16]);
    for r in (1..rounds).rev() {
        aes_inv_shift_rows(block);
        aes_sub_bytes(block, isbox);
        aes_add_round_key(block, &rk[16 * r..16 * r + 16]);
        aes_inv_mix_columns(block);
    }
    aes_inv_shift_rows(block);
    aes_sub_bytes(block, isbox);
    aes_add_round_key(block, &rk[..16]);
}

macro_rules! impl_ecb {
    ($trait:ident, $reg_macro:ident, $ctx:ident, $key_len:expr, $nk:expr, $rounds:expr, $rk_len:expr) => {
        /// Conventional FIPS 197 round keys only, so the context fits the
        /// driver's opaque storage.
        #[derive(Clone)]
        pub struct $ctx {
            rk: [u8; $rk_len],
        }

        impl drv::$trait for McuCryptoAsmDriver {
            type Context = $ctx;

            fn init(key: &[u8; $key_len]) -> Self::Context {
                let (sbox, _) = aes_sboxes();
                let mut rk = [0u8; $rk_len];
                aes_expand_key::<$nk, $rounds>(key, &mut rk, &sbox);
                $ctx { rk }
            }

            fn encrypt_blocks(ctx: &Self::Context, blocks: drv::InOutBuf<'_, '_, u8>) {
                let (sbox, _) = aes_sboxes();
                let buf = blocks.into_out_with_copied_in();
                for chunk in buf.chunks_exact_mut(16) {
                    let b: &mut [u8; 16] = chunk.try_into().unwrap();
                    aes_encrypt_block(b, &ctx.rk, $rounds, &sbox);
                }
            }

            fn decrypt_blocks(ctx: &Self::Context, blocks: drv::InOutBuf<'_, '_, u8>) {
                let (_, isbox) = aes_sboxes();
                let buf = blocks.into_out_with_copied_in();
                for chunk in buf.chunks_exact_mut(16) {
                    let b: &mut [u8; 16] = chunk.try_into().unwrap();
                    aes_decrypt_block(b, &ctx.rk, $rounds, &isbox);
                }
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

macro_rules! impl_cbc {
    ($trait:ident, $reg_macro:ident, $ctx:ident, $key_len:expr, $nk:expr, $rounds:expr, $rk_len:expr) => {
        /// Conventional FIPS 197 round keys plus the CBC chaining value.
        #[derive(Clone)]
        pub struct $ctx {
            rk: [u8; $rk_len],
            iv: [u8; 16],
        }

        impl drv::$trait for McuCryptoAsmDriver {
            type EncryptContext = $ctx;
            type DecryptContext = $ctx;

            fn encrypt_init(key: &[u8; $key_len], iv: &[u8; 16]) -> Self::EncryptContext {
                let (sbox, _) = aes_sboxes();
                let mut rk = [0u8; $rk_len];
                aes_expand_key::<$nk, $rounds>(key, &mut rk, &sbox);
                $ctx { rk, iv: *iv }
            }

            fn decrypt_init(key: &[u8; $key_len], iv: &[u8; 16]) -> Self::DecryptContext {
                Self::encrypt_init(key, iv)
            }

            fn encrypt_blocks(ctx: &mut Self::EncryptContext, blocks: drv::InOutBuf<'_, '_, u8>) {
                let (sbox, _) = aes_sboxes();
                let buf = blocks.into_out_with_copied_in();
                let mut prev = ctx.iv;
                for chunk in buf.chunks_exact_mut(16) {
                    let b: &mut [u8; 16] = chunk.try_into().unwrap();
                    for i in 0..16 {
                        b[i] ^= prev[i];
                    }
                    aes_encrypt_block(b, &ctx.rk, $rounds, &sbox);
                    prev = *b;
                }
                ctx.iv = prev;
            }

            fn decrypt_blocks(ctx: &mut Self::DecryptContext, blocks: drv::InOutBuf<'_, '_, u8>) {
                let (_, isbox) = aes_sboxes();
                let buf = blocks.into_out_with_copied_in();
                let mut prev = ctx.iv;
                for chunk in buf.chunks_exact_mut(16) {
                    let b: &mut [u8; 16] = chunk.try_into().unwrap();
                    let ct = *b;
                    aes_decrypt_block(b, &ctx.rk, $rounds, &isbox);
                    for i in 0..16 {
                        b[i] ^= prev[i];
                    }
                    prev = ct;
                }
                ctx.iv = prev;
            }
        }

        reg::$reg_macro!(McuCryptoAsmDriver);
    };
}

impl_ecb!(Aes128Ecb, aes128_ecb_impl, Aes128EcbContext, 16, 4, 10, 176);
impl_ecb!(Aes256Ecb, aes256_ecb_impl, Aes256EcbContext, 32, 8, 14, 240);
impl_cbc!(Aes128Cbc, aes128_cbc_impl, Aes128CbcContext, 16, 4, 10, 176);
impl_cbc!(Aes256Cbc, aes256_cbc_impl, Aes256CbcContext, 32, 8, 14, 240);

// ---------------------------------------------------------------------------
// SHA-512 family (FIPS 180-4)
// ---------------------------------------------------------------------------
//
// The crate's compression function backs all four SHA-512 variants; /224 and
// /256 differ only in their initialization vectors and output truncation.

/// IV of SHA-512/224 (FIPS 180-4 section 5.3.6.2).
const SHA512_224_IV: [u64; 8] = [
    0x8C3D37C819544DA2,
    0x73E1996689DCD4D6,
    0x1DFAB7AE32FF9C82,
    0x679DD514582F9FCF,
    0x0F6D2B697BD44DA8,
    0x77E36F7304C48942,
    0x3F9D85A86A1D36C8,
    0x1112E6AD91D692A1,
];

/// IV of SHA-512/256 (FIPS 180-4 section 5.3.6.3).
const SHA512_256_IV: [u64; 8] = [
    0x22312194FC2BF72C,
    0x9F555FA3C84C64C2,
    0x2393B86B6F53B151,
    0x963877195940EABD,
    0x96283EE2A88EFFE3,
    0xBE5E1E2553863992,
    0x2B0199FC2C85B8AA,
    0x0EB72DDC81C52CA2,
];

/// Streaming SHA-512 core with a configurable IV.
#[derive(Clone, Copy)]
pub struct Sha512Core {
    state: [u64; 8],
    buffer: [u8; 128],
    buf_len: usize,
    total_len: u128,
}

impl Sha512Core {
    const BLOCK: usize = 128;

    fn new(iv: [u64; 8]) -> Self {
        Self {
            state: iv,
            buffer: [0u8; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);
        if self.buf_len > 0 {
            let n = core::cmp::min(Self::BLOCK - self.buf_len, data.len());
            self.buffer[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
            if self.buf_len == Self::BLOCK {
                let blk = self.buffer;
                crate::sha512::compress_blocks(&mut self.state, &blk);
                self.buf_len = 0;
            }
        }
        let mut chunks = data.chunks_exact(Self::BLOCK);
        for blk in &mut chunks {
            crate::sha512::compress_blocks(&mut self.state, blk);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buffer[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != Self::BLOCK - 16 {
            self.update(&[0]);
        }
        self.buffer[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let blk = self.buffer;
        crate::sha512::compress_blocks(&mut self.state, &blk);
        let mut out = [0u8; 64];
        for i in 0..8 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

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

impl_sha512_family!(Sha512, sha512_impl, 64, crate::sha512::SHA512_IV);
impl_sha512_family!(Sha384, sha384_impl, 48, crate::sha512::SHA384_IV);
impl_sha512_family!(Sha512_224, sha512_224_impl, 28, SHA512_224_IV);
impl_sha512_family!(Sha512_256, sha512_256_impl, 32, SHA512_256_IV);

/// HMAC over any member of the SHA-512 family (RFC 2104; 128-byte block).
#[derive(Clone)]
pub struct HmacSha512Family {
    inner: Sha512Core,
    opad: [u8; 128],
    /// Full digest length of this SHA-512 variant (64/48/28/32). HMAC feeds
    /// the inner hash's truncated output to the outer hash.
    out_len: usize,
}

impl HmacSha512Family {
    fn new(iv: [u64; 8], key: &[u8], out_len: usize) -> Self {
        let mut kblock = [0u8; 128];
        if key.len() > 128 {
            let mut h = Sha512Core::new(iv);
            h.update(key);
            let digest = h.finalize();
            kblock[..out_len].copy_from_slice(&digest[..out_len]);
        } else {
            kblock[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0u8; 128];
        let mut opad = [0u8; 128];
        for i in 0..128 {
            ipad[i] = kblock[i] ^ 0x36;
            opad[i] = kblock[i] ^ 0x5C;
        }
        wipe(&mut kblock);

        let mut inner = Sha512Core::new(iv);
        inner.update(&ipad);
        wipe(&mut ipad);
        Self {
            inner,
            opad,
            out_len,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self, iv: [u64; 8]) -> [u8; 64] {
        let inner_digest = self.inner.finalize();
        let mut outer = Sha512Core::new(iv);
        outer.update(&self.opad);
        outer.update(&inner_digest[..self.out_len]);
        outer.finalize()
    }
}

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

impl_hmac_sha512_family!(HmacSha512, hmac_sha512_impl, 64, crate::sha512::SHA512_IV);
impl_hmac_sha512_family!(HmacSha384, hmac_sha384_impl, 48, crate::sha512::SHA384_IV);
impl_hmac_sha512_family!(HmacSha512_224, hmac_sha512_224_impl, 28, SHA512_224_IV);
impl_hmac_sha512_family!(HmacSha512_256, hmac_sha512_256_impl, 32, SHA512_256_IV);
