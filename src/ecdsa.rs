//! ECDSA (Elliptic Curve Digital Signature Algorithm) for P-256 and P-384.
//!
//! Provides constant-time signature generation and verification following
//! SEC 1 v2.0 and FIPS 186-4.
//!
//! Verification uses fast projective verification without field inversion,
//! checking `r * Z == X (mod p)` in a single Montgomery multiplication.
#![allow(clippy::too_many_arguments)]

use crate::scalar::Scalar;
use crate::{CurveParams, Fe, Point, PointJacobian};

/// An error from an ECDSA operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A buffer was the wrong length.
    BadLength,
    /// A private key or nonce was zero or >= n.
    BadScalar,
    /// A public key point was invalid or not on the curve.
    BadPoint,
    /// Signature verification failed (r or s out of range, or signature invalid).
    BadSignature,
}

/// Verify an ECDSA signature `(r, s)` against a public key `pk` and message hash `msg_hash`.
///
/// Accepts uncompressed (`0x04 || x || y`) and compressed (`0x02/0x03 || x`) public keys.
/// Rejects signatures with `r, s ∉ [1, n-1]`.
pub fn verify<const N: usize>(
    c: &CurveParams,
    pk: &[u8],
    msg_hash: &[u8],
    r: &[u8],
    s: &[u8],
    comb: &[([u32; N], [u32; N])],
    comb_d: usize,
    comb_t: usize,
) -> Result<(), Error> {
    if r.len() != 4 * N || s.len() != 4 * N {
        return Err(Error::BadLength);
    }
    let r_scalar = Scalar::<N>::from_be_bytes_nonzero(c, r).map_err(|_| Error::BadSignature)?;
    let s_scalar = Scalar::<N>::from_be_bytes_nonzero(c, s).map_err(|_| Error::BadSignature)?;

    let q = Point::<N>::decode(c, pk).map_err(|e| match e {
        crate::ecdh::Error::BadLength => Error::BadLength,
        _ => Error::BadPoint,
    })?;

    let w = s_scalar.invert(c).ok_or(Error::BadSignature)?;
    let z = Scalar::<N>::from_be_bytes_reduce(c, msg_hash);
    let u1 = z.mul(c, &w);
    let u2 = r_scalar.mul(c, &w);

    let u1_limbs = u1.to_int(c);
    let u2_limbs = u2.to_int(c);

    let q_j = PointJacobian::<N>::from_affine(&q.x, &q.y, &c.field);
    let u1_g_proj = Point::<N>::mul_base(c, &u1_limbs, comb, comb_d, comb_t);
    let u1_g = PointJacobian::<N>::from_projective(&u1_g_proj, &c.field);
    let u2_q = q_j.mul_scalar(c, &u2_limbs);
    let r_pt = u1_g.add(c, &u2_q);

    if r_pt.is_identity() {
        return Err(Error::BadSignature);
    }

    // Fast Jacobian verification: check r * Z^2 == X mod p
    let z2 = r_pt.z.sqr(&c.field);
    let r_limbs = r_scalar.to_int(c);
    let r_fe = Fe::<N>::from_int(&c.field, &r_limbs);
    let lhs1 = r_fe.mul(&c.field, &z2);
    if lhs1.ct_eq(&r_pt.x) {
        return Ok(());
    }

    // In the rare case that r + n < p, check (r + n) * Z^2 == X mod p
    let mut r_plus_n = [0u32; N];
    let mut carry = 0u32;
    for i in 0..N {
        let (v1, c1) = r_limbs[i].overflowing_add(c.order[i]);
        let (v2, c2) = v1.overflowing_add(carry);
        r_plus_n[i] = v2;
        carry = (c1 as u32) | (c2 as u32);
    }

    if carry == 0 && less_than(&r_plus_n, c.field.p) {
        let r2_fe = Fe::<N>::from_int(&c.field, &r_plus_n);
        let lhs2 = r2_fe.mul(&c.field, &z2);
        if lhs2.ct_eq(&r_pt.x) {
            return Ok(());
        }
    }

    Err(Error::BadSignature)
}

/// Sign a message hash `msg_hash` with private key `sk` and nonce `k_nonce`.
///
/// Returns signature components `(out_r, out_s)` as `4 * N` big-endian bytes each.
pub fn sign<const N: usize>(
    c: &CurveParams,
    sk: &[u8],
    msg_hash: &[u8],
    k_nonce: &[u8],
    comb: &[([u32; N], [u32; N])],
    comb_d: usize,
    comb_t: usize,
    out_r: &mut [u8],
    out_s: &mut [u8],
) -> Result<(), Error> {
    if sk.len() != 4 * N || k_nonce.len() != 4 * N || out_r.len() != 4 * N || out_s.len() != 4 * N {
        return Err(Error::BadLength);
    }
    let d = Scalar::<N>::from_be_bytes_nonzero(c, sk).map_err(|_| Error::BadScalar)?;
    let k = Scalar::<N>::from_be_bytes_nonzero(c, k_nonce).map_err(|_| Error::BadScalar)?;

    let k_limbs = k.to_int(c);
    let r_pt = Point::<N>::mul_base(c, &k_limbs, comb, comb_d, comb_t);
    let (rx, _) = r_pt.to_affine(&c.field).ok_or(Error::BadPoint)?;

    // r = rx mod n
    // Since rx < p < 2n, if rx >= n, subtract n.
    let mut r_limbs = rx;
    let mut diff = [0u32; N];
    let mut borrow = 0u32;
    for i in 0..N {
        let (r1, b1) = r_limbs[i].overflowing_sub(c.order[i]);
        let (r2, b2) = r1.overflowing_sub(borrow);
        diff[i] = r2;
        borrow = (b1 as u32) | (b2 as u32);
    }
    let mask = borrow.wrapping_sub(1);
    let mask = core::hint::black_box(mask);
    for i in 0..N {
        r_limbs[i] = r_limbs[i] ^ ((r_limbs[i] ^ diff[i]) & mask);
    }

    let r_scalar = Scalar::<N>::from_int(c, &r_limbs);
    if r_scalar.is_zero() {
        return Err(Error::BadScalar);
    }

    // s = k^-1 * (z + r * d) mod n
    let k_inv = k.invert(c).ok_or(Error::BadScalar)?;
    let z = Scalar::<N>::from_be_bytes_reduce(c, msg_hash);
    let rd = r_scalar.mul(c, &d);
    let z_plus_rd = z.add(c, &rd);
    let s_scalar = k_inv.mul(c, &z_plus_rd);

    if s_scalar.is_zero() {
        return Err(Error::BadScalar);
    }

    r_scalar
        .to_be_bytes(c, out_r)
        .map_err(|_| Error::BadLength)?;
    s_scalar
        .to_be_bytes(c, out_s)
        .map_err(|_| Error::BadLength)?;
    Ok(())
}



fn less_than<const N: usize>(a: &[u32; N], b: &[u32]) -> bool {
    let mut borrow = 0u32;
    for i in 0..N {
        let (r1, b1) = a[i].overflowing_sub(b[i]);
        let (_, b2) = r1.overflowing_sub(borrow);
        borrow = (b1 as u32) | (b2 as u32);
    }
    borrow == 1
}
