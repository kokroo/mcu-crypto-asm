//! ECDH over P-256 / P-384, shaped to match the `embassy-crypto-driver`
//! `P256Ecdh` unitrait (`derive_public_key` / `shared_secret`), so this can be
//! registered as a driver once that trait is restored upstream.
//!
//! Encoding is SEC1 uncompressed, big-endian: `0x04 || x || y`.
//!
//! # Validation is not optional
//!
//! [`shared_secret`] **rejects a peer point that is not on the curve.** Without
//! that check an attacker supplies a point on a different, weaker curve and
//! recovers the private key from a handful of exchanges (the invalid-curve
//! attack). Scalars are likewise required to be in `[1, n)`.

use crate::{CurveParams, Point};

/// Why an ECDH operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A buffer had the wrong length for the curve.
    BadLength,
    /// The scalar was zero or >= the group order.
    BadScalar,
    /// The peer's point was malformed, not on the curve, or the identity.
    BadPoint,
}

/// Big-endian bytes -> little-endian 32-bit limbs.
fn be_to_limbs<const N: usize>(bytes: &[u8], out: &mut [u32; N]) -> Result<(), Error> {
    if bytes.len() != N * 4 {
        return Err(Error::BadLength);
    }
    for i in 0..N {
        let off = (N - 1 - i) * 4;
        out[i] = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    }
    Ok(())
}

/// Little-endian 32-bit limbs -> big-endian bytes.
fn limbs_to_be<const N: usize>(limbs: &[u32; N], out: &mut [u8]) {
    for i in 0..N {
        let off = (N - 1 - i) * 4;
        out[off..off + 4].copy_from_slice(&limbs[i].to_be_bytes());
    }
}

/// Is `0 < k < order`? Constant time in `k`.
fn scalar_in_range<const N: usize>(k: &[u32; N], order: &[u32]) -> bool {
    let mut nonzero = 0u32;
    for v in k.iter() {
        nonzero |= *v;
    }
    // k < order, via a borrow-producing subtraction.
    let mut borrow = 0u32;
    for i in 0..N {
        let (r1, b1) = k[i].overflowing_sub(order[i]);
        let (_, b2) = r1.overflowing_sub(borrow);
        borrow = (b1 as u32) | (b2 as u32);
    }
    nonzero != 0 && borrow == 1
}

/// Public key from a private scalar: `pk = k * G`, SEC1 uncompressed.
///
/// `secret` is `4*N` big-endian bytes; `out` is `1 + 8*N`.
pub fn derive_public_key<const N: usize>(
    c: &CurveParams,
    secret: &[u8],
    out: &mut [u8],
    comb: &[([u32; N], [u32; N])],
    comb_d: usize,
    comb_t: usize,
) -> Result<(), Error> {
    if out.len() != 1 + 8 * N {
        return Err(Error::BadLength);
    }
    let mut k = [0u32; N];
    be_to_limbs(secret, &mut k)?;
    if !scalar_in_range(&k, c.order) {
        return Err(Error::BadScalar);
    }

    // Fixed base: use the comb table, ~2.6x less work than the general path.
    let p = Point::<N>::mul_base(c, &k, comb, comb_d, comb_t);
    let (x, y) = p.to_affine(&c.field).ok_or(Error::BadPoint)?;

    out[0] = 0x04;
    limbs_to_be(&x, &mut out[1..1 + 4 * N]);
    limbs_to_be(&y, &mut out[1 + 4 * N..]);
    Ok(())
}

/// Public key from a private scalar: `pk = k * G`, SEC1 compressed (0x02/0x03 || x).
///
/// `secret` is `4*N` big-endian bytes; `out` is `1 + 4*N`.
pub fn derive_public_key_compressed<const N: usize>(
    c: &CurveParams,
    secret: &[u8],
    out: &mut [u8],
    comb: &[([u32; N], [u32; N])],
    comb_d: usize,
    comb_t: usize,
) -> Result<(), Error> {
    if out.len() != 1 + 4 * N {
        return Err(Error::BadLength);
    }
    let mut k = [0u32; N];
    be_to_limbs(secret, &mut k)?;
    if !scalar_in_range(&k, c.order) {
        return Err(Error::BadScalar);
    }

    let p = Point::<N>::mul_base(c, &k, comb, comb_d, comb_t);
    let (x, y) = p.to_affine(&c.field).ok_or(Error::BadPoint)?;

    out[0] = if (y[0] & 1) == 1 { 0x03 } else { 0x02 };
    limbs_to_be(&x, &mut out[1..1 + 4 * N]);
    Ok(())
}

#[inline]
fn parse_peer_point<const N: usize>(c: &CurveParams, peer: &[u8]) -> Result<Point<N>, Error> {
    Point::decode(c, peer)
}

/// ECDH shared secret: the x-coordinate of `k * peer`.
///
/// Accepts both uncompressed (`0x04 || x || y`) and compressed (`0x02/0x03 || x`)
/// peer public keys. Rejects peer points that are not on the curve.
pub fn shared_secret<const N: usize>(
    c: &CurveParams,
    secret: &[u8],
    peer: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    #[cfg(nistp_asm_cm4)]
    {
        if N == 8 && core::ptr::eq(c.order.as_ptr(), crate::params::p256::ORDER.as_ptr()) {
            return crate::backend::cortex_m4::p256::ecdh_shared_secret(secret, peer, out);
        }
    }
    if out.len() != 4 * N {
        return Err(Error::BadLength);
    }
    let mut k = [0u32; N];
    be_to_limbs(secret, &mut k)?;
    if !scalar_in_range(&k, c.order) {
        return Err(Error::BadScalar);
    }

    let peer_point: Point<N> = parse_peer_point(c, peer)?;
    let shared = peer_point.mul_scalar(c, &k);
    let (sx, _) = shared.to_affine(&c.field).ok_or(Error::BadPoint)?;
    limbs_to_be(&sx, out);
    Ok(())
}
