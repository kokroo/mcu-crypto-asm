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

use crate::{mul_scalar_yielding, CurveParams, Fe, Point};


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
        out[i] = u32::from_be_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
        ]);
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

/// Is `(x, y)` on `y^2 = x^3 - 3x + b`?
fn on_curve<const N: usize>(c: &CurveParams, x: &Fe<N>, y: &Fe<N>) -> bool {
    let f = &c.field;
    let mut b = [0u32; N];
    b.copy_from_slice(c.b_mont);
    let b = Fe::<N>::from_mont_limbs(b);

    let lhs = y.sqr(f); // y^2
    let x3 = x.sqr(f).mul(f, x); // x^3
    let three_x = x.add(f, x).add(f, x); // 3x
    let rhs = x3.sub(f, &three_x).add(f, &b); // x^3 - 3x + b
    lhs.ct_eq(&rhs)
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
    let p = Point::<N>::mul_base(c, &k, comb, comb_d);
    let (x, y) = p.to_affine(&c.field).ok_or(Error::BadPoint)?;

    out[0] = 0x04;
    limbs_to_be(&x, &mut out[1..1 + 4 * N]);
    limbs_to_be(&y, &mut out[1 + 4 * N..]);
    Ok(())
}

/// ECDH shared secret: the x-coordinate of `k * peer`.
///
/// Rejects peer points that are not on the curve — see the module note.
pub fn shared_secret<const N: usize>(
    c: &CurveParams,
    secret: &[u8],
    peer: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    if peer.len() != 1 + 8 * N || out.len() != 4 * N {
        return Err(Error::BadLength);
    }
    if peer[0] != 0x04 {
        return Err(Error::BadPoint); // only uncompressed is accepted
    }

    let mut k = [0u32; N];
    be_to_limbs(secret, &mut k)?;
    if !scalar_in_range(&k, c.order) {
        return Err(Error::BadScalar);
    }

    let mut xi = [0u32; N];
    let mut yi = [0u32; N];
    be_to_limbs(&peer[1..1 + 4 * N], &mut xi)?;
    be_to_limbs(&peer[1 + 4 * N..], &mut yi)?;

    // Coordinates must be reduced field elements; from_int would silently
    // accept x >= p, so check before converting.
    if !less_than(&xi, c.field.p) || !less_than(&yi, c.field.p) {
        return Err(Error::BadPoint);
    }

    let x = Fe::<N>::from_int(&c.field, &xi);
    let y = Fe::<N>::from_int(&c.field, &yi);
    if !on_curve(c, &x, &y) {
        return Err(Error::BadPoint);
    }

    let mut one = [0u32; N];
    one.copy_from_slice(c.field.one);
    let peer_point = Point {
        x,
        y,
        z: Fe::from_mont_limbs(one),
    };

    let shared = peer_point.mul_scalar(c, &k);
    let (sx, _) = shared.to_affine(&c.field).ok_or(Error::BadPoint)?;
    limbs_to_be(&sx, out);
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


// ---------------------------------------------------------------------------
// Yielding variants
// ---------------------------------------------------------------------------
//
// Identical maths, but the scalar multiplication is interleaved with the rest
// of the system instead of held for 100 ms (P-256) or 285 ms (P-384). See
// `crate::scalar_mul` for what `budget` buys you.

/// [`derive_public_key`], yielding every `budget` point operations.
pub async fn derive_public_key_yielding<const N: usize>(
    c: &CurveParams,
    secret: &[u8],
    out: &mut [u8],
    comb: &'static [([u32; N], [u32; N])],
    comb_d: usize,
    budget: u32,
) -> Result<(), Error> {
    if out.len() != 1 + 8 * N {
        return Err(Error::BadLength);
    }
    let mut k = [0u32; N];
    be_to_limbs(secret, &mut k)?;
    if !scalar_in_range(&k, c.order) {
        return Err(Error::BadScalar);
    }
    let p = crate::mul_base_yielding(c, &k, comb, comb_d, budget).await;
    let (x, y) = p.to_affine(&c.field).ok_or(Error::BadPoint)?;
    out[0] = 0x04;
    limbs_to_be(&x, &mut out[1..1 + 4 * N]);
    limbs_to_be(&y, &mut out[1 + 4 * N..]);
    Ok(())
}

/// [`shared_secret`], yielding every `budget` point operations.
///
/// Validation happens up front, before any yielding, so a hostile peer point
/// is rejected immediately rather than after a partial computation.
pub async fn shared_secret_yielding<const N: usize>(
    c: &CurveParams,
    secret: &[u8],
    peer: &[u8],
    out: &mut [u8],
    budget: u32,
) -> Result<(), Error> {
    if peer.len() != 1 + 8 * N || out.len() != 4 * N {
        return Err(Error::BadLength);
    }
    if peer[0] != 0x04 {
        return Err(Error::BadPoint);
    }
    let mut k = [0u32; N];
    be_to_limbs(secret, &mut k)?;
    if !scalar_in_range(&k, c.order) {
        return Err(Error::BadScalar);
    }
    let mut xi = [0u32; N];
    let mut yi = [0u32; N];
    be_to_limbs(&peer[1..1 + 4 * N], &mut xi)?;
    be_to_limbs(&peer[1 + 4 * N..], &mut yi)?;
    if !less_than(&xi, c.field.p) || !less_than(&yi, c.field.p) {
        return Err(Error::BadPoint);
    }
    let x = Fe::<N>::from_int(&c.field, &xi);
    let y = Fe::<N>::from_int(&c.field, &yi);
    if !on_curve(c, &x, &y) {
        return Err(Error::BadPoint);
    }
    let mut one = [0u32; N];
    one.copy_from_slice(c.field.one);
    let peer_point = Point {
        x,
        y,
        z: Fe::from_mont_limbs(one),
    };
    let shared = mul_scalar_yielding(c, &peer_point, &k, budget).await;
    let (sx, _) = shared.to_affine(&c.field).ok_or(Error::BadPoint)?;
    limbs_to_be(&sx, out);
    Ok(())
}
