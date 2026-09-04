//! Scalar field arithmetic modulo curve order `n`.
//!
//! Provides `Scalar<const N: usize>` representing elements in `Z / n Z`
//! stored in Montgomery form (`s * R mod n`).

use crate::backend;
use crate::CurveParams;

/// An error from a scalar operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A buffer was the wrong length.
    BadLength,
    /// A scalar was zero or >= n when a valid scalar was required.
    BadScalar,
}

/// A scalar element in Montgomery form: stores `s * R mod n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar<const N: usize> {
    pub(crate) v: [u32; N],
}

impl<const N: usize> Scalar<N> {
    /// Zero in Montgomery form is also 0.
    pub const ZERO: Self = Self { v: [0u32; N] };

    /// Wrap limbs that are already in Montgomery form.
    #[inline]
    pub const fn from_mont_limbs(v: [u32; N]) -> Self {
        Self { v }
    }

    /// The raw Montgomery limbs.
    #[inline]
    pub const fn as_mont_limbs(&self) -> &[u32; N] {
        &self.v
    }

    /// One in Montgomery form: `R mod n`.
    #[inline]
    pub fn one(c: &CurveParams) -> Self {
        let mut r = [0u32; N];
        r.copy_from_slice(c.order_r);
        Self { v: r }
    }

    /// Convert a plain integer `x < n` into Montgomery form: `x * R mod n`.
    #[inline]
    pub fn from_int(c: &CurveParams, limbs: &[u32; N]) -> Self {
        debug_assert_eq!(c.order.len(), N);
        let mut out = [0u32; N];
        backend::portable::mul_mont(limbs, c.order_r2, c.order, c.order_n0inv, &mut out);
        Self { v: out }
    }

    /// Convert from Montgomery form back to a plain integer `x < n`.
    #[inline]
    pub fn to_int(&self, c: &CurveParams) -> [u32; N] {
        let mut one = [0u32; N];
        one[0] = 1;
        let mut out = [0u32; N];
        backend::portable::mul_mont(&self.v, &one, c.order, c.order_n0inv, &mut out);
        out
    }

    /// Constant-time zero check.
    #[inline]
    pub fn is_zero(&self) -> bool {
        let mut acc = 0u32;
        for &w in &self.v {
            acc |= w;
        }
        acc == 0
    }

    /// Constant-time equality check.
    #[inline]
    pub fn ct_eq(&self, rhs: &Self) -> bool {
        let mut diff = 0u32;
        for i in 0..N {
            diff |= self.v[i] ^ rhs.v[i];
        }
        diff == 0
    }

    /// `out = self + rhs mod n`
    #[inline]
    pub fn add(&self, c: &CurveParams, rhs: &Self) -> Self {
        let mut out = [0u32; N];
        backend::portable::add_mod_n(&self.v, &rhs.v, c.order, &mut out);
        Self { v: out }
    }

    /// `out = self - rhs mod n`
    #[inline]
    pub fn sub(&self, c: &CurveParams, rhs: &Self) -> Self {
        let mut out = [0u32; N];
        backend::portable::sub_mod_n(&self.v, &rhs.v, c.order, &mut out);
        Self { v: out }
    }

    /// `out = -self mod n`
    #[inline]
    pub fn neg(&self, c: &CurveParams) -> Self {
        Self::ZERO.sub(c, self)
    }

    /// `out = self * rhs mod n`
    #[inline]
    pub fn mul(&self, c: &CurveParams, rhs: &Self) -> Self {
        let mut out = [0u32; N];
        backend::portable::mul_mont(&self.v, &rhs.v, c.order, c.order_n0inv, &mut out);
        Self { v: out }
    }

    /// `out = self^2 mod n`
    #[inline]
    pub fn sqr(&self, c: &CurveParams) -> Self {
        self.mul(c, self)
    }

    #[inline(always)]
    fn sqr_n(&self, c: &CurveParams, n: usize) -> Self {
        let mut res = *self;
        for _ in 0..n {
            res = res.sqr(c);
        }
        res
    }

    /// Multiplicative inverse `self^-1 mod n` via Fermat's Little Theorem:
    /// `self^(n-2) mod n`.
    ///
    /// Returns `None` if `self == 0`.
    pub fn invert(&self, c: &CurveParams) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        if N == 8 {
            let t1 = *self;
            let t2 = t1.sqr_n(c, 1).mul(c, &t1);
            let t3 = t2.sqr_n(c, 1).mul(c, &t1);
            let t6 = t3.sqr_n(c, 3).mul(c, &t3);
            let t12 = t6.sqr_n(c, 6).mul(c, &t6);
            let t15 = t12.sqr_n(c, 3).mul(c, &t3);
            let t30 = t15.sqr_n(c, 15).mul(c, &t15);
            let t32 = t30.sqr_n(c, 2).mul(c, &t2);
            let t64 = t32.sqr_n(c, 32).mul(c, &t32);

            let mut acc = t32;
            acc = acc.sqr_n(c, 32);
            acc = acc.sqr_n(c, 64).mul(c, &t64);

            let mut tbl = [*self; 16];
            for i in 2..16 {
                tbl[i] = tbl[i - 1].mul(c, self);
            }

            let low128 = [
                c.order[0].wrapping_sub(2),
                c.order[1],
                c.order[2],
                c.order[3],
            ];
            for nib in (0..32).rev() {
                acc = acc.sqr_n(c, 4);
                let d = ((low128[nib / 8] >> ((nib % 8) * 4)) & 0xF) as usize;
                if d != 0 {
                    acc = acc.mul(c, &tbl[d]);
                }
            }
            return Some(acc);
        }

        if N == 12 {
            let t1 = *self;
            let t2 = t1.sqr_n(c, 1).mul(c, &t1);
            let t3 = t2.sqr_n(c, 1).mul(c, &t1);
            let t6 = t3.sqr_n(c, 3).mul(c, &t3);
            let t12 = t6.sqr_n(c, 6).mul(c, &t6);
            let t24 = t12.sqr_n(c, 12).mul(c, &t12);
            let t48 = t24.sqr_n(c, 24).mul(c, &t24);
            let t96 = t48.sqr_n(c, 48).mul(c, &t48);
            let t192 = t96.sqr_n(c, 96).mul(c, &t96);

            let mut tbl = [*self; 16];
            for i in 2..16 {
                tbl[i] = tbl[i - 1].mul(c, self);
            }

            let mut acc = t192;
            let low192 = [
                c.order[0].wrapping_sub(2),
                c.order[1],
                c.order[2],
                c.order[3],
                c.order[4],
                c.order[5],
            ];
            for nib in (0..48).rev() {
                acc = acc.sqr_n(c, 4);
                let d = ((low192[nib / 8] >> ((nib % 8) * 4)) & 0xF) as usize;
                if d != 0 {
                    acc = acc.mul(c, &tbl[d]);
                }
            }
            return Some(acc);
        }

        // Exponent is (order - 2). Top bit of order is 1 (bit 255 for P-256, bit 383 for P-384).
        let mut acc = *self;
        let mut first = true;
        for i in (0..N).rev() {
            let word = if i == 0 {
                c.order[0].wrapping_sub(2)
            } else {
                c.order[i]
            };
            for bit in (0..32).rev() {
                if first {
                    first = false;
                    continue;
                }
                acc = acc.sqr(c);
                if (word >> bit) & 1 == 1 {
                    acc = acc.mul(c, self);
                }
            }
        }
        Some(acc)
    }

    /// Parse a big-endian byte slice of length `4 * N` into a `Scalar`.
    /// Rejects scalars that are not in `[0, n)`.
    pub fn from_be_bytes(c: &CurveParams, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 * N {
            return Err(Error::BadLength);
        }
        let mut limbs = [0u32; N];
        for (i, chunk) in bytes.rchunks(4).enumerate() {
            limbs[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        if !less_than(&limbs, c.order) {
            return Err(Error::BadScalar);
        }
        Ok(Self::from_int(c, &limbs))
    }

    /// Parse a non-zero scalar in `[1, n)`.
    pub fn from_be_bytes_nonzero(c: &CurveParams, bytes: &[u8]) -> Result<Self, Error> {
        let s = Self::from_be_bytes(c, bytes)?;
        if s.is_zero() {
            return Err(Error::BadScalar);
        }
        Ok(s)
    }

    /// Serialize this scalar to `4 * N` big-endian bytes.
    pub fn to_be_bytes(&self, c: &CurveParams, out: &mut [u8]) -> Result<(), Error> {
        if out.len() != 4 * N {
            return Err(Error::BadLength);
        }
        let limbs = self.to_int(c);
        for (i, chunk) in out.rchunks_mut(4).enumerate() {
            chunk.copy_from_slice(&limbs[i].to_be_bytes());
        }
        Ok(())
    }

    /// Ingest an arbitrary-length message hash and reduce it modulo `n`
    /// according to SEC1 / FIPS 186-4 Section B.2.1.
    ///
    /// If `bytes.len() > 4 * N`, truncates to the leftmost `4 * N` bytes.
    /// If `bytes.len() < 4 * N`, zero-pads on the left.
    /// The resulting integer is then reduced modulo `n`.
    pub fn from_be_bytes_reduce(c: &CurveParams, bytes: &[u8]) -> Self {
        let mut buf = [0u8; 64]; // Enough for up to 16 limbs (512 bits)
        let n_bytes = 4 * N;
        assert!(n_bytes <= buf.len());

        let slice = if bytes.len() >= n_bytes {
            &bytes[..n_bytes]
        } else {
            let offset = n_bytes - bytes.len();
            buf[offset..n_bytes].copy_from_slice(bytes);
            &buf[..n_bytes]
        };

        let mut limbs = [0u32; N];
        for (i, chunk) in slice.rchunks(4).enumerate() {
            limbs[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // If limbs >= order, subtract order once (since limbs < 2^(32*N) < 2*order).
        let mut diff = [0u32; N];
        let mut borrow = 0u32;
        for i in 0..N {
            let (r1, b1) = limbs[i].overflowing_sub(c.order[i]);
            let (r2, b2) = r1.overflowing_sub(borrow);
            diff[i] = r2;
            borrow = (b1 as u32) | (b2 as u32);
        }

        // If borrow == 0, limbs >= order, so select diff.
        // mask is all-ones when borrow == 0, and 0 when borrow == 1.
        let mask = borrow.wrapping_sub(1);
        let mask = core::hint::black_box(mask);
        for i in 0..N {
            limbs[i] = limbs[i] ^ ((limbs[i] ^ diff[i]) & mask);
        }

        Self::from_int(c, &limbs)
    }
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
