//! Field element in Montgomery form.
//!
//! `Fe<N>` is a thin, `Copy` wrapper over `[u32; N]`. All arithmetic goes
//! through [`crate::backend`], which picks assembly or the portable reference
//! at compile time.

use crate::backend;

/// Parameters describing a prime field.
///
/// Held by reference rather than baked into the type so that one code path
/// serves both curves; the limb count is still a compile-time constant on the
/// element type, so the compiler fully specialises each curve.
#[derive(Clone, Copy)]
pub struct Params {
    /// Limb count.
    pub n: usize,
    /// Modulus, little-endian 32-bit limbs.
    pub p: &'static [u32],
    /// `-p^-1 mod 2^32`.
    pub n0inv: u32,
    /// `R^2 mod p`, for conversion into Montgomery form.
    pub r2: &'static [u32],
    /// `R mod p` — the Montgomery representation of 1.
    pub one: &'static [u32],
}

/// A field element in Montgomery form: stores `x * R mod p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fe<const N: usize> {
    pub(crate) v: [u32; N],
}

impl<const N: usize> Fe<N> {
    /// Zero.
    pub const ZERO: Self = Self { v: [0u32; N] };

    /// Wrap limbs that are *already* in Montgomery form.
    #[inline]
    pub const fn from_mont_limbs(v: [u32; N]) -> Self {
        Self { v }
    }

    /// The raw Montgomery limbs.
    #[inline]
    pub const fn as_mont_limbs(&self) -> &[u32; N] {
        &self.v
    }

    /// Convert a plain integer `x < p` into Montgomery form: `x * R mod p`.
    ///
    /// Implemented as `mul_mont(x, R^2) = x * R^2 * R^-1 = x * R`.
    #[inline]
    pub fn from_int(f: &Params, limbs: &[u32; N]) -> Self {
        debug_assert_eq!(f.n, N);
        let mut out = [0u32; N];
        backend::mul_mont(limbs, f.r2, f.p, f.n0inv, &mut out);
        Self { v: out }
    }

    /// Convert back to a plain integer.
    ///
    /// Implemented as `mul_mont(x*R, 1) = x*R*1*R^-1 = x`.
    #[inline]
    pub fn to_int(&self, f: &Params) -> [u32; N] {
        debug_assert_eq!(f.n, N);
        let mut one = [0u32; N];
        one[0] = 1;
        let mut out = [0u32; N];
        backend::mul_mont(&self.v, &one, f.p, f.n0inv, &mut out);
        out
    }

    /// `self * rhs mod p` (Montgomery form in, Montgomery form out).
    #[inline]
    pub fn mul(&self, f: &Params, rhs: &Self) -> Self {
        let mut out = [0u32; N];
        backend::mul_mont(&self.v, &rhs.v, f.p, f.n0inv, &mut out);
        Self { v: out }
    }

    /// `self^2 mod p`.
    #[inline]
    pub fn sqr(&self, f: &Params) -> Self {
        let mut out = [0u32; N];
        backend::sqr_mont(&self.v, f.p, f.n0inv, &mut out);
        Self { v: out }
    }

    /// `self + rhs mod p`.
    #[inline]
    pub fn add(&self, f: &Params, rhs: &Self) -> Self {
        let mut out = [0u32; N];
        backend::add_mod(&self.v, &rhs.v, f.p, &mut out);
        Self { v: out }
    }

    /// `self - rhs mod p`.
    #[inline]
    pub fn sub(&self, f: &Params, rhs: &Self) -> Self {
        let mut out = [0u32; N];
        backend::sub_mod(&self.v, &rhs.v, f.p, &mut out);
        Self { v: out }
    }

    /// Modular inverse, `self^(p-2) mod p` (Fermat's little theorem).
    ///
    /// Returns zero for a zero input, which has no inverse — callers that care
    /// must check separately.
    ///
    /// Constant time **with respect to `self`**: the exponent is `p - 2`, a
    /// public compile-time constant, so branching on its bits leaks nothing
    /// about the value being inverted. Every squaring and multiplication is
    /// itself constant time.
    ///
    /// A binary chain costs ~1.5·(32N) multiplications. An addition chain
    /// tuned per prime would be meaningfully faster; inversion happens once
    /// per scalar multiplication, so it is not the bottleneck yet.
    pub fn invert(&self, f: &Params) -> Self {
        debug_assert_eq!(f.n, N);

        // exp = p - 2. Both NIST primes have low word 0xFFFFFFFF, so this
        // cannot borrow past the first limb, but do it properly anyway.
        let mut exp = [0u32; N];
        let mut borrow = 2u32;
        for i in 0..N {
            let (v, b) = f.p[i].overflowing_sub(borrow);
            exp[i] = v;
            borrow = b as u32;
        }

        let mut result = Self::from_mont_limbs({
            let mut one = [0u32; N];
            one.copy_from_slice(f.one);
            one
        });

        // Square-and-multiply, most significant bit first.
        let mut started = false;
        for i in (0..N).rev() {
            for bit in (0..32).rev() {
                if started {
                    result = result.sqr(f);
                }
                if (exp[i] >> bit) & 1 == 1 {
                    result = if started { result.mul(f, self) } else { *self };
                    started = true;
                }
            }
        }
        result
    }

    /// Constant-time equality.
    #[inline]
    pub fn ct_eq(&self, rhs: &Self) -> bool {
        let mut acc = 0u32;
        for i in 0..N {
            acc |= self.v[i] ^ rhs.v[i];
        }
        acc == 0
    }

    /// Constant-time test for zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        let mut acc = 0u32;
        for i in 0..N {
            acc |= self.v[i];
        }
        acc == 0
    }
}
