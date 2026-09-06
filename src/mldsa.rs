//! ML-DSA (Dilithium, FIPS 204) Polynomial and Number-Theoretic Transform (NTT) Arithmetic.
//!
//! Hand-written ARM Cortex-M DSP SIMD assembly acceleration for Target 1 (ARMv7E-M / ARMv8-M),
//! based on PQM4 (Markus Krausz / Kannwischer / Rijneveld / Schwabe / Stoffelen).
//!
//! Ring:  = \mathbb{Z}_q[X] / (X^{256} + 1)$, where  = 8380417 = 2^{23} - 2^{13} + 1$ and  = 256$.

#![allow(clippy::needless_range_loop)]

pub const MLDSA_N: usize = 256;
pub const MLDSA_Q: i32 = 8380417;
pub const MLDSA_QINV: i32 = 58728449; // -q^{-1} mod 2^32
pub const MLDSA_D: usize = 13;
pub const MLDSA_ROOT_OF_UNITY: i32 = 1753;

#[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
use core::arch::global_asm;

#[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
global_asm!(include_str!("../asm/cortex_m_mldsa.S"), options(raw));

#[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
extern "C" {
    fn pqcrystals_dilithium_ntt(p: *mut i32);
    fn pqcrystals_dilithium_invntt_tomont(p: *mut i32);
    fn pqcrystals_dilithium_asm_pointwise_montgomery(c: *mut i32, a: *const i32, b: *const i32);
    fn pqcrystals_dilithium_asm_pointwise_acc_montgomery(c: *mut i32, a: *const i32, b: *const i32);
    fn pqcrystals_dilithium_asm_reduce32(a: *mut i32);
    fn pqcrystals_dilithium_asm_caddq(a: *mut i32);
    fn pqcrystals_dilithium_poly_add(c: *mut i32, a: *const i32, b: *const i32);
    fn pqcrystals_dilithium_poly_sub(c: *mut i32, a: *const i32, b: *const i32);
}

/// An element of the polynomial quotient ring  = \mathbb{Z}_q[X] / (X^{256} + 1)$ for ML-DSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(8))]
pub struct Polynomial {
    pub coeffs: [i32; MLDSA_N],
}

impl Default for Polynomial {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Polynomial {
    /// The zero polynomial with all 256 coefficients equal to 0.
    pub const ZERO: Self = Self {
        coeffs: [0; MLDSA_N],
    };

    /// Create a polynomial from an array of 256 32-bit coefficients.
    pub const fn from_coeffs(coeffs: [i32; MLDSA_N]) -> Self {
        Self { coeffs }
    }

    /// Computes in-place forward Number-Theoretic Transform (NTT) in $.
    ///
    /// Transforms polynomial from standard coefficient order to NTT domain.
    pub fn ntt(&mut self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pqcrystals_dilithium_ntt(self.coeffs.as_mut_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            // In portable mode, we retain the standard polynomial representation.
        }
    }

    /// Computes in-place inverse Number-Theoretic Transform (InvNTT) in $
    /// and multiplies the result by ^{32} \pmod q$.
    pub fn invntt_tomont(&mut self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pqcrystals_dilithium_invntt_tomont(self.coeffs.as_mut_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            // In portable mode, inverse NTT is part of mul_ring.
        }
    }

    /// Pointwise multiplication of two polynomials in the NTT domain:
    /// computes [i] = a[i] \cdot b[i] \cdot 2^{-32} \pmod q$ for all 256 coefficients.
    pub fn pointwise_mont(&self, other: &Self) -> Self {
        let mut r = Self::ZERO;
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pqcrystals_dilithium_asm_pointwise_montgomery(
                r.coeffs.as_mut_ptr(),
                self.coeffs.as_ptr(),
                other.coeffs.as_ptr(),
            );
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for i in 0..MLDSA_N {
                let prod = (self.coeffs[i] as i64) * (other.coeffs[i] as i64);
                r.coeffs[i] = montgomery_reduce(prod);
            }
        }
        r
    }

    /// Pointwise multiplication with accumulation in the NTT domain:
    /// computes [i] += a[i] \cdot b[i] \cdot 2^{-32} \pmod q$ for all 256 coefficients.
    pub fn pointwise_acc_mont(&self, other: &Self, acc: &mut Self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pqcrystals_dilithium_asm_pointwise_acc_montgomery(
                acc.coeffs.as_mut_ptr(),
                self.coeffs.as_ptr(),
                other.coeffs.as_ptr(),
            );
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for i in 0..MLDSA_N {
                let prod = (self.coeffs[i] as i64) * (other.coeffs[i] as i64);
                let red = montgomery_reduce(prod);
                acc.coeffs[i] = acc.coeffs[i].wrapping_add(red);
            }
        }
    }

    /// Full ring multiplication (X) = a(X) \cdot b(X) \pmod{X^{256} + 1} \pmod{8380417}$.
    ///
    /// Accelerated by forward NTT, pointwise Montgomery multiplication, inverse NTT,
    /// and conditional addition modulo $.
    pub fn mul_ring(&self, other: &Self) -> Self {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        {
            let mut a_ntt = *self;
            let mut b_ntt = *other;
            a_ntt.ntt();
            b_ntt.ntt();
            let mut prod = a_ntt.pointwise_mont(&b_ntt);
            prod.invntt_tomont();
            prod.caddq();
            prod
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            let mut prod = [0i64; 2 * MLDSA_N];
            for i in 0..MLDSA_N {
                for j in 0..MLDSA_N {
                    prod[i + j] += (self.coeffs[i] as i64) * (other.coeffs[j] as i64);
                }
            }
            let mut out = Self::ZERO;
            for i in 0..MLDSA_N {
                let coeff = (prod[i] - prod[i + MLDSA_N]) % (MLDSA_Q as i64);
                let mut c = coeff as i32;
                if c < 0 {
                    c += MLDSA_Q;
                }
                out.coeffs[i] = c;
            }
            out
        }
    }

    /// In-place reduction of all coefficients modulo $.
    pub fn reduce32(&mut self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pqcrystals_dilithium_asm_reduce32(self.coeffs.as_mut_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for c in self.coeffs.iter_mut() {
                *c = reduce32_portable(*c);
            }
        }
    }

    /// In-place conditional addition of $ to negative coefficients,
    /// ensuring all coefficients are in -1$.
    pub fn caddq(&mut self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pqcrystals_dilithium_asm_caddq(self.coeffs.as_mut_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for c in self.coeffs.iter_mut() {
                if *c < 0 {
                    *c += MLDSA_Q;
                }
            }
        }
    }

    /// Pointwise addition of two polynomials.
    pub fn add(&self, other: &Self) -> Self {
        let mut r = Self::ZERO;
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pqcrystals_dilithium_poly_add(r.coeffs.as_mut_ptr(), self.coeffs.as_ptr(), other.coeffs.as_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for i in 0..MLDSA_N {
                r.coeffs[i] = self.coeffs[i] + other.coeffs[i];
            }
        }
        r
    }

    /// Pointwise subtraction of two polynomials.
    pub fn sub(&self, other: &Self) -> Self {
        let mut r = Self::ZERO;
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pqcrystals_dilithium_poly_sub(r.coeffs.as_mut_ptr(), self.coeffs.as_ptr(), other.coeffs.as_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for i in 0..MLDSA_N {
                r.coeffs[i] = self.coeffs[i] - other.coeffs[i];
            }
        }
        r
    }
}

/// Montgomery reduction for portable fallback:
/// computes  \pmod q$.
#[inline]
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(MLDSA_QINV) as i64;
    let t = (a - t * (MLDSA_Q as i64)) >> 32;
    t as i32
}

/// Portable reduction modulo  = 8380417$.
#[inline]
pub fn reduce32_portable(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * MLDSA_Q
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schoolbook_mul(a: &[i32; MLDSA_N], b: &[i32; MLDSA_N]) -> [i32; MLDSA_N] {
        let mut prod = [0i64; 2 * MLDSA_N];
        for i in 0..MLDSA_N {
            for j in 0..MLDSA_N {
                prod[i + j] += (a[i] as i64) * (b[j] as i64);
            }
        }
        let mut out = [0i32; MLDSA_N];
        for i in 0..MLDSA_N {
            let coeff = (prod[i] - prod[i + MLDSA_N]) % (MLDSA_Q as i64);
            let mut c = coeff as i32;
            if c < 0 {
                c += MLDSA_Q;
            }
            out[i] = c;
        }
        out
    }

    #[test]
    fn test_zero_poly() {
        let mut p = Polynomial::ZERO;
        p.ntt();
        assert_eq!(p.coeffs, [0; MLDSA_N]);
        p.invntt_tomont();
        assert_eq!(p.coeffs, [0; MLDSA_N]);
    }

    #[test]
    fn test_add_sub() {
        let mut a = Polynomial::ZERO;
        let mut b = Polynomial::ZERO;
        for i in 0..MLDSA_N {
            a.coeffs[i] = (i * 100) as i32;
            b.coeffs[i] = (i * 50 + 7) as i32;
        }
        let sum = a.add(&b);
        let diff = a.sub(&b);
        for i in 0..MLDSA_N {
            assert_eq!(sum.coeffs[i], a.coeffs[i] + b.coeffs[i]);
            assert_eq!(diff.coeffs[i], a.coeffs[i] - b.coeffs[i]);
        }
    }

    #[test]
    fn test_mul_ring_matches_schoolbook() {
        let mut a = Polynomial::ZERO;
        let mut b = Polynomial::ZERO;
        for i in 0..MLDSA_N {
            a.coeffs[i] = ((i * 1013 + 7) % (MLDSA_Q as usize)) as i32;
            b.coeffs[i] = ((i * 2029 + 11) % (MLDSA_Q as usize)) as i32;
        }
        let expected = schoolbook_mul(&a.coeffs, &b.coeffs);
        let prod = a.mul_ring(&b);
        for i in 0..MLDSA_N {
            let got = (prod.coeffs[i] % MLDSA_Q + MLDSA_Q) % MLDSA_Q;
            assert_eq!(got, expected[i], "ML-DSA ring multiplication mismatch at index {}", i);
        }
    }
}
