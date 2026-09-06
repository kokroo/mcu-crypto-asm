//! Ed25519 signature algorithm and Edwards curve point operations (RFC 8032).

use core::ops::{Add, Index, IndexMut, Mul, Neg, Sub};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CompressedEdwardsY(pub [u8; 32]);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EdwardsPoint(pub [u32; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scalar(pub [u32; 8]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Scalar512([u32; 16]);

#[inline(always)]
fn carrying_mul(a: u32, b: u32, carry: u32) -> (u32, u32) {
    let p = (a as u64) * (b as u64) + (carry as u64);
    (p as u32, (p >> 32) as u32)
}

#[inline(always)]
fn carrying_add(a: u32, b: u32, carry: bool) -> (u32, bool) {
    let s = (a as u64) + (b as u64) + (carry as u64);
    (s as u32, s > 0xffff_ffff)
}

#[inline(always)]
fn borrowing_sub(a: u32, b: u32, borrow: bool) -> (u32, bool) {
    let d = (a as i64) - (b as i64) - (borrow as i64);
    (d as u32, d < 0)
}

impl Index<usize> for Scalar {
    type Output = u32;
    fn index(&self, i: usize) -> &u32 {
        &self.0[i]
    }
}

impl IndexMut<usize> for Scalar {
    fn index_mut(&mut self, i: usize) -> &mut u32 {
        &mut self.0[i]
    }
}

impl Index<usize> for Scalar512 {
    type Output = u32;
    fn index(&self, i: usize) -> &u32 {
        &self.0[i]
    }
}

impl IndexMut<usize> for Scalar512 {
    fn index_mut(&mut self, i: usize) -> &mut u32 {
        &mut self.0[i]
    }
}

impl Scalar {
    pub fn as_bytes(&self) -> &[u8; 32] {
        unsafe { core::mem::transmute(self) }
    }

    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        let words: [u32; 8] = unsafe { core::mem::transmute(bytes) };
        Scalar(words).reduce()
    }

    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        let words: [u32; 16] = unsafe { core::mem::transmute(*bytes) };
        let low = Scalar(words[..8].try_into().unwrap());
        let high = Scalar(words[8..].try_into().unwrap());
        (low.raw_mul(R) + high.raw_mul(RR)).montgomery_reduce()
    }

    fn reduce(&self) -> Scalar {
        self.raw_mul(R).montgomery_reduce()
    }

    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Self> {
        if (bytes[31] >> 7) != 0u8 {
            return None;
        }
        let candidate = Scalar(unsafe { core::mem::transmute(bytes) });
        if candidate == candidate.reduce() {
            Some(candidate)
        } else {
            None
        }
    }

    fn raw_mul(self, b: Scalar) -> Scalar512 {
        let a = self;
        let mut res = Scalar512([0; 16]);
        for i in 0..8 {
            let mut carry = 0;
            for j in 0..8 {
                let (val, c) = carrying_mul(a[i], b[j], carry);
                let (sum, add_carry) = carrying_add(res[i + j], val, false);
                res[i + j] = sum;
                carry = c + (add_carry as u32);
            }
            for j in 8..(16 - i) {
                let (sum, add_carry) = carrying_add(res[i + j], carry, false);
                res[i + j] = sum;
                carry = add_carry as u32;
            }
            debug_assert_eq!(carry, 0);
        }
        res
    }
}

impl Scalar512 {
    fn montgomery_reduce(self) -> Scalar {
        let mut t = self;
        for i in 0..8 {
            let mut carry = 0;
            let m = t[i].wrapping_mul(LFACTOR);
            for j in 0..8 {
                let (val, c) = carrying_mul(L[j], m, carry);
                let (sum, add_carry) = carrying_add(t[i + j], val, false);
                t[i + j] = sum;
                carry = c + (add_carry as u32);
            }
            for j in 8..(16 - i) {
                let (sum, add_carry) = carrying_add(t[i + j], carry, false);
                t[i + j] = sum;
                carry = add_carry as u32;
            }
            debug_assert_eq!(carry, 0);
        }
        Scalar(t.0[8..].try_into().unwrap()) - L
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;
    fn add(self, b: Scalar) -> Self::Output {
        let mut a = self;
        let mut carry = false;
        for i in 0..8 {
            let (sum, c) = carrying_add(a[i], b[i], carry);
            a[i] = sum;
            carry = c;
        }
        a - L
    }
}

impl Add<Scalar512> for Scalar512 {
    type Output = Scalar512;
    fn add(self, b: Scalar512) -> Self::Output {
        let mut a = self;
        let mut carry = false;
        for i in 0..16 {
            let (sum, c) = carrying_add(a[i], b[i], carry);
            a[i] = sum;
            carry = c;
        }
        debug_assert!(!carry);
        a
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;
    fn sub(self, b: Scalar) -> Self::Output {
        let mut a = self;
        let mut borrow = false;
        for i in 0..8 {
            let (diff, bor) = borrowing_sub(a[i], b[i], borrow);
            a[i] = diff;
            borrow = bor;
        }

        let underflow_mask = ((!borrow) as u32).wrapping_sub(1);
        let mut carry = false;
        for i in 0..8 {
            let (sum, c) = carrying_add(a[i], L[i] & underflow_mask, carry);
            a[i] = sum;
            carry = c;
        }
        a
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Scalar) -> Self::Output {
        self.raw_mul(rhs)
            .montgomery_reduce()
            .raw_mul(RR)
            .montgomery_reduce()
    }
}

const L: Scalar = Scalar([
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0x00000000, 0x00000000, 0x00000000, 0x10000000,
]);

const R: Scalar = Scalar([
    0x8d98951d, 0xd6ec3174, 0x737dcf70, 0xc6ef5bf4, 0xfffffffe, 0xffffffff, 0xffffffff, 0x0fffffff,
]);

const RR: Scalar = Scalar([
    0x449c0f01, 0xa40611e3, 0x68859347, 0xd00e1ba7, 0x17f5be65, 0xceec73d2, 0x7c309a3d, 0x0399411b,
]);

const LFACTOR: u32 = 0x12547e1b;

impl CompressedEdwardsY {
    pub fn decompress(&self) -> Option<EdwardsPoint> {
        #[cfg(nistp_asm_cm4)]
        {
            let mut result = [0u32; 32];
            match unsafe { super::cortex_m::ed25519_decompress(&mut result, &self.0) } {
                false => None,
                true => Some(EdwardsPoint(result)),
            }
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            None
        }
    }
}

impl EdwardsPoint {
    pub fn compress(&self) -> CompressedEdwardsY {
        #[cfg(nistp_asm_cm4)]
        {
            let mut result = [0u8; 32];
            unsafe { super::cortex_m::ed25519_compress(&mut result, &self.0) };
            CompressedEdwardsY(result)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            CompressedEdwardsY([0u8; 32])
        }
    }
}

impl Add<EdwardsPoint> for EdwardsPoint {
    type Output = EdwardsPoint;
    fn add(self, rhs: EdwardsPoint) -> Self::Output {
        #[cfg(nistp_asm_cm4)]
        {
            let mut result = [0u32; 32];
            unsafe { super::cortex_m::ed25519_add(&mut result, &self.0, &rhs.0) };
            EdwardsPoint(result)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            EdwardsPoint([0u32; 32])
        }
    }
}

impl Mul<EdwardsPoint> for Scalar {
    type Output = EdwardsPoint;
    fn mul(self, rhs: EdwardsPoint) -> Self::Output {
        #[cfg(nistp_asm_cm4)]
        {
            let mut result = [0u32; 32];
            unsafe { super::cortex_m::ed25519_scalarmult(&mut result, self.as_bytes(), &rhs.0) };
            EdwardsPoint(result)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            EdwardsPoint([0u32; 32])
        }
    }
}

impl Neg for EdwardsPoint {
    type Output = EdwardsPoint;
    fn neg(self) -> Self::Output {
        #[cfg(nistp_asm_cm4)]
        {
            let mut result = self.0;
            unsafe { super::cortex_m::ed25519_neg(&mut result) };
            EdwardsPoint(result)
        }
        #[cfg(not(nistp_asm_cm4))]
        {
            EdwardsPoint([0u32; 32])
        }
    }
}

#[rustfmt::skip]
pub const ED25519_BASEPOINT_POINT: EdwardsPoint = EdwardsPoint([
    // x
    0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760,
    0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3,

    // y
    0x6666_6658, 0x6666_6666, 0x6666_6666, 0x6666_6666,
    0x6666_6666, 0x6666_6666, 0x6666_6666, 0x6666_6666,

    // z
    0x0000_0001, 0x0000_0000, 0x0000_0000, 0x0000_0000,
    0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_0000,

    // t = x*y
    0xa5b7dda3, 0x6dde8ab3, 0x775152f5, 0x20f09f80,
    0x64abe37d, 0x66ea4e8e, 0xd78b7665, 0x67875f0f,
]);
