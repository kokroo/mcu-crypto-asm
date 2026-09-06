//! Ed25519 signature algorithm and Edwards curve point operations (RFC 8032).

use core::ops::{Add, Index, IndexMut, Mul, Neg, Sub};
use super::portable::Fe51;

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

#[cfg(not(nistp_asm_cm4))]
const D_BYTES: [u8; 32] = [
    163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0,
    152, 232, 121, 119, 121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82,
];

#[cfg(not(nistp_asm_cm4))]
const D2_BYTES: [u8; 32] = [
    89, 241, 178, 38, 148, 155, 214, 235, 86, 177, 131, 130, 154, 20, 224, 0,
    48, 209, 243, 238, 242, 128, 142, 25, 231, 252, 223, 86, 220, 217, 6, 36,
];

#[cfg(not(nistp_asm_cm4))]
const SQRT_M1_BYTES: [u8; 32] = [
    176, 160, 14, 74, 39, 27, 238, 196, 120, 228, 47, 173, 6, 24, 67, 47,
    167, 215, 251, 61, 153, 0, 77, 43, 11, 223, 193, 79, 128, 36, 131, 43,
];

#[cfg(not(nistp_asm_cm4))]
#[derive(Clone, Copy)]
struct PointFe {
    x: Fe51,
    y: Fe51,
    z: Fe51,
    t: Fe51,
}

#[cfg(not(nistp_asm_cm4))]
fn fe51_to_words(fe: &Fe51) -> [u32; 8] {
    let bytes = fe.to_bytes();
    let mut words = [0u32; 8];
    for i in 0..8 {
        words[i] = u32::from_le_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    words
}

#[cfg(not(nistp_asm_cm4))]
fn words_to_fe51(words: &[u32]) -> Fe51 {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&words[i].to_le_bytes());
    }
    Fe51::from_bytes(&bytes)
}

#[cfg(not(nistp_asm_cm4))]
impl EdwardsPoint {
    fn to_fe(&self) -> PointFe {
        PointFe {
            x: words_to_fe51(&self.0[0..8]),
            y: words_to_fe51(&self.0[8..16]),
            z: words_to_fe51(&self.0[16..24]),
            t: words_to_fe51(&self.0[24..32]),
        }
    }

    fn from_fe(p: &PointFe) -> Self {
        let mut words = [0u32; 32];
        words[0..8].copy_from_slice(&fe51_to_words(&p.x));
        words[8..16].copy_from_slice(&fe51_to_words(&p.y));
        words[16..24].copy_from_slice(&fe51_to_words(&p.z));
        words[24..32].copy_from_slice(&fe51_to_words(&p.t));
        EdwardsPoint(words)
    }
}

#[cfg(not(nistp_asm_cm4))]
fn edwards_add_fe(p1: &PointFe, p2: &PointFe) -> PointFe {
    let d2 = Fe51::from_bytes(&D2_BYTES);
    let a = p1.y.sub(&p1.x).mul(&p2.y.sub(&p2.x));
    let b = p1.y.add(&p1.x).mul(&p2.y.add(&p2.x));
    let c = d2.mul(&p1.t).mul(&p2.t);
    let d = p1.z.add(&p1.z).mul(&p2.z);
    let e = b.sub(&a);
    let f = d.sub(&c);
    let g = d.add(&c);
    let h = b.add(&a);

    PointFe {
        x: e.mul(&f),
        y: g.mul(&h),
        z: f.mul(&g),
        t: e.mul(&h),
    }
}

#[cfg(not(nistp_asm_cm4))]
fn pow_p_plus_3_over_8(z: &Fe51) -> Fe51 {
    let mut res = Fe51::ONE;
    for i in (0..252).rev() {
        res = res.sqr();
        if i >= 1 {
            res = res.mul(z);
        }
    }
    res
}

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
            let sign = (self.0[31] >> 7) != 0;
            let mut y_bytes = self.0;
            y_bytes[31] &= 0x7F;

            let y = Fe51::from_bytes(&y_bytes);
            let y_roundtrip = y.to_bytes();
            if y_roundtrip != y_bytes {
                return None;
            }

            let d = Fe51::from_bytes(&D_BYTES);
            let y2 = y.sqr();
            let u = y2.sub(&Fe51::ONE);
            let v = d.mul(&y2).add(&Fe51::ONE);

            let xx = u.mul(&v.invert());
            let mut x = pow_p_plus_3_over_8(&xx);

            let mut check = x.sqr().sub(&xx);
            let check_bytes = check.to_bytes();
            let mut is_zero = true;
            for &b in &check_bytes {
                if b != 0 {
                    is_zero = false;
                    break;
                }
            }

            if !is_zero {
                let sqrt_m1 = Fe51::from_bytes(&SQRT_M1_BYTES);
                x = x.mul(&sqrt_m1);
                check = x.sqr().sub(&xx);
                let check_bytes2 = check.to_bytes();
                let mut is_zero2 = true;
                for &b in &check_bytes2 {
                    if b != 0 {
                        is_zero2 = false;
                        break;
                    }
                }
                if !is_zero2 {
                    return None;
                }
            }

            let x_bytes = x.to_bytes();
            if ((x_bytes[0] & 1) != 0) != sign {
                x = Fe51::ZERO.sub(&x);
            }

            let t = x.mul(&y);
            let pt = PointFe {
                x,
                y,
                z: Fe51::ONE,
                t,
            };
            Some(EdwardsPoint::from_fe(&pt))
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
            let pt = self.to_fe();
            let zinv = pt.z.invert();
            let x = pt.x.mul(&zinv);
            let y = pt.y.mul(&zinv);
            let mut out = y.to_bytes();
            let x_bytes = x.to_bytes();
            out[31] |= (x_bytes[0] & 1) << 7;
            CompressedEdwardsY(out)
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
            let p1 = self.to_fe();
            let p2 = rhs.to_fe();
            EdwardsPoint::from_fe(&edwards_add_fe(&p1, &p2))
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
            let p = rhs.to_fe();
            let scalar_bytes = self.as_bytes();
            let mut res = PointFe {
                x: Fe51::ZERO,
                y: Fe51::ONE,
                z: Fe51::ONE,
                t: Fe51::ZERO,
            };
            for bit_idx in (0..256).rev() {
                res = edwards_add_fe(&res, &res);
                if ((scalar_bytes[bit_idx / 8] >> (bit_idx % 8)) & 1) != 0 {
                    res = edwards_add_fe(&res, &p);
                }
            }
            EdwardsPoint::from_fe(&res)
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
            let p = self.to_fe();
            EdwardsPoint::from_fe(&PointFe {
                x: Fe51::ZERO.sub(&p.x),
                y: p.y,
                z: p.z,
                t: Fe51::ZERO.sub(&p.t),
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basepoint_compress() {
        let b = ED25519_BASEPOINT_POINT;
        let comp = b.compress();
        let mut expected = [0x66u8; 32];
        expected[0] = 0x58;
        assert_eq!(comp.0, expected);
    }

    #[test]
    fn test_basepoint_decompress() {
        let mut b_bytes = [0x66u8; 32];
        b_bytes[0] = 0x58;
        let comp = CompressedEdwardsY(b_bytes);
        let pt = comp.decompress().expect("Base point decompress failed");
        let recomp = pt.compress();
        assert_eq!(recomp.0, b_bytes);
    }

    #[test]
    fn test_point_add_and_double() {
        let b = ED25519_BASEPOINT_POINT;
        let b2_add = b + b;

        let s2 = Scalar([2, 0, 0, 0, 0, 0, 0, 0]);
        let b2_mul = s2 * b;

        assert_eq!(b2_add.compress().0, b2_mul.compress().0);
    }

    #[test]
    fn test_point_neg_identity() {
        let b = ED25519_BASEPOINT_POINT;
        let b_neg = -b;
        let id = b + b_neg;
        // Identity has x=0, y=1, z=1
        let comp = id.compress();
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(comp.0, expected);
    }
}
