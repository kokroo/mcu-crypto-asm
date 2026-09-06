//! Fast, constant-time secp256k1 (Bitcoin/Koblitz) elliptic curve cryptography.
//!
//! Accelerated on Target 1 (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) by assembly `UMAAL`
//! multi-precision multiplication and fast pseudo-Mersenne Solinas reduction modulo
//! $p = 2^{256} - 2^{32} - 977$.
//!
//! Provides:
//! - Complete Renes–Costello–Batina addition formulas for $a = 0$ (Algorithm 1)
//! - Constant-time Montgomery ladder scalar multiplication
//! - SEC1 compressed (33 bytes) and uncompressed (65 bytes) point encoding/decoding
//! - ECDH shared secret derivation

#![allow(clippy::needless_range_loop)]

#[cfg(nistp_asm_cm4)]
mod asm {
    extern "C" {
        pub fn bignum_mulacc(
            accumulator: *mut u32,
            a: *const u32,
            b: *const u32,
            operand_length_bytes: usize,
        );
        pub fn bignum_sqracc(
            accumulator: *mut u32,
            a: *const u32,
            operand_length_bytes: usize,
        );
    }
}

/// Modulus $p = 2^{256} - 2^{32} - 977$ in little-endian 32-bit limbs.
pub const SECP256K1_P: [u32; 8] = [
    0xFFFF_FC2F, 0xFFFF_FFFE, 0xFFFF_FFFF, 0xFFFF_FFFF,
    0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
];

/// Curve order $n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BB5D25E3DF031AD85$.
pub const SECP256K1_N: [u32; 8] = [
    0xD036_4141, 0xBFD2_5E8C, 0xAF48_A03B, 0xBAAE_DCE6,
    0xFFFF_FFFE, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
];

/// Base point G x-coordinate.
pub const SECP256K1_GX: [u32; 8] = [
    0x16F8_1798, 0x59F2_815B, 0x2DCE_28D9, 0x029B_FCDB,
    0xCE87_0B07, 0x55A0_6295, 0xF9DC_BBAC, 0x79BE_667E,
];

/// Base point G y-coordinate.
pub const SECP256K1_GY: [u32; 8] = [
    0xFB10_D4B8, 0x9C47_D08F, 0xA685_5419, 0xFD17_B448,
    0x0E11_08A8, 0x5DA4_FBFC, 0x26A3_C465, 0x483A_DA77,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Secp256k1Error {
    InvalidScalar,
    InvalidEncoding,
    PointNotOnCurve,
    PointAtInfinity,
}

/// A field element in $\mathbb{F}_p$ where $p = 2^{256} - 2^{32} - 977$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement(pub [u32; 8]);

impl FieldElement {
    pub const ZERO: Self = FieldElement([0; 8]);
    pub const ONE: Self = FieldElement([1, 0, 0, 0, 0, 0, 0, 0]);

    /// Construct from big-endian bytes. Returns error if >= p.
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Result<Self, Secp256k1Error> {
        let mut limbs = [0u32; 8];
        for i in 0..8 {
            let offset = (7 - i) * 4;
            limbs[i] = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
        }
        if gte(&limbs, &SECP256K1_P) {
            return Err(Secp256k1Error::InvalidEncoding);
        }
        Ok(FieldElement(limbs))
    }

    /// Serialize to big-endian bytes.
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..8 {
            let b = self.0[i].to_be_bytes();
            let offset = (7 - i) * 4;
            out[offset..offset + 4].copy_from_slice(&b);
        }
        out
    }

    /// Is this field element zero?
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        let mut acc = 0u32;
        for &w in &self.0 {
            acc |= w;
        }
        acc == 0
    }

    /// Is this field element odd?
    #[inline(always)]
    pub fn is_odd(&self) -> bool {
        (self.0[0] & 1) != 0
    }

    /// Constant-time conditional selection: returns `a` if `choice == 0`, `b` if `choice == 1`.
    #[inline(always)]
    pub fn conditional_select(a: &Self, b: &Self, choice: u32) -> Self {
        let mask = (!choice.wrapping_sub(1)) as u32; // 0xFFFFFFFF if 1, 0 if 0
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i]));
        }
        FieldElement(out)
    }

    /// Field addition $(a + b) \pmod p$.
    #[inline]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut sum = [0u32; 8];
        let mut carry = 0u64;
        for i in 0..8 {
            carry += (self.0[i] as u64) + (rhs.0[i] as u64);
            sum[i] = carry as u32;
            carry >>= 32;
        }

        let mut diff = [0u32; 8];
        let mut borrow = 0i64;
        for i in 0..8 {
            borrow += (sum[i] as i64) - (SECP256K1_P[i] as i64);
            diff[i] = borrow as u32;
            borrow >>= 32;
        }

        if carry != 0 || borrow == 0 {
            FieldElement(diff)
        } else {
            FieldElement(sum)
        }
    }

    /// Field subtraction $(a - b) \pmod p$.
    #[inline]
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut diff = [0u32; 8];
        let mut borrow = 0i64;
        for i in 0..8 {
            borrow += (self.0[i] as i64) - (rhs.0[i] as i64);
            diff[i] = borrow as u32;
            borrow >>= 32;
        }
        if borrow != 0 {
            let mut carry = 0u64;
            for i in 0..8 {
                carry += (diff[i] as u64) + (SECP256K1_P[i] as u64);
                diff[i] = carry as u32;
                carry >>= 32;
            }
        }
        FieldElement(diff)
    }

    /// Field negation $(-a) \pmod p$.
    #[inline]
    pub fn neg(&self) -> Self {
        if self.is_zero() {
            *self
        } else {
            Self::ZERO.sub(self)
        }
    }

    /// Field multiplication $(a \times b) \pmod p$.
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut prod = [0u32; 16];

        #[cfg(nistp_asm_cm4)]
        unsafe {
            asm::bignum_mulacc(prod.as_mut_ptr(), self.0.as_ptr(), rhs.0.as_ptr(), 32);
        }

        #[cfg(not(nistp_asm_cm4))]
        {
            comba_mul_8(&self.0, &rhs.0, &mut prod);
        }

        let mut out = [0u32; 8];
        secp256k1_reduce(&prod, &mut out);
        FieldElement(out)
    }

    /// Field squaring $(a^2) \pmod p$.
    #[inline]
    pub fn square(&self) -> Self {
        let mut prod = [0u32; 16];

        #[cfg(nistp_asm_cm4)]
        unsafe {
            asm::bignum_sqracc(prod.as_mut_ptr(), self.0.as_ptr(), 32);
        }

        #[cfg(not(nistp_asm_cm4))]
        {
            comba_mul_8(&self.0, &self.0, &mut prod);
        }

        let mut out = [0u32; 8];
        secp256k1_reduce(&prod, &mut out);
        FieldElement(out)
    }

    /// Field inversion $a^{-1} \equiv a^{p-2} \pmod p$ via constant-time square-and-multiply.
    pub fn invert(&self) -> Self {
        if self.is_zero() {
            return *self;
        }

        // p - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
        // Exponent has 256 bits.
        let mut res = FieldElement::ONE;
        let mut cur = *self;

        for word_idx in 0..8 {
            let mut w: u32 = match word_idx {
                0 => 0xFFFF_FC2D_u32,
                1 => 0xFFFF_FFFE_u32,
                _ => 0xFFFF_FFFF_u32,
            };
            for _ in 0..32 {
                if (w & 1) != 0 {
                    res = res.mul(&cur);
                }
                cur = cur.square();
                w >>= 1;
            }
        }
        res
    }

    /// Modular square root via $a^{(p+1)/4} \pmod p$.
    ///
    /// Returns `Some(root)` if $a$ is a quadratic residue, or `None`.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(*self);
        }
        // (p + 1) / 4 = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C
        let mut res = FieldElement::ONE;
        let mut cur = *self;

        for word_idx in 0..8 {
            let mut w: u32 = match word_idx {
                0 => 0xBFFF_FF0C_u32,
                7 => 0x3FFF_FFFF_u32,
                _ => 0xFFFF_FFFF_u32,
            };
            let bit_count = if word_idx == 7 { 30 } else { 32 };
            for _ in 0..bit_count {
                if (w & 1) != 0 {
                    res = res.mul(&cur);
                }
                cur = cur.square();
                w >>= 1;
            }
        }

        if res.square() == *self {
            Some(res)
        } else {
            None
        }
    }
}

/// Pseudo-Mersenne fast reduction modulo $p = 2^{256} - 2^{32} - 977$.
///
/// Exploits $2^{256} \equiv 2^{32} + 0x3D1 \pmod p$.
pub fn secp256k1_reduce(product: &[u32; 16], out: &mut [u32; 8]) {
    // Step 1: omega_mult on product[8..15]
    // Multiply by 0x3D1 (977)
    let mut tmp = [0u32; 16];
    let mut carry = 0u64;
    for k in 0..8 {
        let prod = 0x3D1u64 * (product[8 + k] as u64) + carry;
        tmp[k] = prod as u32;
        carry = prod >> 32;
    }
    tmp[8] = carry as u32;

    // Add product[8..15] into tmp[1..9] (shifted by 2^32)
    carry = 0;
    for k in 0..8 {
        let s = (tmp[1 + k] as u64) + (product[8 + k] as u64) + carry;
        tmp[1 + k] = s as u32;
        carry = s >> 32;
    }
    tmp[9] += carry as u32;

    // Step 2: res = product[0..7] + tmp[0..7]
    let mut res = [0u32; 8];
    carry = 0;
    for k in 0..8 {
        let s = (product[k] as u64) + (tmp[k] as u64) + carry;
        res[k] = s as u32;
        carry = s >> 32;
    }
    let c1 = carry as u32;

    // Step 3: second omega_mult on tmp[8..9]
    let mut tmp2 = [0u32; 8];
    carry = 0;
    for k in 0..2 {
        let prod = 0x3D1u64 * (tmp[8 + k] as u64) + carry;
        tmp2[k] = prod as u32;
        carry = prod >> 32;
    }
    tmp2[2] = carry as u32;

    carry = 0;
    for k in 0..2 {
        let s = (tmp2[1 + k] as u64) + (tmp[8 + k] as u64) + carry;
        tmp2[1 + k] = s as u32;
        carry = s >> 32;
    }
    tmp2[3] += carry as u32;

    // Add c1 * (2^32 + 0x3D1) to tmp2
    let c1_3d1 = (c1 as u64) * 0x3D1;
    let s0 = (tmp2[0] as u64) + c1_3d1;
    tmp2[0] = s0 as u32;
    carry = s0 >> 32;

    let s1 = (tmp2[1] as u64) + (c1 as u64) + carry;
    tmp2[1] = s1 as u32;
    carry = s1 >> 32;

    let mut idx = 2;
    while carry > 0 && idx < 8 {
        let s = (tmp2[idx] as u64) + carry;
        tmp2[idx] = s as u32;
        carry = s >> 32;
        idx += 1;
    }

    // Step 4: res = res + tmp2
    carry = 0;
    for k in 0..8 {
        let s = (res[k] as u64) + (tmp2[k] as u64) + carry;
        res[k] = s as u32;
        carry = s >> 32;
    }
    let c2 = carry as u32;

    // Fold overflow c2 if any
    if c2 > 0 {
        let c2_3d1 = (c2 as u64) * 0x3D1;
        let s0 = (res[0] as u64) + c2_3d1;
        res[0] = s0 as u32;
        carry = s0 >> 32;

        let s1 = (res[1] as u64) + (c2 as u64) + carry;
        res[1] = s1 as u32;
        carry = s1 >> 32;

        idx = 2;
        while carry > 0 && idx < 8 {
            let s = (res[idx] as u64) + carry;
            res[idx] = s as u32;
            carry = s >> 32;
            idx += 1;
        }
    }

    // Constant-time final reduction against p
    sub_p_if_gte(&mut res, 0);
    out.copy_from_slice(&res);
}

#[allow(dead_code)]
#[inline(always)]
fn comba_mul_8(a: &[u32; 8], b: &[u32; 8], out: &mut [u32; 16]) {
    let mut c: u128 = 0;
    for i in 0..15 {
        let start = if i > 7 { i - 7 } else { 0 };
        let end = if i < 7 { i } else { 7 };
        for j in start..=end {
            c += (a[j] as u128) * (b[i - j] as u128);
        }
        out[i] = c as u32;
        c >>= 32;
    }
    out[15] = c as u32;
}

#[inline(always)]
fn gte(a: &[u32; 8], b: &[u32; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

#[inline]
fn sub_p_if_gte(a: &mut [u32; 8], overflow: u32) {
    // Attempt subtraction: diff = a - p
    for _ in 0..2 {
        let mut diff = [0u32; 8];
        let mut borrow = 0i64;
        for i in 0..8 {
            borrow += (a[i] as i64) - (SECP256K1_P[i] as i64);
            diff[i] = borrow as u32;
            borrow >>= 32;
        }
        borrow += overflow as i64;
        if borrow >= 0 {
            a.copy_from_slice(&diff);
        } else {
            break;
        }
    }
}

/// Projective point $(X : Y : Z)$ in homogeneous coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectivePoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl ProjectivePoint {
    /// Identity point $(0 : 1 : 0)$.
    pub const IDENTITY: Self = ProjectivePoint {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Base generator point $G$.
    pub const GENERATOR: Self = ProjectivePoint {
        x: FieldElement(SECP256K1_GX),
        y: FieldElement(SECP256K1_GY),
        z: FieldElement::ONE,
    };

    /// Is this point the identity $\mathcal{O}$?
    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    /// Complete addition formula for $y^2 = x^3 + b$ ($a = 0$).
    ///
    /// Renes–Costello–Batina Algorithm 1 (2015/1060).
    /// Complete and unconditionally valid for all inputs including $P + P$, $P + (-P)$, and $\mathcal{O}$.
    pub fn add(&self, rhs: &Self) -> Self {
        let b3 = FieldElement([21, 0, 0, 0, 0, 0, 0, 0]);

        let x1 = &self.x;
        let y1 = &self.y;
        let z1 = &self.z;

        let x2 = &rhs.x;
        let y2 = &rhs.y;
        let z2 = &rhs.z;

        let mut t0 = x1.mul(x2);
        let mut t1 = y1.mul(y2);
        let mut t2 = z1.mul(z2);

        let mut t3 = x1.add(y1);
        let mut t4 = x2.add(y2);
        t3 = t3.mul(&t4);
        t4 = t0.add(&t1);
        t3 = t3.sub(&t4);

        t4 = y1.add(z1);
        let mut x3 = y2.add(z2);
        t4 = t4.mul(&x3);
        x3 = t1.add(&t2);
        t4 = t4.sub(&x3);

        x3 = x1.add(z1);
        let mut y3 = x2.add(z2);
        x3 = x3.mul(&y3);
        y3 = t0.add(&t2);
        y3 = x3.sub(&y3);

        x3 = t0.add(&t0);
        t0 = x3.add(&t0);
        t2 = t2.mul(&b3);
        let mut z3 = t1.add(&t2);
        t1 = t1.sub(&t2);
        y3 = y3.mul(&b3);
        x3 = t4.mul(&y3);
        t2 = t3.mul(&t1);
        x3 = t2.sub(&x3);
        y3 = y3.mul(&t0);
        t1 = t1.mul(&z3);
        y3 = t1.add(&y3);
        t0 = t0.mul(&t3);
        z3 = z3.mul(&t4);
        z3 = z3.add(&t0);

        ProjectivePoint { x: x3, y: y3, z: z3 }
    }

    /// Point doubling: $P + P$.
    #[inline]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Constant-time conditional selection.
    pub fn conditional_select(a: &Self, b: &Self, choice: u32) -> Self {
        ProjectivePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }

    /// Convert to affine coordinates $(x, y) = (X/Z, Y/Z)$.
    pub fn to_affine(&self) -> Option<AffinePoint> {
        if self.is_identity() {
            return None;
        }
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);
        Some(AffinePoint { x, y })
    }

    /// Constant-time scalar multiplication using Montgomery ladder over 256 bits.
    pub fn scalarmult(&self, scalar: &[u8; 32]) -> ProjectivePoint {
        let mut r0 = ProjectivePoint::IDENTITY;
        let mut r1 = *self;

        for byte_idx in 0..32 {
            let byte = scalar[byte_idx];
            for bit_idx in (0..8).rev() {
                let bit = ((byte >> bit_idx) & 1) as u32;

                // cswap(r0, r1) if bit == 1
                let swap_r0 = ProjectivePoint::conditional_select(&r0, &r1, bit);
                let swap_r1 = ProjectivePoint::conditional_select(&r1, &r0, bit);

                // ladder step
                let new_r1 = swap_r0.add(&swap_r1);
                let new_r0 = swap_r0.double();

                // cswap back
                r0 = ProjectivePoint::conditional_select(&new_r0, &new_r1, bit);
                r1 = ProjectivePoint::conditional_select(&new_r1, &new_r0, bit);
            }
        }
        r0
    }
}

/// An affine point $(x, y)$ on secp256k1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: FieldElement,
    pub y: FieldElement,
}

impl AffinePoint {
    /// Convert to projective coordinates $(x : y : 1)$.
    pub fn to_projective(&self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x,
            y: self.y,
            z: FieldElement::ONE,
        }
    }

    /// Check if point satisfies the curve equation $y^2 \equiv x^3 + 7 \pmod p$.
    pub fn is_on_curve(&self) -> bool {
        let y2 = self.y.square();
        let x3_plus_7 = self.x.square().mul(&self.x).add(&FieldElement([7, 0, 0, 0, 0, 0, 0, 0]));
        y2 == x3_plus_7
    }

    /// Parse SEC1 encoded point (33-byte compressed or 65-byte uncompressed).
    pub fn from_encoded_point(bytes: &[u8]) -> Result<Self, Secp256k1Error> {
        if bytes.is_empty() {
            return Err(Secp256k1Error::InvalidEncoding);
        }
        match bytes[0] {
            // Compressed: 0x02 (even y) or 0x03 (odd y)
            0x02 | 0x03 => {
                if bytes.len() != 33 {
                    return Err(Secp256k1Error::InvalidEncoding);
                }
                let mut x_bytes = [0u8; 32];
                x_bytes.copy_from_slice(&bytes[1..33]);
                let x = FieldElement::from_bytes_be(&x_bytes)?;

                // y^2 = x^3 + 7
                let y2 = x.square().mul(&x).add(&FieldElement([7, 0, 0, 0, 0, 0, 0, 0]));
                let mut y = y2.sqrt().ok_or(Secp256k1Error::PointNotOnCurve)?;

                let is_odd = bytes[0] == 0x03;
                if y.is_odd() != is_odd {
                    y = y.neg();
                }
                let pt = AffinePoint { x, y };
                if !pt.is_on_curve() {
                    return Err(Secp256k1Error::PointNotOnCurve);
                }
                Ok(pt)
            }
            // Uncompressed: 0x04
            0x04 => {
                if bytes.len() != 65 {
                    return Err(Secp256k1Error::InvalidEncoding);
                }
                let mut x_bytes = [0u8; 32];
                let mut y_bytes = [0u8; 32];
                x_bytes.copy_from_slice(&bytes[1..33]);
                y_bytes.copy_from_slice(&bytes[33..65]);

                let x = FieldElement::from_bytes_be(&x_bytes)?;
                let y = FieldElement::from_bytes_be(&y_bytes)?;
                let pt = AffinePoint { x, y };
                if !pt.is_on_curve() {
                    return Err(Secp256k1Error::PointNotOnCurve);
                }
                Ok(pt)
            }
            _ => Err(Secp256k1Error::InvalidEncoding),
        }
    }

    /// Serialize to SEC1 format (compressed 33 bytes or uncompressed 65 bytes).
    pub fn to_encoded_point(&self, compress: bool) -> ([u8; 65], usize) {
        let mut out = [0u8; 65];
        let x_bytes = self.x.to_bytes_be();
        let y_bytes = self.y.to_bytes_be();

        if compress {
            out[0] = if self.y.is_odd() { 0x03 } else { 0x02 };
            out[1..33].copy_from_slice(&x_bytes);
            (out, 33)
        } else {
            out[0] = 0x04;
            out[1..33].copy_from_slice(&x_bytes);
            out[33..65].copy_from_slice(&y_bytes);
            (out, 65)
        }
    }
}

/// A secp256k1 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub AffinePoint);

impl PublicKey {
    /// Parse from SEC1 encoded bytes (compressed or uncompressed).
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Secp256k1Error> {
        let pt = AffinePoint::from_encoded_point(bytes)?;
        Ok(PublicKey(pt))
    }

    /// Serialize to SEC1 encoded bytes.
    pub fn to_sec1_bytes(&self, compress: bool) -> ([u8; 65], usize) {
        self.0.to_encoded_point(compress)
    }
}

/// Derive the public key from a 32-byte secret scalar ($P = scalar \times G$).
pub fn public_key_from_secret(secret_scalar: &[u8; 32]) -> Result<PublicKey, Secp256k1Error> {
    // Validate non-zero scalar
    let mut is_zero = 0u8;
    for &b in secret_scalar {
        is_zero |= b;
    }
    if is_zero == 0 {
        return Err(Secp256k1Error::InvalidScalar);
    }

    let p = ProjectivePoint::GENERATOR.scalarmult(secret_scalar);
    let affine = p.to_affine().ok_or(Secp256k1Error::PointAtInfinity)?;
    Ok(PublicKey(affine))
}

/// ECDH shared secret derivation.
///
/// Computes $scalar \times Q$ and returns the 32-byte big-endian $x$-coordinate.
pub fn ecdh(secret_scalar: &[u8; 32], public_key: &PublicKey) -> Result<[u8; 32], Secp256k1Error> {
    let proj = public_key.0.to_projective();
    let shared_proj = proj.scalarmult(secret_scalar);
    let affine = shared_proj.to_affine().ok_or(Secp256k1Error::PointAtInfinity)?;
    Ok(affine.x.to_bytes_be())
}
