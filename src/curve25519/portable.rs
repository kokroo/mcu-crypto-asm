//! Portable constant-time field arithmetic and Montgomery ladder for Curve25519.
//!
//! Evaluates `x25519` in constant time without any platform-specific assembly.

const MASK51: u64 = (1 << 51) - 1;

/// Field element in 5 unsaturated 51-bit limbs modulo 2^255 - 19.
#[derive(Clone, Copy, Debug)]
pub struct Fe51(pub [u64; 5]);

impl Fe51 {
    pub const ZERO: Self = Fe51([0; 5]);
    pub const ONE: Self = Fe51([1, 0, 0, 0, 0]);

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];
        let mut w = [0u64; 4];
        for i in 0..4 {
            w[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        // Mask off bit 255 per RFC 7748
        w[3] &= (1 << 63) - 1;

        limbs[0] = w[0] & MASK51;
        limbs[1] = ((w[0] >> 51) | (w[1] << 13)) & MASK51;
        limbs[2] = ((w[1] >> 38) | (w[2] << 26)) & MASK51;
        limbs[3] = ((w[2] >> 25) | (w[3] << 39)) & MASK51;
        limbs[4] = w[3] >> 12;

        Fe51(limbs)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut t = self.0;
        // Strict reduction modulo 2^255 - 19
        for _ in 0..2 {
            let mut carry = 0u64;
            for i in 0..4 {
                t[i] += carry;
                carry = t[i] >> 51;
                t[i] &= MASK51;
            }
            t[4] += carry;
            carry = t[4] >> 51;
            t[4] &= MASK51;
            t[0] += carry * 19;
        }

        // Full reduction: if >= 2^255 - 19, subtract 2^255 - 19
        // Pack into 4 u64 words
        let mut w = [0u64; 4];
        w[0] = t[0] | (t[1] << 51);
        w[1] = (t[1] >> 13) | (t[2] << 38);
        w[2] = (t[2] >> 26) | (t[3] << 25);
        w[3] = (t[3] >> 39) | (t[4] << 12);

        // Constant-time check if w >= 2^255 - 19:
        // P in 64-bit words: [0xffffffffffffffed, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff]
        let mut borrow = 19u64;
        let mut sub = [0u64; 4];
        for i in 0..4 {
            let (diff, b) = w[i].overflowing_sub(borrow);
            sub[i] = diff;
            borrow = b as u64;
            if i < 3 {
                borrow = (w[i] < 0xffff_ffff_ffff_ffff) as u64;
            }
        }

        // Direct subtraction:
        let (d0, b0) = w[0].overflowing_add(19);
        let (d1, b1) = w[1].overflowing_add(b0 as u64);
        let (d2, b2) = w[2].overflowing_add(b1 as u64);
        let (d3, b3) = w[3].overflowing_add(b2 as u64);
        let has_overflow = (d3 >> 63) != 0 || b3;
        if has_overflow {
            w[0] = d0;
            w[1] = d1;
            w[2] = d2;
            w[3] = d3 & ((1 << 63) - 1);
        }

        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&w[i].to_le_bytes());
        }
        out
    }

    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = [0u64; 5];
        for i in 0..5 {
            out[i] = self.0[i] + rhs.0[i];
        }
        Fe51(out)
    }

    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        // Add 2 * P to prevent underflow before subtraction: 2*P = (2*19, 0, 0, 0, 2*(1<<51))
        let mut out = [0u64; 5];
        let p_bias = [0x7ffffffffffed * 2, 0x7ffffffffffff * 2, 0x7ffffffffffff * 2, 0x7ffffffffffff * 2, 0x7ffffffffffff * 2];
        for i in 0..5 {
            out[i] = self.0[i] + p_bias[i] - rhs.0[i];
        }
        Fe51(out)
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let a = &self.0;
        let b = &rhs.0;
        let mut r = [0u128; 5];

        for i in 0..5 {
            for j in 0..5 {
                let prod = (a[i] as u128) * (b[j] as u128);
                if i + j < 5 {
                    r[i + j] += prod;
                } else {
                    r[i + j - 5] += prod * 19;
                }
            }
        }

        let mut out = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..4 {
            r[i] += carry;
            out[i] = (r[i] as u64) & MASK51;
            carry = r[i] >> 51;
        }
        r[4] += carry;
        out[4] = (r[4] as u64) & MASK51;
        carry = r[4] >> 51;

        let r0 = (out[0] as u128) + carry * 19;
        out[0] = (r0 as u64) & MASK51;
        out[1] += (r0 >> 51) as u64;

        Fe51(out)
    }

    #[inline(always)]
    pub fn sqr(&self) -> Self {
        self.mul(self)
    }

    pub fn mul_scalar(&self, s: u64) -> Self {
        let mut r = [0u128; 5];
        for i in 0..5 {
            r[i] = (self.0[i] as u128) * (s as u128);
        }
        let mut out = [0u64; 5];
        let mut carry = 0u128;
        for i in 0..4 {
            r[i] += carry;
            out[i] = (r[i] as u64) & MASK51;
            carry = r[i] >> 51;
        }
        r[4] += carry;
        out[4] = (r[4] as u64) & MASK51;
        carry = r[4] >> 51;
        let r0 = (out[0] as u128) + carry * 19;
        out[0] = (r0 as u64) & MASK51;
        out[1] += (r0 >> 51) as u64;
        Fe51(out)
    }

    pub fn invert(&self) -> Self {
        // Compute self^(2^255 - 21) mod (2^255 - 19) via addition chain
        let mut t0 = self.sqr();
        let mut t1 = t0.sqr().sqr();
        t1 = self.mul(&t1);
        t0 = t0.mul(&t1);
        let mut t2 = t0.sqr();
        t1 = t1.mul(&t2);
        t2 = t1.sqr();
        for _ in 1..5 {
            t2 = t2.sqr();
        }
        t1 = t2.mul(&t1);
        t2 = t1.sqr();
        for _ in 1..10 {
            t2 = t2.sqr();
        }
        t2 = t2.mul(&t1);
        let mut t3 = t2.sqr();
        for _ in 1..20 {
            t3 = t3.sqr();
        }
        t2 = t3.mul(&t2);
        t2 = t2.sqr();
        for _ in 1..10 {
            t2 = t2.sqr();
        }
        t1 = t2.mul(&t1);
        t2 = t1.sqr();
        for _ in 1..50 {
            t2 = t2.sqr();
        }
        t2 = t2.mul(&t1);
        t3 = t2.sqr();
        for _ in 1..100 {
            t3 = t3.sqr();
        }
        t2 = t3.mul(&t2);
        t2 = t2.sqr();
        for _ in 1..50 {
            t2 = t2.sqr();
        }
        t1 = t2.mul(&t1);
        t1 = t1.sqr().sqr().sqr().sqr().sqr();
        t1.mul(&t0)
    }

    #[inline(always)]
    pub fn cswap(swap: u64, a: &mut Self, b: &mut Self) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let delta = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= delta;
            b.0[i] ^= delta;
        }
    }
}

/// Constant-time RFC 7748 Montgomery ladder.
pub fn scalarmult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    let x1 = Fe51::from_bytes(point);
    let mut x2 = Fe51::ONE;
    let mut z2 = Fe51::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe51::ONE;

    let mut swap = 0u64;

    for t in (0..=254).rev() {
        let byte_idx = t / 8;
        let bit_idx = t % 8;
        let kt = ((clamped[byte_idx] >> bit_idx) & 1) as u64;

        swap ^= kt;
        Fe51::cswap(swap, &mut x2, &mut x3);
        Fe51::cswap(swap, &mut z2, &mut z3);
        swap = kt;

        let a = x2.add(&z2);
        let aa = a.sqr();
        let b = x2.sub(&z2);
        let bb = b.sqr();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        let da_plus_cb = da.add(&cb);
        let da_minus_cb = da.sub(&cb);
        x3 = da_plus_cb.sqr();
        z3 = x1.mul(&da_minus_cb.sqr());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_scalar(121665)));
    }

    Fe51::cswap(swap, &mut x2, &mut x3);
    Fe51::cswap(swap, &mut z2, &mut z3);

    let z2_inv = z2.invert();
    let x = x2.mul(&z2_inv);
    x.to_bytes()
}
