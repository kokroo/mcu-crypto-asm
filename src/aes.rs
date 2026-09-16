//! Constant-time Fixsliced AES (Advanced Encryption Standard).
//!
//! Accelerated on Target 1 (ARM Cortex-M3/M4/M7/M33) using Alexandre Adomnicai's
//! Fixslicing assembly implementation (CHES 2020), providing the fastest
//! constant-time 32-bit software AES in existence.

#[cfg(cortex_m_thumb2)]
mod asm {
    use core::arch::global_asm;

    global_asm!(include_str!("../asm/cortex_m_aes_encrypt.S"), options(raw));
    global_asm!(
        include_str!("../asm/cortex_m_aes_keyschedule.S"),
        options(raw)
    );

    extern "C" {
        pub fn aes128_keyschedule_ffs_lut(rkeys: *mut u32, key: *const u8);
        pub fn aes128_encrypt_ffs(
            ctext0: *mut u8,
            ctext1: *mut u8,
            ptext0: *const u8,
            ptext1: *const u8,
            rkeys: *const u32,
        );
        pub fn aes256_keyschedule_ffs_lut(rkeys: *mut u32, key: *const u8);
        pub fn aes256_encrypt_ffs(
            ctext0: *mut u8,
            ctext1: *mut u8,
            ptext0: *const u8,
            ptext1: *const u8,
            rkeys: *const u32,
        );
    }
}

#[cfg(not(cortex_m_thumb2))]
pub(crate) mod ct {
    #[inline(always)]
    fn swapn(cl: u32, ch: u32, s: u32, x: u32, y: u32) -> (u32, u32) {
        let nx = (x & cl) | ((y & cl) << s);
        let ny = ((x & ch) >> s) | (y & ch);
        (nx, ny)
    }

    #[inline(always)]
    pub fn ortho(q: &mut [u32; 8]) {
        let (a, b) = swapn(0x55555555, 0xAAAAAAAA, 1, q[0], q[1]);
        q[0] = a;
        q[1] = b;
        let (a, b) = swapn(0x55555555, 0xAAAAAAAA, 1, q[2], q[3]);
        q[2] = a;
        q[3] = b;
        let (a, b) = swapn(0x55555555, 0xAAAAAAAA, 1, q[4], q[5]);
        q[4] = a;
        q[5] = b;
        let (a, b) = swapn(0x55555555, 0xAAAAAAAA, 1, q[6], q[7]);
        q[6] = a;
        q[7] = b;

        let (a, b) = swapn(0x33333333, 0xCCCCCCCC, 2, q[0], q[2]);
        q[0] = a;
        q[2] = b;
        let (a, b) = swapn(0x33333333, 0xCCCCCCCC, 2, q[1], q[3]);
        q[1] = a;
        q[3] = b;
        let (a, b) = swapn(0x33333333, 0xCCCCCCCC, 2, q[4], q[6]);
        q[4] = a;
        q[6] = b;
        let (a, b) = swapn(0x33333333, 0xCCCCCCCC, 2, q[5], q[7]);
        q[5] = a;
        q[7] = b;

        let (a, b) = swapn(0x0F0F0F0F, 0xF0F0F0F0, 4, q[0], q[4]);
        q[0] = a;
        q[4] = b;
        let (a, b) = swapn(0x0F0F0F0F, 0xF0F0F0F0, 4, q[1], q[5]);
        q[1] = a;
        q[5] = b;
        let (a, b) = swapn(0x0F0F0F0F, 0xF0F0F0F0, 4, q[2], q[6]);
        q[2] = a;
        q[6] = b;
        let (a, b) = swapn(0x0F0F0F0F, 0xF0F0F0F0, 4, q[3], q[7]);
        q[3] = a;
        q[7] = b;
    }

    #[inline(always)]
    pub fn bitslice_sbox(q: &mut [u32; 8]) {
        let x0 = q[7];
        let x1 = q[6];
        let x2 = q[5];
        let x3 = q[4];
        let x4 = q[3];
        let x5 = q[2];
        let x6 = q[1];
        let x7 = q[0];

        // Top linear transformation.
        let y14 = x3 ^ x5;
        let y13 = x0 ^ x6;
        let y9 = x0 ^ x3;
        let y8 = x0 ^ x5;
        let t0 = x1 ^ x2;
        let y1 = t0 ^ x7;
        let y4 = y1 ^ x3;
        let y12 = y13 ^ y14;
        let y2 = y1 ^ x0;
        let y5 = y1 ^ x6;
        let y3 = y5 ^ y8;
        let t1 = x4 ^ y12;
        let y15 = t1 ^ x5;
        let y20 = t1 ^ x1;
        let y6 = y15 ^ x7;
        let y10 = y15 ^ t0;
        let y11 = y20 ^ y9;
        let y7 = x7 ^ y11;
        let y17 = y10 ^ y11;
        let y19 = y10 ^ y8;
        let y16 = t0 ^ y11;
        let y21 = y13 ^ y16;
        let y18 = x0 ^ y16;

        // Non-linear section.
        let t2 = y12 & y15;
        let t3 = y3 & y6;
        let t4 = t3 ^ t2;
        let t5 = y4 & x7;
        let t6 = t5 ^ t2;
        let t7 = y13 & y16;
        let t8 = y5 & y1;
        let t9 = t8 ^ t7;
        let t10 = y2 & y7;
        let t11 = t10 ^ t7;
        let t12 = y9 & y11;
        let t13 = y14 & y17;
        let t14 = t13 ^ t12;
        let t15 = y8 & y10;
        let t16 = t15 ^ t12;
        let t17 = t4 ^ t14;
        let t18 = t6 ^ t16;
        let t19 = t9 ^ t14;
        let t20 = t11 ^ t16;
        let t21 = t17 ^ y20;
        let t22 = t18 ^ y19;
        let t23 = t19 ^ y21;
        let t24 = t20 ^ y18;

        let t25 = t21 ^ t22;
        let t26 = t21 & t23;
        let t27 = t24 ^ t26;
        let t28 = t25 & t27;
        let t29 = t28 ^ t22;
        let t30 = t23 ^ t24;
        let t31 = t22 ^ t26;
        let t32 = t31 & t30;
        let t33 = t32 ^ t24;
        let t34 = t23 ^ t33;
        let t35 = t27 ^ t33;
        let t36 = t24 & t35;
        let t37 = t36 ^ t34;
        let t38 = t27 ^ t36;
        let t39 = t29 & t38;
        let t40 = t25 ^ t39;

        let t41 = t40 ^ t37;
        let t42 = t29 ^ t33;
        let t43 = t29 ^ t40;
        let t44 = t33 ^ t37;
        let t45 = t42 ^ t41;
        let z0 = t44 & y15;
        let z1 = t37 & y6;
        let z2 = t33 & x7;
        let z3 = t43 & y16;
        let z4 = t40 & y1;
        let z5 = t29 & y7;
        let z6 = t42 & y11;
        let z7 = t45 & y17;
        let z8 = t41 & y10;
        let z9 = t44 & y12;
        let z10 = t37 & y3;
        let z11 = t33 & y4;
        let z12 = t43 & y13;
        let z13 = t40 & y5;
        let z14 = t29 & y2;
        let z15 = t42 & y9;
        let z16 = t45 & y14;
        let z17 = t41 & y8;

        // Bottom linear transformation.
        let t46 = z15 ^ z16;
        let t47 = z10 ^ z11;
        let t48 = z5 ^ z13;
        let t49 = z9 ^ z10;
        let t50 = z2 ^ z12;
        let t51 = z2 ^ z5;
        let t52 = z7 ^ z8;
        let t53 = z0 ^ z3;
        let t54 = z6 ^ z7;
        let t55 = z16 ^ z17;
        let t56 = z12 ^ t48;
        let t57 = t50 ^ t53;
        let t58 = z4 ^ t46;
        let t59 = z3 ^ t54;
        let t60 = t46 ^ t57;
        let t61 = z14 ^ t57;
        let t62 = t52 ^ t58;
        let t63 = t49 ^ t58;
        let t64 = z4 ^ t59;
        let t65 = t61 ^ t62;
        let t66 = z1 ^ t63;
        let s0 = t59 ^ t63;
        let s6 = t56 ^ !t62;
        let s7 = t48 ^ !t60;
        let t67 = t64 ^ t65;
        let s3 = t53 ^ t66;
        let s4 = t51 ^ t66;
        let s5 = t47 ^ t65;
        let s1 = t64 ^ !s3;
        let s2 = t55 ^ !t67;

        q[7] = s0;
        q[6] = s1;
        q[5] = s2;
        q[4] = s3;
        q[3] = s4;
        q[2] = s5;
        q[1] = s6;
        q[0] = s7;
    }

    #[inline(always)]
    pub fn shift_rows(q: &mut [u32; 8]) {
        for i in 0..8 {
            let x = q[i];
            q[i] = (x & 0x000000FF)
                | ((x & 0x0000FC00) >> 2)
                | ((x & 0x00000300) << 6)
                | ((x & 0x00F00000) >> 4)
                | ((x & 0x000F0000) << 4)
                | ((x & 0xC0000000) >> 6)
                | ((x & 0x3F000000) << 2);
        }
    }

    #[inline(always)]
    fn rotr16(x: u32) -> u32 {
        x.rotate_right(16)
    }

    #[inline(always)]
    pub fn mix_columns(q: &mut [u32; 8]) {
        let q0 = q[0];
        let q1 = q[1];
        let q2 = q[2];
        let q3 = q[3];
        let q4 = q[4];
        let q5 = q[5];
        let q6 = q[6];
        let q7 = q[7];
        let r0 = q0.rotate_right(8);
        let r1 = q1.rotate_right(8);
        let r2 = q2.rotate_right(8);
        let r3 = q3.rotate_right(8);
        let r4 = q4.rotate_right(8);
        let r5 = q5.rotate_right(8);
        let r6 = q6.rotate_right(8);
        let r7 = q7.rotate_right(8);

        q[0] = q7 ^ r7 ^ r0 ^ rotr16(q0 ^ r0);
        q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr16(q1 ^ r1);
        q[2] = q1 ^ r1 ^ r2 ^ rotr16(q2 ^ r2);
        q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr16(q3 ^ r3);
        q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr16(q4 ^ r4);
        q[5] = q4 ^ r4 ^ r5 ^ rotr16(q5 ^ r5);
        q[6] = q5 ^ r5 ^ r6 ^ rotr16(q6 ^ r6);
        q[7] = q6 ^ r6 ^ r7 ^ rotr16(q7 ^ r7);
    }

    #[inline(always)]
    pub fn add_round_key(q: &mut [u32; 8], sk: &[u32]) {
        for i in 0..8 {
            q[i] ^= sk[i];
        }
    }

    fn sub_word(x: u32) -> u32 {
        let mut q = [x; 8];
        ortho(&mut q);
        bitslice_sbox(&mut q);
        ortho(&mut q);
        q[0]
    }

    const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    pub fn keyschedule(key: &[u8], num_rounds: usize, rkeys: &mut [u32]) {
        let nk = key.len() / 4;
        let nkf = (num_rounds + 1) * 4;
        let mut skey = [0u32; 120];
        let mut tmp = 0u32;

        for i in 0..nk {
            tmp = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
            skey[i << 1] = tmp;
            skey[(i << 1) + 1] = tmp;
        }

        let mut j = 0;
        let mut k = 0;
        for i in nk..nkf {
            if j == 0 {
                tmp = tmp.rotate_right(8);
                tmp = sub_word(tmp) ^ RCON[k];
            } else if nk > 6 && j == 4 {
                tmp = sub_word(tmp);
            }
            tmp ^= skey[(i - nk) << 1];
            skey[i << 1] = tmp;
            skey[(i << 1) + 1] = tmp;
            j += 1;
            if j == nk {
                j = 0;
                k += 1;
            }
        }

        for i in (0..nkf).step_by(4) {
            let chunk = &mut skey[(i << 1)..(i << 1) + 8];
            let mut q = [
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ];
            ortho(&mut q);
            chunk.copy_from_slice(&q);
        }

        // Expand into rkeys: each 32-bit word produces two bitsliced words
        for u in 0..nkf {
            let comp = (skey[u * 2] & 0x55555555) | (skey[u * 2 + 1] & 0xAAAAAAAA);
            let x = comp & 0x55555555;
            rkeys[u * 2] = x | (x << 1);
            let y = comp & 0xAAAAAAAA;
            rkeys[u * 2 + 1] = y | (y >> 1);
        }
    }

    pub fn bitslice_encrypt(num_rounds: usize, rkeys: &[u32], q: &mut [u32; 8]) {
        add_round_key(q, &rkeys[0..8]);
        for u in 1..num_rounds {
            bitslice_sbox(q);
            shift_rows(q);
            mix_columns(q);
            add_round_key(q, &rkeys[u * 8..u * 8 + 8]);
        }
        bitslice_sbox(q);
        shift_rows(q);
        add_round_key(q, &rkeys[num_rounds * 8..num_rounds * 8 + 8]);
    }
}

#[derive(Clone)]
pub struct Aes128 {
    rkeys: [u32; 88],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut rkeys = [0u32; 88];
        #[cfg(cortex_m_thumb2)]
        unsafe {
            asm::aes128_keyschedule_ffs_lut(rkeys.as_mut_ptr(), key.as_ptr());
        }
        #[cfg(not(cortex_m_thumb2))]
        {
            ct::keyschedule(key, 10, &mut rkeys);
        }
        Aes128 { rkeys }
    }

    /// Encrypt two 16-byte blocks in parallel using 2-way interleaved bitslicing / fixslicing.
    pub fn encrypt_two_blocks(
        &self,
        p0: &[u8; 16],
        p1: &[u8; 16],
        c0: &mut [u8; 16],
        c1: &mut [u8; 16],
    ) {
        #[cfg(cortex_m_thumb2)]
        unsafe {
            asm::aes128_encrypt_ffs(
                c0.as_mut_ptr(),
                c1.as_mut_ptr(),
                p0.as_ptr(),
                p1.as_ptr(),
                self.rkeys.as_ptr(),
            );
        }
        #[cfg(not(cortex_m_thumb2))]
        {
            let mut q = [0u32; 8];
            q[0] = u32::from_le_bytes(p0[0..4].try_into().unwrap());
            q[1] = u32::from_le_bytes(p1[0..4].try_into().unwrap());
            q[2] = u32::from_le_bytes(p0[4..8].try_into().unwrap());
            q[3] = u32::from_le_bytes(p1[4..8].try_into().unwrap());
            q[4] = u32::from_le_bytes(p0[8..12].try_into().unwrap());
            q[5] = u32::from_le_bytes(p1[8..12].try_into().unwrap());
            q[6] = u32::from_le_bytes(p0[12..16].try_into().unwrap());
            q[7] = u32::from_le_bytes(p1[12..16].try_into().unwrap());

            ct::ortho(&mut q);
            ct::bitslice_encrypt(10, &self.rkeys, &mut q);
            ct::ortho(&mut q);

            c0[0..4].copy_from_slice(&q[0].to_le_bytes());
            c1[0..4].copy_from_slice(&q[1].to_le_bytes());
            c0[4..8].copy_from_slice(&q[2].to_le_bytes());
            c1[4..8].copy_from_slice(&q[3].to_le_bytes());
            c0[8..12].copy_from_slice(&q[4].to_le_bytes());
            c1[8..12].copy_from_slice(&q[5].to_le_bytes());
            c0[12..16].copy_from_slice(&q[6].to_le_bytes());
            c1[12..16].copy_from_slice(&q[7].to_le_bytes());
        }
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]) {
        let mut dummy = [0u8; 16];
        self.encrypt_two_blocks(ptext, ptext, ctext, &mut dummy);
    }
}

#[derive(Clone)]
pub struct Aes256 {
    rkeys: [u32; 120],
}

impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut rkeys = [0u32; 120];
        #[cfg(cortex_m_thumb2)]
        unsafe {
            asm::aes256_keyschedule_ffs_lut(rkeys.as_mut_ptr(), key.as_ptr());
        }
        #[cfg(not(cortex_m_thumb2))]
        {
            ct::keyschedule(key, 14, &mut rkeys);
        }
        Aes256 { rkeys }
    }

    /// Encrypt two 16-byte blocks in parallel using 2-way interleaved bitslicing / fixslicing.
    pub fn encrypt_two_blocks(
        &self,
        p0: &[u8; 16],
        p1: &[u8; 16],
        c0: &mut [u8; 16],
        c1: &mut [u8; 16],
    ) {
        #[cfg(cortex_m_thumb2)]
        unsafe {
            asm::aes256_encrypt_ffs(
                c0.as_mut_ptr(),
                c1.as_mut_ptr(),
                p0.as_ptr(),
                p1.as_ptr(),
                self.rkeys.as_ptr(),
            );
        }
        #[cfg(not(cortex_m_thumb2))]
        {
            let mut q = [0u32; 8];
            q[0] = u32::from_le_bytes(p0[0..4].try_into().unwrap());
            q[1] = u32::from_le_bytes(p1[0..4].try_into().unwrap());
            q[2] = u32::from_le_bytes(p0[4..8].try_into().unwrap());
            q[3] = u32::from_le_bytes(p1[4..8].try_into().unwrap());
            q[4] = u32::from_le_bytes(p0[8..12].try_into().unwrap());
            q[5] = u32::from_le_bytes(p1[8..12].try_into().unwrap());
            q[6] = u32::from_le_bytes(p0[12..16].try_into().unwrap());
            q[7] = u32::from_le_bytes(p1[12..16].try_into().unwrap());

            ct::ortho(&mut q);
            ct::bitslice_encrypt(14, &self.rkeys, &mut q);
            ct::ortho(&mut q);

            c0[0..4].copy_from_slice(&q[0].to_le_bytes());
            c1[0..4].copy_from_slice(&q[1].to_le_bytes());
            c0[4..8].copy_from_slice(&q[2].to_le_bytes());
            c1[4..8].copy_from_slice(&q[3].to_le_bytes());
            c0[8..12].copy_from_slice(&q[4].to_le_bytes());
            c1[8..12].copy_from_slice(&q[5].to_le_bytes());
            c0[12..16].copy_from_slice(&q[6].to_le_bytes());
            c1[12..16].copy_from_slice(&q[7].to_le_bytes());
        }
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]) {
        let mut dummy = [0u8; 16];
        self.encrypt_two_blocks(ptext, ptext, ctext, &mut dummy);
    }
}

// ---------------------------------------------------------------------------
// AES modes and algorithms
// ---------------------------------------------------------------------------

use crate::ghash::{Ghash, Htable};

#[inline]
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(&mut *buf);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AesError {
    InvalidInput,
    InvalidSignature,
}

/// Facade over the two fixsliced AES cores so the mode helpers below are
/// generic over the key size.
pub trait AesEncrypt {
    fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]);
    fn encrypt_two_blocks(
        &self,
        p0: &[u8; 16],
        p1: &[u8; 16],
        c0: &mut [u8; 16],
        c1: &mut [u8; 16],
    );
}

impl AesEncrypt for Aes128 {
    #[inline]
    fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]) {
        Aes128::encrypt_block(self, ptext, ctext);
    }
    #[inline]
    fn encrypt_two_blocks(
        &self,
        p0: &[u8; 16],
        p1: &[u8; 16],
        c0: &mut [u8; 16],
        c1: &mut [u8; 16],
    ) {
        Aes128::encrypt_two_blocks(self, p0, p1, c0, c1);
    }
}

impl AesEncrypt for Aes256 {
    #[inline]
    fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]) {
        Aes256::encrypt_block(self, ptext, ctext);
    }
    #[inline]
    fn encrypt_two_blocks(
        &self,
        p0: &[u8; 16],
        p1: &[u8; 16],
        c0: &mut [u8; 16],
        c1: &mut [u8; 16],
    ) {
        Aes256::encrypt_two_blocks(self, p0, p1, c0, c1);
    }
}

pub trait AesInit<const KEY_LEN: usize>: AesEncrypt + Sized {
    fn new(key: &[u8; KEY_LEN]) -> Self;
}

impl AesInit<16> for Aes128 {
    fn new(key: &[u8; 16]) -> Self {
        Aes128::new(key)
    }
}

impl AesInit<32> for Aes256 {
    fn new(key: &[u8; 32]) -> Self {
        Aes256::new(key)
    }
}

#[inline]
pub fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// Increment the rightmost 32 bits of the counter block (GCM, SP 800-38D).
#[inline]
pub fn inc32(blk: &mut [u8; 16]) {
    let c = u32::from_be_bytes(blk[12..16].try_into().unwrap()).wrapping_add(1);
    blk[12..16].copy_from_slice(&c.to_be_bytes());
}

/// Increment the full 128-bit big-endian counter (CTR, SP 800-38A).
#[inline]
pub fn inc128(blk: &mut [u8; 16]) {
    for i in (0..16).rev() {
        let (v, carry) = blk[i].overflowing_add(1);
        blk[i] = v;
        if !carry {
            break;
        }
    }
}

/// XOR `data` with the keystream `E(counter)`, `E(inc(counter))`, ... in
/// place, processing two blocks per call where possible.
pub fn ctr_apply<E: AesEncrypt>(
    aes: &E,
    counter: &mut [u8; 16],
    inc: fn(&mut [u8; 16]),
    data: &mut [u8],
) {
    let mut chunks = data.chunks_exact_mut(32);
    for pair in &mut chunks {
        let (l, r) = pair.split_at_mut(16);
        let c0: &mut [u8; 16] = l.try_into().unwrap();
        let c1: &mut [u8; 16] = r.try_into().unwrap();
        let (m0, m1) = (*c0, *c1);
        let mut k0 = [0u8; 16];
        let mut k1 = [0u8; 16];
        let b0 = *counter;
        inc(counter);
        aes.encrypt_block(&b0, &mut k0);
        let b1 = *counter;
        inc(counter);
        aes.encrypt_block(&b1, &mut k1);
        for i in 0..16 {
            c0[i] = m0[i] ^ k0[i];
            c1[i] = m1[i] ^ k1[i];
        }
    }
    let rem = chunks.into_remainder();
    let mut chunks16 = rem.chunks_exact_mut(16);
    for blk in &mut chunks16 {
        let b: &mut [u8; 16] = blk.try_into().unwrap();
        let m = *b;
        let mut k = [0u8; 16];
        let ctr = *counter;
        inc(counter);
        aes.encrypt_block(&ctr, &mut k);
        for i in 0..16 {
            b[i] = m[i] ^ k[i];
        }
    }
    let tail = chunks16.into_remainder();
    if !tail.is_empty() {
        let mut k = [0u8; 16];
        let ctr = *counter;
        inc(counter);
        aes.encrypt_block(&ctr, &mut k);
        for i in 0..tail.len() {
            tail[i] ^= k[i];
        }
    }
}

// ---------------------------------------------------------------------------
// GCM (NIST SP 800-38D)
// ---------------------------------------------------------------------------

/// GHASH subkey table: H = E_K(0^128).
pub fn gcm_htable<E: AesEncrypt>(aes: &E) -> Htable {
    let mut h = [0u8; 16];
    aes.encrypt_block(&[0u8; 16], &mut h);
    let ht = Htable::new(&h);
    wipe(&mut h);
    ht
}

/// Feed `data` into GHASH, zero-padding a trailing partial block.
pub fn ghash_update_padded(g: &mut Ghash, data: &[u8]) {
    let mut chunks = data.chunks_exact(16);
    for blk in &mut chunks {
        g.update_block(blk.try_into().unwrap());
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut blk = [0u8; 16];
        blk[..rem.len()].copy_from_slice(rem);
        g.update_block(&blk);
    }
}

/// The closing `[len(A)]_64 || [len(C)]_64` block of the GHASH input.
pub fn gcm_length_block(aad_len: usize, ct_len: usize) -> [u8; 16] {
    let mut blk = [0u8; 16];
    blk[0..8].copy_from_slice(&((aad_len as u64).wrapping_mul(8)).to_be_bytes());
    blk[8..16].copy_from_slice(&((ct_len as u64).wrapping_mul(8)).to_be_bytes());
    blk
}

/// Derive J0 from the nonce (SP 800-38D section 5.2).
pub fn gcm_j0<E: AesEncrypt>(
    _aes: &E,
    htable: &Htable,
    nonce: &[u8],
) -> Result<[u8; 16], AesError> {
    if nonce.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        Ok(j0)
    } else {
        if nonce.is_empty() {
            return Err(AesError::InvalidInput);
        }
        let mut g = Ghash::from_htable(*htable);
        ghash_update_padded(&mut g, nonce);
        g.update_block(&gcm_length_block(0, nonce.len()));
        Ok(g.finalize())
    }
}

/// GCM authentication tag: `GHASH(A || pad || C || pad || len) ^ E_K(J0)`.
pub fn gcm_tag<E: AesEncrypt>(
    aes: &E,
    htable: &Htable,
    j0: &[u8; 16],
    aad: &[u8],
    ct: &[u8],
) -> [u8; 16] {
    let mut g = Ghash::from_htable(*htable);
    ghash_update_padded(&mut g, aad);
    ghash_update_padded(&mut g, ct);
    g.update_block(&gcm_length_block(aad.len(), ct.len()));
    let mut s = g.finalize();
    let mut e_j0 = [0u8; 16];
    aes.encrypt_block(j0, &mut e_j0);
    xor_block(&mut s, &e_j0);
    wipe(&mut e_j0);
    s
}

/// First data counter block: inc32(J0).
#[inline]
pub fn gcm_ctr_start(j0: &[u8; 16]) -> [u8; 16] {
    let mut c = *j0;
    inc32(&mut c);
    c
}

/// Key schedule for the AES-GCM driver.
pub struct AesGcm<E, const KEY_LEN: usize> {
    pub aes: E,
    pub key: [u8; KEY_LEN],
}

impl<E: AesInit<KEY_LEN>, const KEY_LEN: usize> Clone for AesGcm<E, KEY_LEN> {
    fn clone(&self) -> Self {
        Self {
            aes: E::new(&self.key),
            key: self.key,
        }
    }
}

impl<E: AesInit<KEY_LEN>, const KEY_LEN: usize> AesGcm<E, KEY_LEN> {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            aes: E::new(key),
            key: *key,
        }
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), AesError> {
        let htable = gcm_htable(&self.aes);
        let j0 = gcm_j0(&self.aes, &htable, nonce)?;
        let mut ctr = gcm_ctr_start(&j0);
        ctr_apply(&self.aes, &mut ctr, inc32, buf);
        let mut t = gcm_tag(&self.aes, &htable, &j0, aad, buf);
        tag.copy_from_slice(&t);
        wipe(&mut t);
        Ok(())
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), AesError> {
        let htable = gcm_htable(&self.aes);
        let j0 = gcm_j0(&self.aes, &htable, nonce)?;
        let mut t = gcm_tag(&self.aes, &htable, &j0, aad, buf);
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= t[i] ^ tag[i];
        }
        wipe(&mut t);
        if diff != 0 {
            // Never release unauthenticated plaintext.
            for b in buf.iter_mut() {
                *b = 0;
            }
            return Err(AesError::InvalidSignature);
        }
        let mut ctr = gcm_ctr_start(&j0);
        ctr_apply(&self.aes, &mut ctr, inc32, buf);
        Ok(())
    }
}

pub type Aes128Gcm = AesGcm<Aes128, 16>;
pub type Aes256Gcm = AesGcm<Aes256, 32>;

// ---------------------------------------------------------------------------
// CTR (NIST SP 800-38A)
// ---------------------------------------------------------------------------

/// Streaming keystream state for AES-CTR.
#[derive(Clone)]
pub struct AesCtr<E> {
    pub aes: E,
    pub counter: [u8; 16],
    pub keystream: [u8; 16],
    /// Number of keystream bytes already consumed from `keystream`;
    /// 16 means the buffer is exhausted and a fresh block is needed.
    pub pos: usize,
}

impl<E: AesEncrypt> AesCtr<E> {
    pub fn new(aes: E, iv: &[u8; 16]) -> Self {
        Self {
            aes,
            counter: *iv,
            keystream: [0u8; 16],
            pos: 16,
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            if self.pos == 16 {
                if data.len() - offset >= 32 {
                    let bulk = (data.len() - offset) & !15;
                    ctr_apply(
                        &self.aes,
                        &mut self.counter,
                        inc128,
                        &mut data[offset..offset + bulk],
                    );
                    offset += bulk;
                    if offset == data.len() {
                        return;
                    }
                }
                self.aes.encrypt_block(&self.counter, &mut self.keystream);
                inc128(&mut self.counter);
                self.pos = 0;
            }
            let n = core::cmp::min(16 - self.pos, data.len() - offset);
            for j in 0..n {
                data[offset + j] ^= self.keystream[self.pos + j];
            }
            self.pos += n;
            offset += n;
        }
    }
}

pub type Aes128Ctr = AesCtr<Aes128>;
pub type Aes256Ctr = AesCtr<Aes256>;

impl Aes128Ctr {
    pub fn init(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self::new(Aes128::new(key), iv)
    }
}

impl Aes256Ctr {
    pub fn init(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self::new(Aes256::new(key), iv)
    }
}

// ---------------------------------------------------------------------------
// CMAC (NIST SP 800-38B)
// ---------------------------------------------------------------------------

/// GF(2^128) doubling (multiply by x; reduction polynomial
/// x^128 + x^7 + x^2 + x + 1).
#[inline]
pub fn cmac_double(blk: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let carry = blk[0] >> 7;
    for i in 0..15 {
        out[i] = (blk[i] << 1) | (blk[i + 1] >> 7);
    }
    out[15] = blk[15] << 1;
    if carry != 0 {
        out[15] ^= 0x87;
    }
    out
}

/// Streaming CMAC state shared by both key sizes. Only subkey K1 is stored;
/// K2 = dbl(K1) is derived in `finalize`.
pub struct CmacState<E> {
    pub aes: E,
    pub state: [u8; 16],
    pub buffer: [u8; 16],
    pub buf_len: usize,
    pub k1: [u8; 16],
}

impl<E: AesEncrypt> CmacState<E> {
    pub fn new(aes: E) -> Self {
        let mut l = [0u8; 16];
        aes.encrypt_block(&[0u8; 16], &mut l);
        let k1 = cmac_double(&l);
        wipe(&mut l);
        Self {
            aes,
            state: [0u8; 16],
            buffer: [0u8; 16],
            buf_len: 0,
            k1,
        }
    }

    pub fn mac_feed(&mut self, blk: &[u8; 16]) {
        let mut x = *blk;
        xor_block(&mut x, &self.state);
        self.aes.encrypt_block(&x, &mut self.state);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        loop {
            if self.buf_len == 16 {
                if data.is_empty() {
                    return;
                }
                let blk = self.buffer;
                self.mac_feed(&blk);
                self.buf_len = 0;
            }
            if data.is_empty() {
                return;
            }
            let n = core::cmp::min(16 - self.buf_len, data.len());
            self.buffer[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
        }
    }

    pub fn finalize(self) -> [u8; 16] {
        let k2 = cmac_double(&self.k1);
        let (blk, key) = if self.buf_len == 16 {
            (self.buffer, self.k1)
        } else {
            let mut b = self.buffer;
            for i in self.buf_len..16 {
                b[i] = 0;
            }
            b[self.buf_len] = 0x80;
            (b, k2)
        };
        let mut x = blk;
        xor_block(&mut x, &key);
        xor_block(&mut x, &self.state);
        let mut out = [0u8; 16];
        self.aes.encrypt_block(&x, &mut out);
        out
    }

    pub fn reset(&mut self) {
        self.state = [0u8; 16];
        self.buf_len = 0;
    }
}

pub struct AesCmac<E, const KEY_LEN: usize> {
    pub inner: CmacState<E>,
    pub key: [u8; KEY_LEN],
}

impl<E: AesInit<KEY_LEN>, const KEY_LEN: usize> Clone for AesCmac<E, KEY_LEN> {
    fn clone(&self) -> Self {
        Self {
            inner: CmacState::new(E::new(&self.key)),
            key: self.key,
        }
    }
}

impl<E: AesInit<KEY_LEN>, const KEY_LEN: usize> AesCmac<E, KEY_LEN> {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            inner: CmacState::new(E::new(key)),
            key: *key,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self, out: &mut [u8; 16]) {
        *out = self.inner.finalize();
    }

    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

pub type Aes128Cmac = AesCmac<Aes128, 16>;
pub type Aes256Cmac = AesCmac<Aes256, 32>;

// ---------------------------------------------------------------------------
// CCM (NIST SP 800-38C / RFC 3610)
// ---------------------------------------------------------------------------

pub fn ccm_params(nonce_len: usize, tag_len: usize) -> Result<(usize, usize), AesError> {
    if !(7..=13).contains(&nonce_len) {
        return Err(AesError::InvalidInput);
    }
    match tag_len {
        4 | 6 | 8 | 10 | 12 | 14 | 16 => {}
        _ => return Err(AesError::InvalidInput),
    }
    Ok((15 - nonce_len, tag_len))
}

pub fn ccm_check_len(q: usize, msg_len: usize) -> Result<(), AesError> {
    if q < 8 && (msg_len as u128) >= (1u128 << (8 * q)) {
        return Err(AesError::InvalidInput);
    }
    Ok(())
}

pub struct CcmMac<'a, E> {
    pub aes: &'a E,
    pub y: [u8; 16],
    pub blk: [u8; 16],
    pub len: usize,
}

impl<'a, E: AesEncrypt> CcmMac<'a, E> {
    pub fn new(aes: &'a E) -> Self {
        Self {
            aes,
            y: [0u8; 16],
            blk: [0u8; 16],
            len: 0,
        }
    }

    pub fn feed_block(&mut self, blk: &[u8; 16]) {
        let mut x = *blk;
        xor_block(&mut x, &self.y);
        self.aes.encrypt_block(&x, &mut self.y);
    }

    pub fn feed(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let n = core::cmp::min(16 - self.len, data.len());
            self.blk[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len == 16 {
                let b = self.blk;
                self.feed_block(&b);
                self.len = 0;
            }
        }
    }

    pub fn feed_padded(&mut self) {
        if self.len > 0 {
            for i in self.len..16 {
                self.blk[i] = 0;
            }
            let b = self.blk;
            self.feed_block(&b);
            self.len = 0;
        }
    }
}

pub fn ccm_cbc_mac<E: AesEncrypt>(
    aes: &E,
    q: usize,
    t: usize,
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
) -> Result<[u8; 16], AesError> {
    ccm_check_len(q, msg.len())?;

    let mut mac = CcmMac::new(aes);

    // B0: flags || nonce || msg length (q bytes, big-endian).
    let mut b0 = [0u8; 16];
    b0[0] =
        (if aad.is_empty() { 0u8 } else { 0x40 }) | ((((t - 2) / 2) as u8) << 3) | (q - 1) as u8;
    b0[1..1 + nonce.len()].copy_from_slice(nonce);
    let mlen = (msg.len() as u128).to_be_bytes();
    b0[16 - q..16].copy_from_slice(&mlen[16 - q..16]);
    mac.feed_block(&b0);

    if !aad.is_empty() {
        let mut hdr = [0u8; 16];
        let off = if aad.len() < 0xFF00 {
            hdr[0..2].copy_from_slice(&(aad.len() as u16).to_be_bytes());
            2
        } else if aad.len() as u64 <= u32::MAX as u64 {
            hdr[0] = 0xFF;
            hdr[1] = 0xFE;
            hdr[2..6].copy_from_slice(&(aad.len() as u32).to_be_bytes());
            6
        } else {
            return Err(AesError::InvalidInput);
        };
        let n = core::cmp::min(16 - off, aad.len());
        hdr[off..off + n].copy_from_slice(&aad[..n]);
        mac.feed(&hdr[..off + n]);
        mac.feed(&aad[n..]);
        mac.feed_padded();
    }

    mac.feed(msg);
    mac.feed_padded();

    Ok(mac.y)
}

pub fn ccm_ctr_block(q: usize, nonce: &[u8], ctr: u64) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = (q - 1) as u8;
    a[1..1 + nonce.len()].copy_from_slice(nonce);
    let c = ctr.to_be_bytes();
    a[16 - q..16].copy_from_slice(&c[8 - q..8]);
    a
}

pub fn ccm_ctr_crypt<E: AesEncrypt>(aes: &E, q: usize, nonce: &[u8], start: u64, data: &mut [u8]) {
    let mut ctr = start;
    let mut offset = 0;
    while offset < data.len() {
        let a = ccm_ctr_block(q, nonce, ctr);
        ctr = ctr.wrapping_add(1);
        let mut k = [0u8; 16];
        aes.encrypt_block(&a, &mut k);
        let n = core::cmp::min(16, data.len() - offset);
        for j in 0..n {
            data[offset + j] ^= k[j];
        }
        offset += n;
    }
}

pub struct AesCcm<E, const KEY_LEN: usize> {
    pub aes: E,
    pub key: [u8; KEY_LEN],
}

impl<E: AesInit<KEY_LEN>, const KEY_LEN: usize> Clone for AesCcm<E, KEY_LEN> {
    fn clone(&self) -> Self {
        Self {
            aes: E::new(&self.key),
            key: self.key,
        }
    }
}

impl<E: AesInit<KEY_LEN>, const KEY_LEN: usize> AesCcm<E, KEY_LEN> {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            aes: E::new(key),
            key: *key,
        }
    }

    pub fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), AesError> {
        let (q, t) = ccm_params(nonce.len(), tag.len())?;
        let mac = ccm_cbc_mac(&self.aes, q, t, nonce, aad, buf)?;
        ccm_ctr_crypt(&self.aes, q, nonce, 1, buf);
        let mut s0 = [0u8; 16];
        self.aes.encrypt_block(&ccm_ctr_block(q, nonce, 0), &mut s0);
        for i in 0..t {
            tag[i] = mac[i] ^ s0[i];
        }
        wipe(&mut s0);
        Ok(())
    }

    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), AesError> {
        let (q, t) = ccm_params(nonce.len(), tag.len())?;
        ccm_ctr_crypt(&self.aes, q, nonce, 1, buf);
        let mac = ccm_cbc_mac(&self.aes, q, t, nonce, aad, buf)?;
        let mut s0 = [0u8; 16];
        self.aes.encrypt_block(&ccm_ctr_block(q, nonce, 0), &mut s0);
        let mut diff = 0u8;
        for i in 0..t {
            diff |= mac[i] ^ s0[i] ^ tag[i];
        }
        wipe(&mut s0);
        if diff != 0 {
            return Err(AesError::InvalidSignature);
        }
        Ok(())
    }
}

pub type Aes128Ccm = AesCcm<Aes128, 16>;
pub type Aes256Ccm = AesCcm<Aes256, 32>;

// ---------------------------------------------------------------------------
// AES ECB / CBC (FIPS 197 Software AES & Raw Inverse Cipher)
// ---------------------------------------------------------------------------

pub fn aes_xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1B)
}

pub fn aes_gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = aes_xtime(a);
        b >>= 1;
    }
    p
}

pub fn aes_sboxes() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 255];
    let mut log = [0u8; 256];
    let mut x = 1u8;
    for i in 0..255 {
        exp[i] = x;
        log[x as usize] = i as u8;
        x = aes_gmul(x, 3);
    }

    let mut sbox = [0u8; 256];
    let mut isbox = [0u8; 256];
    for a in 0..256usize {
        let inv = if a == 0 {
            0
        } else {
            exp[(255 - log[a] as usize) % 255]
        };
        let mut b = inv;
        let mut t = inv;
        for _ in 0..4 {
            t = t.rotate_left(1);
            b ^= t;
        }
        b ^= 0x63;
        sbox[a] = b;
        isbox[b as usize] = a as u8;
    }
    (sbox, isbox)
}

pub fn aes_expand_key<const NK: usize, const ROUNDS: usize>(
    key: &[u8],
    rk: &mut [u8],
    sbox: &[u8; 256],
) {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    rk[..NK * 4].copy_from_slice(&key[..NK * 4]);
    let mut bytes = NK * 4;
    let mut rcon = 0usize;
    let mut temp = [0u8; 4];
    while bytes < 16 * (ROUNDS + 1) {
        temp.copy_from_slice(&rk[bytes - 4..bytes]);
        if bytes % (NK * 4) == 0 {
            temp.rotate_left(1);
            for b in temp.iter_mut() {
                *b = sbox[*b as usize];
            }
            temp[0] ^= RCON[rcon];
            rcon += 1;
        } else if NK > 6 && bytes % (NK * 4) == 16 {
            for b in temp.iter_mut() {
                *b = sbox[*b as usize];
            }
        }
        for i in 0..4 {
            rk[bytes + i] = rk[bytes - NK * 4 + i] ^ temp[i];
        }
        bytes += 4;
    }
}

pub fn aes_add_round_key(block: &mut [u8; 16], rk: &[u8]) {
    for i in 0..16 {
        block[i] ^= rk[i];
    }
}

pub fn aes_sub_bytes(block: &mut [u8; 16], sbox: &[u8; 256]) {
    for b in block.iter_mut() {
        *b = sbox[*b as usize];
    }
}

pub fn aes_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    s[0] = t[0];
    s[4] = t[4];
    s[8] = t[8];
    s[12] = t[12];
    s[1] = t[5];
    s[5] = t[9];
    s[9] = t[13];
    s[13] = t[1];
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    s[3] = t[15];
    s[7] = t[3];
    s[11] = t[7];
    s[15] = t[11];
}

pub fn aes_inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    s[0] = t[0];
    s[4] = t[4];
    s[8] = t[8];
    s[12] = t[12];
    s[1] = t[13];
    s[5] = t[1];
    s[9] = t[5];
    s[13] = t[9];
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    s[3] = t[7];
    s[7] = t[11];
    s[11] = t[15];
    s[15] = t[3];
}

pub fn aes_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = aes_gmul(a0, 2) ^ aes_gmul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ aes_gmul(a1, 2) ^ aes_gmul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ aes_gmul(a2, 2) ^ aes_gmul(a3, 3);
        s[i + 3] = aes_gmul(a0, 3) ^ a1 ^ a2 ^ aes_gmul(a3, 2);
    }
}

pub fn aes_inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = aes_gmul(a0, 14) ^ aes_gmul(a1, 11) ^ aes_gmul(a2, 13) ^ aes_gmul(a3, 9);
        s[i + 1] = aes_gmul(a0, 9) ^ aes_gmul(a1, 14) ^ aes_gmul(a2, 11) ^ aes_gmul(a3, 13);
        s[i + 2] = aes_gmul(a0, 13) ^ aes_gmul(a1, 9) ^ aes_gmul(a2, 14) ^ aes_gmul(a3, 11);
        s[i + 3] = aes_gmul(a0, 11) ^ aes_gmul(a1, 13) ^ aes_gmul(a2, 9) ^ aes_gmul(a3, 14);
    }
}

pub fn aes_encrypt_block(block: &mut [u8; 16], rk: &[u8], rounds: usize, sbox: &[u8; 256]) {
    aes_add_round_key(block, &rk[..16]);
    for r in 1..rounds {
        aes_sub_bytes(block, sbox);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, &rk[16 * r..16 * r + 16]);
    }
    aes_sub_bytes(block, sbox);
    aes_shift_rows(block);
    aes_add_round_key(block, &rk[16 * rounds..16 * rounds + 16]);
}

pub fn aes_decrypt_block(block: &mut [u8; 16], rk: &[u8], rounds: usize, isbox: &[u8; 256]) {
    aes_add_round_key(block, &rk[16 * rounds..16 * rounds + 16]);
    for r in (1..rounds).rev() {
        aes_inv_shift_rows(block);
        aes_sub_bytes(block, isbox);
        aes_add_round_key(block, &rk[16 * r..16 * r + 16]);
        aes_inv_mix_columns(block);
    }
    aes_inv_shift_rows(block);
    aes_sub_bytes(block, isbox);
    aes_add_round_key(block, &rk[..16]);
}

#[derive(Clone)]
pub struct Aes128Ecb {
    pub rk: [u8; 176],
}

impl Aes128Ecb {
    pub fn new(key: &[u8; 16]) -> Self {
        let (sbox, _) = aes_sboxes();
        let mut rk = [0u8; 176];
        aes_expand_key::<4, 10>(key, &mut rk, &sbox);
        Self { rk }
    }

    pub fn encrypt_blocks(&self, buf: &mut [u8]) {
        let (sbox, _) = aes_sboxes();
        for chunk in buf.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = chunk.try_into().unwrap();
            aes_encrypt_block(b, &self.rk, 10, &sbox);
        }
    }

    pub fn decrypt_blocks(&self, buf: &mut [u8]) {
        let (_, isbox) = aes_sboxes();
        for chunk in buf.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = chunk.try_into().unwrap();
            aes_decrypt_block(b, &self.rk, 10, &isbox);
        }
    }
}

#[derive(Clone)]
pub struct Aes256Ecb {
    pub rk: [u8; 240],
}

impl Aes256Ecb {
    pub fn new(key: &[u8; 32]) -> Self {
        let (sbox, _) = aes_sboxes();
        let mut rk = [0u8; 240];
        aes_expand_key::<8, 14>(key, &mut rk, &sbox);
        Self { rk }
    }

    pub fn encrypt_blocks(&self, buf: &mut [u8]) {
        let (sbox, _) = aes_sboxes();
        for chunk in buf.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = chunk.try_into().unwrap();
            aes_encrypt_block(b, &self.rk, 14, &sbox);
        }
    }

    pub fn decrypt_blocks(&self, buf: &mut [u8]) {
        let (_, isbox) = aes_sboxes();
        for chunk in buf.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = chunk.try_into().unwrap();
            aes_decrypt_block(b, &self.rk, 14, &isbox);
        }
    }
}

#[derive(Clone)]
pub struct Aes128Cbc {
    pub rk: [u8; 176],
    pub iv: [u8; 16],
}

impl Aes128Cbc {
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let (sbox, _) = aes_sboxes();
        let mut rk = [0u8; 176];
        aes_expand_key::<4, 10>(key, &mut rk, &sbox);
        Self { rk, iv: *iv }
    }

    pub fn encrypt_blocks(&mut self, buf: &mut [u8]) {
        let (sbox, _) = aes_sboxes();
        let mut prev = self.iv;
        for chunk in buf.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = chunk.try_into().unwrap();
            for i in 0..16 {
                b[i] ^= prev[i];
            }
            aes_encrypt_block(b, &self.rk, 10, &sbox);
            prev = *b;
        }
        self.iv = prev;
    }

    pub fn decrypt_blocks(&mut self, buf: &mut [u8]) {
        let (_, isbox) = aes_sboxes();
        let mut prev = self.iv;
        for chunk in buf.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = chunk.try_into().unwrap();
            let ct = *b;
            aes_decrypt_block(b, &self.rk, 10, &isbox);
            for i in 0..16 {
                b[i] ^= prev[i];
            }
            prev = ct;
        }
        self.iv = prev;
    }
}

#[derive(Clone)]
pub struct Aes256Cbc {
    pub rk: [u8; 240],
    pub iv: [u8; 16],
}

impl Aes256Cbc {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        let (sbox, _) = aes_sboxes();
        let mut rk = [0u8; 240];
        aes_expand_key::<8, 14>(key, &mut rk, &sbox);
        Self { rk, iv: *iv }
    }

    pub fn encrypt_blocks(&mut self, buf: &mut [u8]) {
        let (sbox, _) = aes_sboxes();
        let mut prev = self.iv;
        for chunk in buf.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = chunk.try_into().unwrap();
            for i in 0..16 {
                b[i] ^= prev[i];
            }
            aes_encrypt_block(b, &self.rk, 14, &sbox);
            prev = *b;
        }
        self.iv = prev;
    }

    pub fn decrypt_blocks(&mut self, buf: &mut [u8]) {
        let (_, isbox) = aes_sboxes();
        let mut prev = self.iv;
        for chunk in buf.chunks_exact_mut(16) {
            let b: &mut [u8; 16] = chunk.try_into().unwrap();
            let ct = *b;
            aes_decrypt_block(b, &self.rk, 14, &isbox);
            for i in 0..16 {
                b[i] ^= prev[i];
            }
            prev = ct;
        }
        self.iv = prev;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_nist_fips197() {
        let key128: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let aes = Aes128::new(&key128);
        let mut ct0 = [0u8; 16];
        let mut ct1 = [0u8; 16];
        aes.encrypt_two_blocks(&pt, &pt, &mut ct0, &mut ct1);
        assert_eq!(ct0, expected, "AES-128 block 0 mismatch");
        assert_eq!(ct1, expected, "AES-128 block 1 mismatch");

        let mut ct_single = [0u8; 16];
        aes.encrypt_block(&pt, &mut ct_single);
        assert_eq!(ct_single, expected, "AES-128 single block mismatch");
    }

    #[test]
    fn test_aes256_nist_fips197() {
        let key256: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];

        let aes = Aes256::new(&key256);
        let mut ct0 = [0u8; 16];
        let mut ct1 = [0u8; 16];
        aes.encrypt_two_blocks(&pt, &pt, &mut ct0, &mut ct1);
        assert_eq!(ct0, expected, "AES-256 block 0 mismatch");
        assert_eq!(ct1, expected, "AES-256 block 1 mismatch");

        let mut ct_single = [0u8; 16];
        aes.encrypt_block(&pt, &mut ct_single);
        assert_eq!(ct_single, expected, "AES-256 single block mismatch");
    }
}
