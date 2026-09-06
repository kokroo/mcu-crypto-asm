//! Constant-time Fixsliced AES (Advanced Encryption Standard).
//!
//! Accelerated on Target 1 (ARM Cortex-M3/M4/M7/M33) using Alexandre Adomnicai's
//! Fixslicing assembly implementation (CHES 2020), providing the fastest
//! constant-time 32-bit software AES in existence.

#[cfg(cortex_m_thumb2)]
mod asm {
    use core::arch::global_asm;

    global_asm!(include_str!("../asm/cortex_m_aes_encrypt.S"), options(raw));
    global_asm!(include_str!("../asm/cortex_m_aes_keyschedule.S"), options(raw));

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
        q[0] = a; q[1] = b;
        let (a, b) = swapn(0x55555555, 0xAAAAAAAA, 1, q[2], q[3]);
        q[2] = a; q[3] = b;
        let (a, b) = swapn(0x55555555, 0xAAAAAAAA, 1, q[4], q[5]);
        q[4] = a; q[5] = b;
        let (a, b) = swapn(0x55555555, 0xAAAAAAAA, 1, q[6], q[7]);
        q[6] = a; q[7] = b;

        let (a, b) = swapn(0x33333333, 0xCCCCCCCC, 2, q[0], q[2]);
        q[0] = a; q[2] = b;
        let (a, b) = swapn(0x33333333, 0xCCCCCCCC, 2, q[1], q[3]);
        q[1] = a; q[3] = b;
        let (a, b) = swapn(0x33333333, 0xCCCCCCCC, 2, q[4], q[6]);
        q[4] = a; q[6] = b;
        let (a, b) = swapn(0x33333333, 0xCCCCCCCC, 2, q[5], q[7]);
        q[5] = a; q[7] = b;

        let (a, b) = swapn(0x0F0F0F0F, 0xF0F0F0F0, 4, q[0], q[4]);
        q[0] = a; q[4] = b;
        let (a, b) = swapn(0x0F0F0F0F, 0xF0F0F0F0, 4, q[1], q[5]);
        q[1] = a; q[5] = b;
        let (a, b) = swapn(0x0F0F0F0F, 0xF0F0F0F0, 4, q[2], q[6]);
        q[2] = a; q[6] = b;
        let (a, b) = swapn(0x0F0F0F0F, 0xF0F0F0F0, 4, q[3], q[7]);
        q[3] = a; q[7] = b;
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
        (x << 16) | (x >> 16)
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
        let r0 = (q0 >> 8) | (q0 << 24);
        let r1 = (q1 >> 8) | (q1 << 24);
        let r2 = (q2 >> 8) | (q2 << 24);
        let r3 = (q3 >> 8) | (q3 << 24);
        let r4 = (q4 >> 8) | (q4 << 24);
        let r5 = (q5 >> 8) | (q5 << 24);
        let r6 = (q6 >> 8) | (q6 << 24);
        let r7 = (q7 >> 8) | (q7 << 24);

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

    const RCON: [u32; 10] = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    ];

    pub fn keyschedule(key: &[u8], num_rounds: usize, rkeys: &mut [u32]) {
        let nk = key.len() / 4;
        let nkf = (num_rounds + 1) * 4;
        let mut skey = [0u32; 120];
        let mut tmp = 0u32;

        for i in 0..nk {
            tmp = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
            skey[(i << 1) + 0] = tmp;
            skey[(i << 1) + 1] = tmp;
        }

        let mut j = 0;
        let mut k = 0;
        for i in nk..nkf {
            if j == 0 {
                tmp = (tmp << 24) | (tmp >> 8);
                tmp = sub_word(tmp) ^ RCON[k];
            } else if nk > 6 && j == 4 {
                tmp = sub_word(tmp);
            }
            tmp ^= skey[(i - nk) << 1];
            skey[(i << 1) + 0] = tmp;
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
            rkeys[u * 2 + 0] = x | (x << 1);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_nist_fips197() {
        let key128: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
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
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
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

