//! Poly1305 one-time authenticator (RFC 8439).
//!
//! Accelerated on Target 1 (ARM Cortex-M4/M7/M33) using hand-written `UMAAL`
//! assembly instructions, processing each 16-byte block in ~2.8 cycles/byte.

#[cfg(cortex_m_thumb2)]
mod asm {
    use core::arch::global_asm;

    global_asm!(include_str!("../asm/cortex_m_poly1305.S"), options(raw));

    extern "C" {
        pub fn poly1305_mul_reduce_umaal(h: *mut u32, r: *const u32, s: *const u32);
    }
}

pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    pad: [u32; 4],
    leftover: usize,
    buffer: [u8; 16],
}

#[inline(always)]
fn u8to32(p: &[u8]) -> u32 {
    (p[0] as u32) | ((p[1] as u32) << 8) | ((p[2] as u32) << 16) | ((p[3] as u32) << 24)
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let r0 = u8to32(&key[0..4]) & 0x3ffffff;
        let r1 = (u8to32(&key[3..7]) >> 2) & 0x3ffff03;
        let r2 = (u8to32(&key[6..10]) >> 4) & 0x3ffc0ff;
        let r3 = (u8to32(&key[9..13]) >> 6) & 0x3f03fff;
        let r4 = (u8to32(&key[12..16]) >> 8) & 0x00fffff;

        let r = [r0, r1, r2, r3, r4];
        let s = [r1 * 5, r2 * 5, r3 * 5, r4 * 5];

        let pad = [
            u8to32(&key[16..20]),
            u8to32(&key[20..24]),
            u8to32(&key[24..28]),
            u8to32(&key[28..32]),
        ];

        Poly1305 {
            r,
            s,
            h: [0; 5],
            pad,
            leftover: 0,
            buffer: [0; 16],
        }
    }

    #[inline(always)]
    fn process_block(&mut self, block: &[u8; 16], hibit: u32) {
        self.h[0] += u8to32(&block[0..4]) & 0x3ffffff;
        self.h[1] += (u8to32(&block[3..7]) >> 2) & 0x3ffffff;
        self.h[2] += (u8to32(&block[6..10]) >> 4) & 0x3ffffff;
        self.h[3] += (u8to32(&block[9..13]) >> 6) & 0x3ffffff;
        self.h[4] += (u8to32(&block[12..16]) >> 8) | hibit;

        #[cfg(cortex_m_thumb2)]
        unsafe {
            asm::poly1305_mul_reduce_umaal(
                self.h.as_mut_ptr(),
                self.r.as_ptr(),
                self.s.as_ptr(),
            );
        }

        #[cfg(not(cortex_m_thumb2))]
        {
            let d0 = (self.h[0] as u64) * (self.r[0] as u64)
                + (self.h[1] as u64) * (self.s[3] as u64)
                + (self.h[2] as u64) * (self.s[2] as u64)
                + (self.h[3] as u64) * (self.s[1] as u64)
                + (self.h[4] as u64) * (self.s[0] as u64);

            let d1 = (self.h[0] as u64) * (self.r[1] as u64)
                + (self.h[1] as u64) * (self.r[0] as u64)
                + (self.h[2] as u64) * (self.s[3] as u64)
                + (self.h[3] as u64) * (self.s[2] as u64)
                + (self.h[4] as u64) * (self.s[1] as u64);

            let d2 = (self.h[0] as u64) * (self.r[2] as u64)
                + (self.h[1] as u64) * (self.r[1] as u64)
                + (self.h[2] as u64) * (self.r[0] as u64)
                + (self.h[3] as u64) * (self.s[3] as u64)
                + (self.h[4] as u64) * (self.s[2] as u64);

            let d3 = (self.h[0] as u64) * (self.r[3] as u64)
                + (self.h[1] as u64) * (self.r[2] as u64)
                + (self.h[2] as u64) * (self.r[1] as u64)
                + (self.h[3] as u64) * (self.r[0] as u64)
                + (self.h[4] as u64) * (self.s[3] as u64);

            let d4 = (self.h[0] as u64) * (self.r[4] as u64)
                + (self.h[1] as u64) * (self.r[3] as u64)
                + (self.h[2] as u64) * (self.r[2] as u64)
                + (self.h[3] as u64) * (self.r[1] as u64)
                + (self.h[4] as u64) * (self.r[0] as u64);

            let c = (d0 >> 26) as u32;
            self.h[0] = (d0 as u32) & 0x3ffffff;

            let d1 = d1 + (c as u64);
            let c = (d1 >> 26) as u32;
            self.h[1] = (d1 as u32) & 0x3ffffff;

            let d2 = d2 + (c as u64);
            let c = (d2 >> 26) as u32;
            self.h[2] = (d2 as u32) & 0x3ffffff;

            let d3 = d3 + (c as u64);
            let c = (d3 >> 26) as u32;
            self.h[3] = (d3 as u32) & 0x3ffffff;

            let d4 = d4 + (c as u64);
            let c = (d4 >> 26) as u32;
            self.h[4] = (d4 as u32) & 0x3ffffff;

            self.h[0] += c * 5;
            let c = self.h[0] >> 26;
            self.h[0] &= 0x3ffffff;
            self.h[1] += c;
        }
    }

    pub fn update(&mut self, mut m: &[u8]) {
        if self.leftover > 0 {
            let want = 16 - self.leftover;
            if m.len() < want {
                self.buffer[self.leftover..self.leftover + m.len()].copy_from_slice(m);
                self.leftover += m.len();
                return;
            }
            self.buffer[self.leftover..16].copy_from_slice(&m[..want]);
            let block = self.buffer;
            self.process_block(&block, 1 << 24);
            m = &m[want..];
            self.leftover = 0;
        }

        while m.len() >= 16 {
            let block: &[u8; 16] = m[..16].try_into().unwrap();
            self.process_block(block, 1 << 24);
            m = &m[16..];
        }

        if !m.is_empty() {
            self.buffer[..m.len()].copy_from_slice(m);
            self.leftover = m.len();
        }
    }

    pub fn finish(mut self) -> [u8; 16] {
        if self.leftover > 0 {
            let mut block = [0u8; 16];
            block[..self.leftover].copy_from_slice(&self.buffer[..self.leftover]);
            block[self.leftover] = 1;
            self.process_block(&block, 0);
        }

        // Full carry
        let c = self.h[1] >> 26;
        self.h[1] &= 0x3ffffff;
        self.h[2] += c;
        let c = self.h[2] >> 26;
        self.h[2] &= 0x3ffffff;
        self.h[3] += c;
        let c = self.h[3] >> 26;
        self.h[3] &= 0x3ffffff;
        self.h[4] += c;
        let c = self.h[4] >> 26;
        self.h[4] &= 0x3ffffff;
        self.h[0] += c * 5;
        let c = self.h[0] >> 26;
        self.h[0] &= 0x3ffffff;
        self.h[1] += c;

        // Compute h - p
        let g0 = self.h[0] + 5;
        let c = g0 >> 26;
        let g0 = g0 & 0x3ffffff;

        let g1 = self.h[1] + c;
        let c = g1 >> 26;
        let g1 = g1 & 0x3ffffff;

        let g2 = self.h[2] + c;
        let c = g2 >> 26;
        let g2 = g2 & 0x3ffffff;

        let g3 = self.h[3] + c;
        let c = g3 >> 26;
        let g3 = g3 & 0x3ffffff;

        let g4 = self.h[4].wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 31).wrapping_sub(1);
        let g0 = g0 & mask;
        let g1 = g1 & mask;
        let g2 = g2 & mask;
        let g3 = g3 & mask;
        let g4 = g4 & mask;

        let not_mask = !mask;
        self.h[0] = (self.h[0] & not_mask) | g0;
        self.h[1] = (self.h[1] & not_mask) | g1;
        self.h[2] = (self.h[2] & not_mask) | g2;
        self.h[3] = (self.h[3] & not_mask) | g3;
        self.h[4] = (self.h[4] & not_mask) | g4;

        let mut h0 = self.h[0] | (self.h[1] << 26);
        let mut h1 = (self.h[1] >> 6) | (self.h[2] << 20);
        let mut h2 = (self.h[2] >> 12) | (self.h[3] << 14);
        let mut h3 = (self.h[3] >> 18) | (self.h[4] << 8);

        // Add pad
        let f = (h0 as u64) + (self.pad[0] as u64);
        h0 = f as u32;
        let f = (h1 as u64) + (self.pad[1] as u64) + (f >> 32);
        h1 = f as u32;
        let f = (h2 as u64) + (self.pad[2] as u64) + (f >> 32);
        h2 = f as u32;
        let f = (h3 as u64) + (self.pad[3] as u64) + (f >> 32);
        h3 = f as u32;

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&h0.to_le_bytes());
        out[4..8].copy_from_slice(&h1.to_le_bytes());
        out[8..12].copy_from_slice(&h2.to_le_bytes());
        out[12..16].copy_from_slice(&h3.to_le_bytes());
        out
    }
}

/// One-shot Poly1305 MAC computation.
pub fn poly1305_auth(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut poly = Poly1305::new(key);
    poly.update(msg);
    poly.finish()
}
