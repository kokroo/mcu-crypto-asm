//! GHASH message authentication algorithm for Galois/Counter Mode (GCM, NIST SP 800-38D).
//!
//! Accelerated by hand-written ARM assembly using a 4-bit windowed GF(2^128) multiplier
//! with a precomputed 256-byte table on Cortex-M (ARMv7-M, ARMv7E-M, ARMv8-M).

#![allow(clippy::needless_range_loop)]

pub const GHASH_BLOCK_SIZE: usize = 16;
pub const GHASH_TAG_SIZE: usize = 16;

#[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
use core::arch::global_asm;

#[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
global_asm!(include_str!("../asm/cortex_m_ghash.S"), options(raw));

#[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
extern "C" {
    fn gcm_ghash_4bit(
        state: *mut u8,
        htable: *const [u32; 4],
        inp: *const u8,
        len: usize,
    );
    fn gcm_gmult_4bit(state: *mut u8, htable: *const [u32; 4]);
}

/// Precomputed 4-bit lookup table for GF(2^128) multiplication by H.
#[derive(Clone, Copy, Debug)]
#[repr(C, align(16))]
pub struct Htable {
    pub words: [[u32; 4]; 16],
    pub h_bytes: [u8; 16],
}

impl Htable {
    /// Precomputes the 16 multiples of H in GF(2^128) in ARM little-endian memory layout.
    pub fn new(h: &[u8; 16]) -> Self {
        let h_hi = u64::from_be_bytes(h[0..8].try_into().unwrap());
        let h_lo = u64::from_be_bytes(h[8..16].try_into().unwrap());

        let mut htbl = [(0u64, 0u64); 16];
        let mut v_hi = h_hi;
        let mut v_lo = h_lo;
        htbl[8] = (v_hi, v_lo);

        // Reduction polynomial R = 0xe100000000000000
        const R: u64 = 0xe100000000000000;
        for &idx in &[4, 2, 1] {
            let t = if (v_lo & 1) != 0 { R } else { 0 };
            v_lo = ((v_hi & 1) << 63) | (v_lo >> 1);
            v_hi = (v_hi >> 1) ^ t;
            htbl[idx] = (v_hi, v_lo);
        }

        htbl[3] = (htbl[1].0 ^ htbl[2].0, htbl[1].1 ^ htbl[2].1);
        let (v4_hi, v4_lo) = htbl[4];
        htbl[5] = (v4_hi ^ htbl[1].0, v4_lo ^ htbl[1].1);
        htbl[6] = (v4_hi ^ htbl[2].0, v4_lo ^ htbl[2].1);
        htbl[7] = (v4_hi ^ htbl[3].0, v4_lo ^ htbl[3].1);
        let (v8_hi, v8_lo) = htbl[8];
        htbl[9] = (v8_hi ^ htbl[1].0, v8_lo ^ htbl[1].1);
        htbl[10] = (v8_hi ^ htbl[2].0, v8_lo ^ htbl[2].1);
        htbl[11] = (v8_hi ^ htbl[3].0, v8_lo ^ htbl[3].1);
        htbl[12] = (v8_hi ^ htbl[4].0, v8_lo ^ htbl[4].1);
        htbl[13] = (v8_hi ^ htbl[5].0, v8_lo ^ htbl[5].1);
        htbl[14] = (v8_hi ^ htbl[6].0, v8_lo ^ htbl[6].1);
        htbl[15] = (v8_hi ^ htbl[7].0, v8_lo ^ htbl[7].1);

        let mut words = [[0u32; 4]; 16];
        for i in 0..16 {
            let (hi, lo) = htbl[i];
            words[i] = [
                lo as u32,
                (lo >> 32) as u32,
                hi as u32,
                (hi >> 32) as u32,
            ];
        }

        Self {
            words,
            h_bytes: *h,
        }
    }
}

/// Compress  16-byte blocks into .
pub fn compress_blocks(state: &mut [u8; 16], htable: &Htable, data: &[u8]) {
    let num_blocks = data.len() / GHASH_BLOCK_SIZE;
    if num_blocks == 0 {
        return;
    }
    let bulk_len = num_blocks * GHASH_BLOCK_SIZE;

    #[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
    unsafe {
        gcm_ghash_4bit(
            state.as_mut_ptr(),
            htable.words.as_ptr(),
            data.as_ptr(),
            bulk_len,
        );
    }

    #[cfg(any(not(cortex_m_thumb2), feature = "force-portable"))]
    {
        portable_compress_blocks(state, htable, &data[..bulk_len]);
    }
}

/// Perform single-block GF(2^128) multiplication: .
pub fn gmult(xi: &mut [u8; 16], htable: &Htable) {
    #[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
    unsafe {
        gcm_gmult_4bit(xi.as_mut_ptr(), htable.words.as_ptr());
    }

    #[cfg(any(not(cortex_m_thumb2), feature = "force-portable"))]
    {
        portable_gmult(xi, htable);
    }
}

/// GHASH streaming state.
#[derive(Clone, Debug)]
pub struct Ghash {
    htable: Htable,
    state: [u8; 16],
    buffer: [u8; GHASH_BLOCK_SIZE],
    buf_len: usize,
}

impl Ghash {
    /// Creates a new GHASH instance with hash key .
    pub fn new(h: &[u8; 16]) -> Self {
        Self {
            htable: Htable::new(h),
            state: [0u8; 16],
            buffer: [0u8; GHASH_BLOCK_SIZE],
            buf_len: 0,
        }
    }

    /// Creates a new GHASH instance with precomputed .
    pub fn from_htable(htable: Htable) -> Self {
        Self {
            htable,
            state: [0u8; 16],
            buffer: [0u8; GHASH_BLOCK_SIZE],
            buf_len: 0,
        }
    }

    /// Feeds additional bytes into GHASH.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (GHASH_BLOCK_SIZE - self.buf_len).min(data.len());
            self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];

            if self.buf_len == GHASH_BLOCK_SIZE {
                let block = self.buffer;
                compress_blocks(&mut self.state, &self.htable, &block);
                self.buf_len = 0;
            }
        }

        let num_blocks = data.len() / GHASH_BLOCK_SIZE;
        if num_blocks > 0 {
            let bulk_len = num_blocks * GHASH_BLOCK_SIZE;
            compress_blocks(&mut self.state, &self.htable, &data[..bulk_len]);
            data = &data[bulk_len..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Processes a single 16-byte block.
    pub fn update_block(&mut self, block: &[u8; 16]) {
        compress_blocks(&mut self.state, &self.htable, block);
    }

    /// Finalizes the hash, zero-padding any incomplete trailing block, and returns the 16-byte tag.
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            for i in self.buf_len..GHASH_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            compress_blocks(&mut self.state, &self.htable, &block);
        }
        self.state
    }
}

// --- Target 2 / Portable Constant-Time 32-bit GHASH Multiplier (Thomas Pornin / BearSSL) ---

#[inline(always)]
fn bmul32(x: u32, y: u32) -> u32 {
    let x0 = x & 0x11111111;
    let x1 = x & 0x22222222;
    let x2 = x & 0x44444444;
    let x3 = x & 0x88888888;
    let y0 = y & 0x11111111;
    let y1 = y & 0x22222222;
    let y2 = y & 0x44444444;
    let y3 = y & 0x88888888;

    let z0 = (x0.wrapping_mul(y0)) ^ (x1.wrapping_mul(y3)) ^ (x2.wrapping_mul(y2)) ^ (x3.wrapping_mul(y1));
    let z1 = (x0.wrapping_mul(y1)) ^ (x1.wrapping_mul(y0)) ^ (x2.wrapping_mul(y3)) ^ (x3.wrapping_mul(y2));
    let z2 = (x0.wrapping_mul(y2)) ^ (x1.wrapping_mul(y1)) ^ (x2.wrapping_mul(y0)) ^ (x3.wrapping_mul(y3));
    let z3 = (x0.wrapping_mul(y3)) ^ (x1.wrapping_mul(y2)) ^ (x2.wrapping_mul(y1)) ^ (x3.wrapping_mul(y0));

    (z0 & 0x11111111) | (z1 & 0x22222222) | (z2 & 0x44444444) | (z3 & 0x88888888)
}

#[inline(always)]
fn rev32(mut x: u32) -> u32 {
    x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555);
    x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333);
    x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F);
    x = ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF);
    (x << 16) | (x >> 16)
}

pub fn ghash_ctmul32(y: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    let mut yw = [
        u32::from_be_bytes(y[12..16].try_into().unwrap()),
        u32::from_be_bytes(y[8..12].try_into().unwrap()),
        u32::from_be_bytes(y[4..8].try_into().unwrap()),
        u32::from_be_bytes(y[0..4].try_into().unwrap()),
    ];

    let hw = [
        u32::from_be_bytes(h[12..16].try_into().unwrap()),
        u32::from_be_bytes(h[8..12].try_into().unwrap()),
        u32::from_be_bytes(h[4..8].try_into().unwrap()),
        u32::from_be_bytes(h[0..4].try_into().unwrap()),
    ];

    let hwr = [rev32(hw[0]), rev32(hw[1]), rev32(hw[2]), rev32(hw[3])];

    let mut b = [0u32; 18];
    b[0] = hw[0];
    b[1] = hw[1];
    b[2] = hw[2];
    b[3] = hw[3];
    b[4] = b[0] ^ b[1];
    b[5] = b[2] ^ b[3];
    b[6] = b[0] ^ b[2];
    b[7] = b[1] ^ b[3];
    b[8] = b[6] ^ b[7];

    b[9] = hwr[0];
    b[10] = hwr[1];
    b[11] = hwr[2];
    b[12] = hwr[3];
    b[13] = b[9] ^ b[10];
    b[14] = b[11] ^ b[12];
    b[15] = b[9] ^ b[11];
    b[16] = b[10] ^ b[12];
    b[17] = b[15] ^ b[16];

    for chunk in data.chunks_exact(16) {
        yw[3] ^= u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        yw[2] ^= u32::from_be_bytes(chunk[4..8].try_into().unwrap());
        yw[1] ^= u32::from_be_bytes(chunk[8..12].try_into().unwrap());
        yw[0] ^= u32::from_be_bytes(chunk[12..16].try_into().unwrap());

        let mut a = [0u32; 18];
        a[0] = yw[0];
        a[1] = yw[1];
        a[2] = yw[2];
        a[3] = yw[3];
        a[4] = a[0] ^ a[1];
        a[5] = a[2] ^ a[3];
        a[6] = a[0] ^ a[2];
        a[7] = a[1] ^ a[3];
        a[8] = a[6] ^ a[7];

        a[9] = rev32(yw[0]);
        a[10] = rev32(yw[1]);
        a[11] = rev32(yw[2]);
        a[12] = rev32(yw[3]);
        a[13] = a[9] ^ a[10];
        a[14] = a[11] ^ a[12];
        a[15] = a[9] ^ a[11];
        a[16] = a[10] ^ a[12];
        a[17] = a[15] ^ a[16];

        let mut c = [0u32; 18];
        for i in 0..18 {
            c[i] = bmul32(a[i], b[i]);
        }

        c[4] ^= c[0] ^ c[1];
        c[5] ^= c[2] ^ c[3];
        c[8] ^= c[6] ^ c[7];

        c[13] ^= c[9] ^ c[10];
        c[14] ^= c[11] ^ c[12];
        c[17] ^= c[15] ^ c[16];

        let d0 = c[0];
        let d1 = c[4] ^ (rev32(c[9]) >> 1);
        let d2 = c[1] ^ c[0] ^ c[2] ^ c[6] ^ (rev32(c[13]) >> 1);
        let d3 = c[4] ^ c[5] ^ c[8] ^ (rev32(c[10] ^ c[9] ^ c[11] ^ c[15]) >> 1);
        let d4 = c[2] ^ c[1] ^ c[3] ^ c[7] ^ (rev32(c[13] ^ c[14] ^ c[17]) >> 1);
        let d5 = c[5] ^ (rev32(c[11] ^ c[10] ^ c[12] ^ c[16]) >> 1);
        let d6 = c[3] ^ (rev32(c[14]) >> 1);
        let d7 = rev32(c[12]) >> 1;

        let mut zw = [0u32; 8];
        zw[0] = d0 << 1;
        zw[1] = (d1 << 1) | (d0 >> 31);
        zw[2] = (d2 << 1) | (d1 >> 31);
        zw[3] = (d3 << 1) | (d2 >> 31);
        zw[4] = (d4 << 1) | (d3 >> 31);
        zw[5] = (d5 << 1) | (d4 >> 31);
        zw[6] = (d6 << 1) | (d5 >> 31);
        zw[7] = (d7 << 1) | (d6 >> 31);

        for i in 0..4 {
            let lw = zw[i];
            zw[i + 4] ^= lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7);
            zw[i + 3] ^= (lw << 31) ^ (lw << 30) ^ (lw << 25);
        }

        yw.copy_from_slice(&zw[4..8]);
    }

    y[0..4].copy_from_slice(&yw[3].to_be_bytes());
    y[4..8].copy_from_slice(&yw[2].to_be_bytes());
    y[8..12].copy_from_slice(&yw[1].to_be_bytes());
    y[12..16].copy_from_slice(&yw[0].to_be_bytes());
}

pub fn portable_compress_blocks(state: &mut [u8; 16], htable: &Htable, data: &[u8]) {
    ghash_ctmul32(state, &htable.h_bytes, data);
}

pub fn portable_gmult(xi: &mut [u8; 16], htable: &Htable) {
    let dummy = [0u8; 16];
    ghash_ctmul32(xi, &htable.h_bytes, &dummy);
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: [u8; 16] = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
    ];

    const B1: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];

    const B2: [u8; 16] = [
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    #[test]
    fn test_ghash_single_block() {
        let mut g = Ghash::new(&H);
        g.update(&B1);
        let tag = g.finalize();
        let expected = [
            0x9f, 0x58, 0x94, 0x6a, 0x05, 0x63, 0xef, 0xa9,
            0x60, 0x90, 0xaf, 0xfe, 0x7c, 0xd3, 0x55, 0x53,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_ghash_two_blocks() {
        let mut g = Ghash::new(&H);
        g.update(&B1);
        g.update(&B2);
        let tag = g.finalize();
        let expected = [
            0x94, 0xc4, 0xec, 0x81, 0xe0, 0x7a, 0x57, 0x99,
            0xf5, 0x6e, 0x17, 0x7c, 0xdc, 0xab, 0x85, 0x85,
        ];
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_gmult() {
        let htable = Htable::new(&H);
        let mut xi = B1;
        gmult(&mut xi, &htable);
        let expected = [
            0x9f, 0x58, 0x94, 0x6a, 0x05, 0x63, 0xef, 0xa9,
            0x60, 0x90, 0xaf, 0xfe, 0x7c, 0xd3, 0x55, 0x53,
        ];
        assert_eq!(xi, expected);
    }
}
