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

// --- Portable Fallback ---

pub fn portable_gmult_bitwise(xi: &mut [u8; 16], h_bytes: &[u8; 16]) {
    let mut x_hi = u64::from_be_bytes(xi[0..8].try_into().unwrap());
    let mut x_lo = u64::from_be_bytes(xi[8..16].try_into().unwrap());
    let mut v_hi = u64::from_be_bytes(h_bytes[0..8].try_into().unwrap());
    let mut v_lo = u64::from_be_bytes(h_bytes[8..16].try_into().unwrap());

    let mut z_hi = 0u64;
    let mut z_lo = 0u64;
    const R: u64 = 0xe100000000000000;

    for _ in 0..64 {
        if (x_hi & 0x8000000000000000) != 0 {
            z_hi ^= v_hi;
            z_lo ^= v_lo;
        }
        x_hi <<= 1;
        let t = if (v_lo & 1) != 0 { R } else { 0 };
        v_lo = ((v_hi & 1) << 63) | (v_lo >> 1);
        v_hi = (v_hi >> 1) ^ t;
    }
    for _ in 0..64 {
        if (x_lo & 0x8000000000000000) != 0 {
            z_hi ^= v_hi;
            z_lo ^= v_lo;
        }
        x_lo <<= 1;
        let t = if (v_lo & 1) != 0 { R } else { 0 };
        v_lo = ((v_hi & 1) << 63) | (v_lo >> 1);
        v_hi = (v_hi >> 1) ^ t;
    }

    xi[0..8].copy_from_slice(&z_hi.to_be_bytes());
    xi[8..16].copy_from_slice(&z_lo.to_be_bytes());
}

pub fn portable_compress_blocks(state: &mut [u8; 16], htable: &Htable, data: &[u8]) {
    for chunk in data.chunks_exact(GHASH_BLOCK_SIZE) {
        for i in 0..16 {
            state[i] ^= chunk[i];
        }
        portable_gmult_bitwise(state, &htable.h_bytes);
    }
}

pub fn portable_gmult(xi: &mut [u8; 16], htable: &Htable) {
    portable_gmult_bitwise(xi, &htable.h_bytes);
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
