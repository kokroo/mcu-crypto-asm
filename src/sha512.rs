//! SHA-512 and SHA-384 cryptographic hash algorithms (FIPS 180-4).
//!
//! Accelerated by hand-written ARM assembly pairing 32-bit registers for 64-bit operations
//! on Cortex-M (ARMv7-M, ARMv7E-M, ARMv8-M).

#![allow(clippy::needless_range_loop)]

pub const SHA512_BLOCK_SIZE: usize = 128;
pub const SHA512_OUTPUT_SIZE: usize = 64;
pub const SHA384_OUTPUT_SIZE: usize = 48;

pub const SHA512_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub const SHA384_IV: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

#[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
use core::arch::global_asm;

#[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
global_asm!(include_str!("../asm/cortex_m_sha512.S"), options(raw));

#[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
extern "C" {
    fn sha512_block_data_order(state: *mut u64, data: *const u8, num_blocks: usize);
}

/// Compress  128-byte blocks into .
pub fn compress_blocks(state: &mut [u64; 8], data: &[u8]) {
    let num_blocks = data.len() / SHA512_BLOCK_SIZE;
    if num_blocks == 0 {
        return;
    }

    #[cfg(all(cortex_m_thumb2, not(feature = "force-portable")))]
    unsafe {
        sha512_block_data_order(state.as_mut_ptr(), data.as_ptr(), num_blocks);
    }

    #[cfg(any(not(cortex_m_thumb2), feature = "force-portable"))]
    {
        portable_compress_blocks(state, data);
    }
}

/// SHA-512 state context.
#[derive(Clone, Debug)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buf_len: usize,
    total_len: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Creates a new SHA-512 hasher instance.
    pub const fn new() -> Self {
        Self {
            state: SHA512_IV,
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feeds additional bytes into the hasher.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);

        // Fill buffer if not empty
        if self.buf_len > 0 {
            let take = (SHA512_BLOCK_SIZE - self.buf_len).min(data.len());
            self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];

            if self.buf_len == SHA512_BLOCK_SIZE {
                let buf = self.buffer;
                compress_blocks(&mut self.state, &buf);
                self.buf_len = 0;
            }
        }

        // Process bulk blocks directly from input
        let bulk_blocks = data.len() / SHA512_BLOCK_SIZE;
        if bulk_blocks > 0 {
            let bulk_bytes = bulk_blocks * SHA512_BLOCK_SIZE;
            compress_blocks(&mut self.state, &data[..bulk_bytes]);
            data = &data[bulk_bytes..];
        }

        // Buffer remaining bytes
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finalizes the hash and returns the 64-byte SHA-512 digest.
    pub fn finalize(mut self) -> [u8; SHA512_OUTPUT_SIZE] {
        let bit_len = self.total_len * 8;

        // Append 0x80 byte
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 112 {
            // Need two blocks
            for i in self.buf_len..SHA512_BLOCK_SIZE {
                self.buffer[i] = 0;
            }
            let buf = self.buffer;
            compress_blocks(&mut self.state, &buf);
            self.buffer = [0u8; SHA512_BLOCK_SIZE];
        } else {
            for i in self.buf_len..112 {
                self.buffer[i] = 0;
            }
        }

        // Write 128-bit big-endian length
        self.buffer[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let buf = self.buffer;
        compress_blocks(&mut self.state, &buf);

        let mut out = [0u8; SHA512_OUTPUT_SIZE];
        for i in 0..8 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }
}

/// SHA-384 state context.
#[derive(Clone, Debug)]
pub struct Sha384 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buf_len: usize,
    total_len: u128,
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384 {
    /// Creates a new SHA-384 hasher instance.
    pub const fn new() -> Self {
        Self {
            state: SHA384_IV,
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feeds additional bytes into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        let mut sha = Sha512 {
            state: self.state,
            buffer: self.buffer,
            buf_len: self.buf_len,
            total_len: self.total_len,
        };
        sha.update(data);
        self.state = sha.state;
        self.buffer = sha.buffer;
        self.buf_len = sha.buf_len;
        self.total_len = sha.total_len;
    }

    /// Finalizes the hash and returns the 48-byte SHA-384 digest.
    pub fn finalize(self) -> [u8; SHA384_OUTPUT_SIZE] {
        let sha = Sha512 {
            state: self.state,
            buffer: self.buffer,
            buf_len: self.buf_len,
            total_len: self.total_len,
        };
        let full_digest = sha.finalize();
        let mut out = [0u8; SHA384_OUTPUT_SIZE];
        out.copy_from_slice(&full_digest[..SHA384_OUTPUT_SIZE]);
        out
    }
}

/// One-shot SHA-512 computation.
pub fn sha512(data: &[u8]) -> [u8; SHA512_OUTPUT_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

/// One-shot SHA-384 computation.
pub fn sha384(data: &[u8]) -> [u8; SHA384_OUTPUT_SIZE] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize()
}

// --- Portable Fallback ---

pub static K512_PORTABLE: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    ((y ^ z) & x) ^ z
}

#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) | (z & (x | y))
}

#[inline]
fn sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

#[inline]
fn sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline]
fn s0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline]
fn s1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

pub fn portable_compress_blocks(state: &mut [u64; 8], mut data: &[u8]) {
    while data.len() >= SHA512_BLOCK_SIZE {
        let block = &data[..SHA512_BLOCK_SIZE];
        data = &data[SHA512_BLOCK_SIZE..];

        let mut w = [0u64; 80];
        for i in 0..16 {
            let chunk = &block[i * 8..(i + 1) * 8];
            w[i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }

        for i in 16..80 {
            w[i] = s1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(s0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..80 {
            let t1 = h
                .wrapping_add(sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K512_PORTABLE[i])
                .wrapping_add(w[i]);
            let t2 = sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha512_empty() {
        let digest = sha512(b"");
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
            0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
            0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
            0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha512_abc() {
        let digest = sha512(b"abc");
        let expected = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha384_abc() {
        let digest = sha384(b"abc");
        let expected = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
            0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
            0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
            0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
            0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];
        assert_eq!(digest, expected);
    }
}
