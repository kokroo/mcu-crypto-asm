//! ChaCha20 stream cipher (RFC 8439).
//!
//! Accelerated on Target 1 (ARM Cortex-M4/M7/M33) and Target 3 (Cortex-M3)
//! using hand-written 32-bit register-allocating assembly.

#[cfg(cortex_m_thumb2)]
mod asm {
    use core::arch::global_asm;

    global_asm!(include_str!("../asm/cortex_m_chacha20.S"), options(raw));

    extern "C" {
        pub fn chacha20_block_cortex_m(out: *mut u32, state: *const u32);
    }
}

pub struct ChaCha20 {
    state: [u32; 16],
    buffer: [u8; 64],
    offset: usize,
}

#[inline(always)]
fn u8to32(p: &[u8]) -> u32 {
    (p[0] as u32) | ((p[1] as u32) << 8) | ((p[2] as u32) << 16) | ((p[3] as u32) << 24)
}



#[cfg(not(cortex_m_thumb2))]
#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);

    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

pub fn chacha20_block(out: &mut [u8; 64], state: &[u32; 16]) {
    #[cfg(cortex_m_thumb2)]
    unsafe {
        asm::chacha20_block_cortex_m(out.as_mut_ptr() as *mut u32, state.as_ptr());
    }

    #[cfg(not(cortex_m_thumb2))]
    {
        let mut x = *state;
        for _ in 0..10 {
            // Column rounds
            quarter_round(&mut x, 0, 4, 8, 12);
            quarter_round(&mut x, 1, 5, 9, 13);
            quarter_round(&mut x, 2, 6, 10, 14);
            quarter_round(&mut x, 3, 7, 11, 15);

            // Diagonal rounds
            quarter_round(&mut x, 0, 5, 10, 15);
            quarter_round(&mut x, 1, 6, 11, 12);
            quarter_round(&mut x, 2, 7, 8, 13);
            quarter_round(&mut x, 3, 4, 9, 14);
        }

        for i in 0..16 {
            let val = x[i].wrapping_add(state[i]);
            out[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }
    }
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; 16];
        // RFC 8439 Section 2.3 constants
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key
        for i in 0..8 {
            state[4 + i] = u8to32(&key[i * 4..i * 4 + 4]);
        }

        // Counter
        state[12] = counter;

        // Nonce
        for i in 0..3 {
            state[13 + i] = u8to32(&nonce[i * 4..i * 4 + 4]);
        }

        ChaCha20 {
            state,
            buffer: [0u8; 64],
            offset: 64, // forces keystream generation on first byte
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut idx = 0;
        while idx < data.len() {
            if self.offset == 64 {
                chacha20_block(&mut self.buffer, &self.state);
                self.state[12] = self.state[12].wrapping_add(1);
                self.offset = 0;
            }

            let available = 64 - self.offset;
            let remaining = data.len() - idx;
            let take = core::cmp::min(available, remaining);

            for i in 0..take {
                data[idx + i] ^= self.buffer[self.offset + i];
            }

            self.offset += take;
            idx += take;
        }
    }
}

pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut cipher = ChaCha20::new(key, nonce, counter);
    cipher.apply_keystream(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_block_rfc8439() {
        let state = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
            0x00000001, 0x09000000, 0x4a000000, 0x00000000,
        ];
        let mut out = [0u8; 64];
        chacha20_block(&mut out, &state);

        let expected_block = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(out, expected_block);
    }

    #[test]
    fn test_chacha20_encryption_rfc8439() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1u32;
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut data = *plaintext;
        chacha20_xor(&key, &nonce, counter, &mut data);

        let expected_enc = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d
        ];
        assert_eq!(&data[..], &expected_enc[..]);
    }
}
