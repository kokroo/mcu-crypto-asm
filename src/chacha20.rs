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
fn rotl32(v: u32, n: u32) -> u32 {
    v.rotate_left(n)
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
