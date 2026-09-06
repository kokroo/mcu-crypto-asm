//! Keccak-p[1600] / SHA-3 / SHAKE implementation.
//!
//! Accelerated on Target 1 (ARM Cortex-M4/M7/M33) and Target 3 (Cortex-M3)
//! using 32-bit bit-interleaved assembly from Adomnicăi / XKCP.

#[cfg(nistp_asm_cm4)]
mod asm {
    use core::arch::global_asm;

    global_asm!(include_str!("../asm/cortex_m_keccak.S"), options(raw));

    extern "C" {
        pub fn KeccakP1600_Initialize(state: *mut u32);
        pub fn KeccakP1600_AddBytes(state: *mut u32, data: *const u8, offset: usize, length: usize);
        pub fn KeccakP1600_ExtractBytes(state: *const u32, data: *mut u8, offset: usize, length: usize);
        pub fn KeccakP1600_Permute_12rounds(state: *mut u32);
        pub fn KeccakP1600_Permute_24rounds(state: *mut u32);
    }
}

pub struct KeccakState {
    #[cfg(nistp_asm_cm4)]
    state: [u32; 50],
    #[cfg(not(nistp_asm_cm4))]
    state: [u64; 25],
}

impl Default for KeccakState {
    fn default() -> Self {
        Self::new()
    }
}

impl KeccakState {
    pub fn new() -> Self {
        #[cfg(nistp_asm_cm4)]
        {
            let mut s = KeccakState { state: [0u32; 50] };
            unsafe {
                asm::KeccakP1600_Initialize(s.state.as_mut_ptr());
            }
            s
        }

        #[cfg(not(nistp_asm_cm4))]
        {
            KeccakState { state: [0u64; 25] }
        }
    }

    pub fn permute_24(&mut self) {
        #[cfg(nistp_asm_cm4)]
        unsafe {
            asm::KeccakP1600_Permute_24rounds(self.state.as_mut_ptr());
        }

        #[cfg(not(nistp_asm_cm4))]
        {
            portable::keccak_f1600(&mut self.state);
        }
    }

    pub fn permute_12(&mut self) {
        #[cfg(nistp_asm_cm4)]
        unsafe {
            asm::KeccakP1600_Permute_12rounds(self.state.as_mut_ptr());
        }

        #[cfg(not(nistp_asm_cm4))]
        {
            portable::keccak_p1600_12(&mut self.state);
        }
    }

    pub fn add_bytes(&mut self, data: &[u8], offset: usize) {
        if data.is_empty() {
            return;
        }

        #[cfg(nistp_asm_cm4)]
        unsafe {
            asm::KeccakP1600_AddBytes(self.state.as_mut_ptr(), data.as_ptr(), offset, data.len());
        }

        #[cfg(not(nistp_asm_cm4))]
        {
            for (i, &b) in data.iter().enumerate() {
                let pos = offset + i;
                let lane = pos / 8;
                let byte_in_lane = pos % 8;
                self.state[lane] ^= (b as u64) << (byte_in_lane * 8);
            }
        }
    }

    pub fn extract_bytes(&self, out: &mut [u8], offset: usize) {
        if out.is_empty() {
            return;
        }

        #[cfg(nistp_asm_cm4)]
        unsafe {
            asm::KeccakP1600_ExtractBytes(self.state.as_ptr(), out.as_mut_ptr(), offset, out.len());
        }

        #[cfg(not(nistp_asm_cm4))]
        {
            for (i, b) in out.iter_mut().enumerate() {
                let pos = offset + i;
                let lane = pos / 8;
                let byte_in_lane = pos % 8;
                *b = (self.state[lane] >> (byte_in_lane * 8)) as u8;
            }
        }
    }
}

pub struct KeccakSponge {
    state: KeccakState,
    rate: usize,
    domain_sep: u8,
    pos: usize,
    squeezing: bool,
}

impl KeccakSponge {
    pub fn new(rate: usize, domain_sep: u8) -> Self {
        assert!(rate <= 200 && rate % 8 == 0);
        KeccakSponge {
            state: KeccakState::new(),
            rate,
            domain_sep,
            pos: 0,
            squeezing: false,
        }
    }

    pub fn absorb(&mut self, mut input: &[u8]) {
        assert!(!self.squeezing);
        while !input.is_empty() {
            let want = self.rate - self.pos;
            let take = core::cmp::min(want, input.len());
            self.state.add_bytes(&input[..take], self.pos);
            self.pos += take;
            input = &input[take..];

            if self.pos == self.rate {
                self.state.permute_24();
                self.pos = 0;
            }
        }
    }

    pub fn finalize_and_squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            // Apply padding
            if self.pos == self.rate - 1 {
                let pad = [self.domain_sep | 0x80];
                self.state.add_bytes(&pad, self.pos);
            } else {
                let ds = [self.domain_sep];
                self.state.add_bytes(&ds, self.pos);
                let pad = [0x80u8];
                self.state.add_bytes(&pad, self.rate - 1);
            }
            self.state.permute_24();
            self.pos = 0;
            self.squeezing = true;
        }

        let mut out_idx = 0;
        while out_idx < out.len() {
            let want = self.rate - self.pos;
            let take = core::cmp::min(want, out.len() - out_idx);
            self.state.extract_bytes(&mut out[out_idx..out_idx + take], self.pos);
            self.pos += take;
            out_idx += take;

            if self.pos == self.rate && out_idx < out.len() {
                self.state.permute_24();
                self.pos = 0;
            }
        }
    }
}

pub fn sha3_256(msg: &[u8]) -> [u8; 32] {
    let mut sponge = KeccakSponge::new(136, 0x06);
    sponge.absorb(msg);
    let mut out = [0u8; 32];
    sponge.finalize_and_squeeze(&mut out);
    out
}

pub fn sha3_512(msg: &[u8]) -> [u8; 64] {
    let mut sponge = KeccakSponge::new(72, 0x06);
    sponge.absorb(msg);
    let mut out = [0u8; 64];
    sponge.finalize_and_squeeze(&mut out);
    out
}

pub fn shake128(msg: &[u8], out: &mut [u8]) {
    let mut sponge = KeccakSponge::new(168, 0x1f);
    sponge.absorb(msg);
    sponge.finalize_and_squeeze(out);
}

pub fn shake256(msg: &[u8], out: &mut [u8]) {
    let mut sponge = KeccakSponge::new(136, 0x1f);
    sponge.absorb(msg);
    sponge.finalize_and_squeeze(out);
}

#[cfg(not(nistp_asm_cm4))]
mod portable {
    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    const RHO: [u32; 25] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ];

    const PI: [usize; 25] = [
        0, 10, 20, 5, 15,
        16, 1, 11, 21, 6,
        7, 17, 2, 12, 22,
        23, 8, 18, 3, 13,
        14, 24, 9, 19, 4,
    ];

    #[inline(always)]
    fn round(a: &mut [u64; 25], rc: u64) {
        // Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }

        // Rho and Pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[PI[x + 5 * y]] = a[x + 5 * y].rotate_left(RHO[x + 5 * y]);
            }
        }

        // Chi
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
            }
        }

        // Iota
        a[0] ^= rc;
    }

    pub fn keccak_f1600(a: &mut [u64; 25]) {
        for &rc in RC.iter() {
            round(a, rc);
        }
    }

    pub fn keccak_p1600_12(a: &mut [u64; 25]) {
        for &rc in RC[12..].iter() {
            round(a, rc);
        }
    }
}
