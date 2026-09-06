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
            let _ = key;
        }
        Aes128 { rkeys }
    }

    /// Encrypt two 16-byte blocks in parallel using 2-way interleaved fixslicing.
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
            let _ = (p0, p1, c0, c1);
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
            let _ = key;
        }
        Aes256 { rkeys }
    }

    /// Encrypt two 16-byte blocks in parallel using 2-way interleaved fixslicing.
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
            let _ = (p0, p1, c0, c1);
        }
    }

    /// Encrypt a single 16-byte block.
    pub fn encrypt_block(&self, ptext: &[u8; 16], ctext: &mut [u8; 16]) {
        let mut dummy = [0u8; 16];
        self.encrypt_two_blocks(ptext, ptext, ctext, &mut dummy);
    }
}
