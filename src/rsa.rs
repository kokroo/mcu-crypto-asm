//! RSA modular exponentiation engine.
//!
//! Accelerated on Target 1 (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) by hand-written
//! assembly (`Emill/rsa-armv7`) utilizing single-cycle `UMAAL` instructions for
//! Montgomery reduction.

#[cfg(nistp_asm_cm4)]
mod asm {
    use core::arch::global_asm;

    global_asm!(include_str!("../asm/cortex_m_bignum.S"), options(raw));

    extern "C" {
        pub fn bignum_to_mont(
            input_output: *mut u32,
            modulus: *const u32,
            modulus_length_bytes: usize,
            temp: *mut u32,
        );
        pub fn bignum_modular_inverse(output: *mut u32, input: *const u32);
        pub fn bignum_mulacc(
            accumulator: *mut u32,
            a: *const u32,
            b: *const u32,
            operand_length_bytes: usize,
        );
        pub fn bignum_sqracc(
            accumulator: *mut u32,
            a: *const u32,
            operand_length_bytes: usize,
        );
        pub fn bignum_mont_redc(
            input: *mut u32,
            modulus_length_bytes: usize,
            modulus: *const u32,
            modulus_prim: *const u32,
            modulus_bitwise_inv: *const u32,
            out: *mut u32,
        );
        pub fn bignum_submod(
            output: *mut u32,
            subtrahend_bitwise_inv: *const u32,
            modulus: *const u32,
            minuend: *const u32,
            modulus_length_bytes: usize,
        ) -> i32;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    BaseTooLarge,
    ModulusEven,
    ZeroExponent,
}

/// Compute `base^exponent mod modulus` for public exponents (e.g. RSA-1024 / RSA-2048 / RSA-4096).
///
/// Modulus and base are little-endian 32-bit words. Exponent is big-endian bytes (e.g. 65537).
/// Constant memory access pattern and constant-time modular arithmetic.
pub fn modexp_public<const N: usize>(
    base: &[u32; N],
    exponent: &[u8],
    modulus: &[u32; N],
    result: &mut [u32; N],
) -> Result<(), Error> {
    let mod_bytes = N * 4;
    if mod_bytes == 0 || mod_bytes % 32 != 0 || N > 128 {
        return Err(Error::InvalidLength);
    }
    if modulus[0] % 2 == 0 {
        return Err(Error::ModulusEven);
    }

    #[cfg(nistp_asm_cm4)]
    {
        let mut n_bitwise_inv = [0u32; N];
        for i in 0..N {
            n_bitwise_inv[i] = !modulus[i];
        }

        unsafe {
            // Check base < modulus and reduce into a1
            let mut a1 = [0u32; N];
            let ret = asm::bignum_submod(
                a1.as_mut_ptr(),
                n_bitwise_inv.as_ptr(),
                modulus.as_ptr(),
                base.as_ptr(),
                mod_bytes,
            );
            if ret == 0 {
                return Err(Error::BaseTooLarge);
            }

            // Find first 1-bit in exponent
            let mut exp_slice = exponent;
            while exp_slice.len() >= 2 && exp_slice[0] == 0 {
                exp_slice = &exp_slice[1..];
            }
            let exp_bits = exp_slice.len() * 8;
            let mut first_bit_pos = 0;
            while first_bit_pos < exp_bits {
                if (exp_slice[first_bit_pos / 8] & (0x80 >> (first_bit_pos % 8))) != 0 {
                    break;
                }
                first_bit_pos += 1;
            }
            if first_bit_pos == exp_bits {
                result.fill(0);
                result[0] = 1;
                return Ok(());
            }

            // temp has 2*N words: upper half holds input to bignum_to_mont
            let mut temp = [0u32; 256];
            temp[N..2 * N].copy_from_slice(&a1);

            let mut t0 = [0u32; 256]; // workspace
            asm::bignum_to_mont(
                temp.as_mut_ptr(),
                modulus.as_ptr(),
                mod_bytes,
                t0.as_mut_ptr(),
            );

            // Now temp[..N] holds base in Montgomery form
            a1.copy_from_slice(&temp[..N]);

            // N' = -N^-1 mod 2^128
            let mut n_prim = [0u32; 4];
            asm::bignum_modular_inverse(n_prim.as_mut_ptr(), modulus.as_ptr());

            // Square-and-multiply from bit after the leading 1
            for bit_pos in (first_bit_pos + 1)..exp_bits {
                t0.fill(0);
                asm::bignum_sqracc(t0.as_mut_ptr(), temp.as_mut_ptr(), mod_bytes);
                asm::bignum_mont_redc(
                    t0.as_mut_ptr(),
                    mod_bytes,
                    modulus.as_ptr(),
                    n_prim.as_ptr(),
                    n_bitwise_inv.as_ptr(),
                    temp.as_mut_ptr(),
                );

                if (exp_slice[bit_pos / 8] & (0x80 >> (bit_pos % 8))) != 0 {
                    let mul_op = if bit_pos + 1 != exp_bits {
                        a1.as_ptr()
                    } else {
                        base.as_ptr()
                    };
                    t0.fill(0);
                    asm::bignum_mulacc(t0.as_mut_ptr(), temp.as_mut_ptr(), mul_op, mod_bytes);
                    asm::bignum_mont_redc(
                        t0.as_mut_ptr(),
                        mod_bytes,
                        modulus.as_ptr(),
                        n_prim.as_ptr(),
                        n_bitwise_inv.as_ptr(),
                        temp.as_mut_ptr(),
                    );
                }
            }

            // If exponent was even, need one more reduction
            if (exp_slice.last().unwrap() & 1) == 0 {
                t0.fill(0);
                t0[..N].copy_from_slice(&temp[..N]);
                asm::bignum_mont_redc(
                    t0.as_mut_ptr(),
                    mod_bytes,
                    modulus.as_ptr(),
                    n_prim.as_ptr(),
                    n_bitwise_inv.as_ptr(),
                    temp.as_mut_ptr(),
                );
            }

            // Final reduction: temp mod N
            asm::bignum_submod(
                result.as_mut_ptr(),
                n_bitwise_inv.as_ptr(),
                modulus.as_ptr(),
                temp.as_ptr(),
                mod_bytes,
            );
        }
        Ok(())
    }

    #[cfg(not(nistp_asm_cm4))]
    {
        let _ = (base, exponent, modulus, result);
        Err(Error::InvalidLength)
    }
}
