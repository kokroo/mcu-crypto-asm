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
        portable_modexp_public(base, exponent, modulus, result)
    }
}

#[inline(always)]
fn inv32(n: u32) -> u32 {
    let mut x = 2u32.wrapping_sub(n);
    x = x.wrapping_mul(2u32.wrapping_sub(n.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(n.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(n.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(n.wrapping_mul(x)));
    x.wrapping_neg()
}

#[inline(always)]
fn sub_m_if_gte<const N: usize>(r: &mut [u32; N], m: &[u32; N], carry: u32) {
    let mut diff = [0u32; N];
    let mut borrow = 0i64;
    for j in 0..N {
        let sub = (r[j] as i64) - (m[j] as i64) + borrow;
        diff[j] = sub as u32;
        borrow = sub >> 32;
    }
    borrow += carry as i64;
    let mask = if borrow >= 0 { 0xFFFF_FFFF } else { 0 };
    for j in 0..N {
        r[j] = (diff[j] & mask) | (r[j] & !mask);
    }
}

fn mont_mul<const N: usize>(
    a: &[u32; N],
    b: &[u32; N],
    m: &[u32; N],
    mu: u32,
    res: &mut [u32; N],
) {
    let mut t = [0u32; 130];
    for i in 0..N {
        let mut carry: u64 = 0;
        let ai = a[i] as u64;
        for j in 0..N {
            let sum = (t[j] as u64) + ai * (b[j] as u64) + carry;
            t[j] = sum as u32;
            carry = sum >> 32;
        }
        let sum = (t[N] as u64) + carry;
        t[N] = sum as u32;
        t[N + 1] = (sum >> 32) as u32;

        let q = t[0].wrapping_mul(mu) as u64;

        let sum = (t[0] as u64) + q * (m[0] as u64);
        carry = sum >> 32;
        for j in 1..N {
            let sum = (t[j] as u64) + q * (m[j] as u64) + carry;
            t[j - 1] = sum as u32;
            carry = sum >> 32;
        }
        let sum = (t[N] as u64) + carry;
        t[N - 1] = sum as u32;
        let sum2 = (t[N + 1] as u64) + (sum >> 32);
        t[N] = sum2 as u32;
        t[N + 1] = (sum2 >> 32) as u32;
    }

    let mut borrow = 0i64;
    let mut diff = [0u32; 128];
    for j in 0..N {
        let sub = (t[j] as i64) - (m[j] as i64) + borrow;
        diff[j] = sub as u32;
        borrow = sub >> 32;
    }
    borrow += t[N] as i64;
    let mask = if borrow >= 0 { 0xFFFF_FFFF } else { 0 };
    for j in 0..N {
        res[j] = (diff[j] & mask) | (t[j] & !mask);
    }
}

pub fn portable_modexp_public<const N: usize>(
    base: &[u32; N],
    exponent: &[u8],
    modulus: &[u32; N],
    result: &mut [u32; N],
) -> Result<(), Error> {
    // Check base < modulus
    let mut borrow = 0i64;
    for j in 0..N {
        let sub = (base[j] as i64) - (modulus[j] as i64) + borrow;
        borrow = sub >> 32;
    }
    if borrow >= 0 {
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

    let mu = inv32(modulus[0]);

    // Compute R^2 mod modulus: start with 1, shift left 64*N times
    let mut r2 = [0u32; N];
    r2[0] = 1;
    for _ in 0..(64 * N) {
        let mut carry = 0u32;
        for j in 0..N {
            let next_carry = r2[j] >> 31;
            r2[j] = (r2[j] << 1) | carry;
            carry = next_carry;
        }
        sub_m_if_gte(&mut r2, modulus, carry);
    }

    // Convert base to Montgomery form
    let mut base_mont = [0u32; N];
    mont_mul(base, &r2, modulus, mu, &mut base_mont);

    // Modular exponentiation (square and multiply)
    let mut acc = base_mont;
    for bit_pos in (first_bit_pos + 1)..exp_bits {
        let mut next_acc = [0u32; N];
        mont_mul(&acc, &acc, modulus, mu, &mut next_acc);
        acc = next_acc;

        if (exp_slice[bit_pos / 8] & (0x80 >> (bit_pos % 8))) != 0 {
            let mut mul_acc = [0u32; N];
            mont_mul(&acc, &base_mont, modulus, mu, &mut mul_acc);
            acc = mul_acc;
        }
    }

    // Convert back to standard domain: acc * 1 * R^-1 mod modulus
    let mut one = [0u32; N];
    one[0] = 1;
    mont_mul(&acc, &one, modulus, mu, result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_small_modexp() {
        // Test with N=8 (256-bit)
        let mut base = [0u32; 8];
        base[0] = 12345;
        let exp = [0x01, 0x00, 0x01]; // 65537
        let mut modulus = [0u32; 8];
        // Modulus must be odd and > base
        modulus[0] = 0xDEADBEEF;
        modulus[1] = 0xCAFEBABE;
        modulus[7] = 0x80000000; // ensure MSB set
        if modulus[0] % 2 == 0 { modulus[0] |= 1; }

        let mut res = [0u32; 8];
        portable_modexp_public(&base, &exp, &modulus, &mut res).unwrap();

        // Check against num_bigint
        use num_bigint::BigUint;
        let mut base_bytes = [0u8; 32];
        for i in 0..8 {
            base_bytes[i*4..(i+1)*4].copy_from_slice(&base[i].to_le_bytes());
        }
        let mut mod_bytes = [0u8; 32];
        for i in 0..8 {
            mod_bytes[i*4..(i+1)*4].copy_from_slice(&modulus[i].to_le_bytes());
        }
        let b = BigUint::from_bytes_le(&base_bytes);
        let m = BigUint::from_bytes_le(&mod_bytes);
        let e = BigUint::from_bytes_be(&exp);
        let expected = b.modpow(&e, &m);
        let mut res_bytes = [0u8; 32];
        for i in 0..8 {
            res_bytes[i*4..(i+1)*4].copy_from_slice(&res[i].to_le_bytes());
        }
        let actual = BigUint::from_bytes_le(&res_bytes);
        assert_eq!(actual, expected, "RSA 256-bit modexp mismatch");
    }

    #[test]
    fn test_rsa_2048_modexp() {
        let mut base = [0u32; 64];
        base[0] = 0x12345678;
        base[1] = 0x9ABCDEF0;
        let exp = [0x01, 0x00, 0x01]; // 65537
        let mut modulus = [0u32; 64];
        for i in 0..64 {
            modulus[i] = 0xDEADBEEF ^ (i as u32 * 0x1234567);
        }
        modulus[63] |= 0x80000000;
        modulus[0] |= 1;

        let mut res = [0u32; 64];
        portable_modexp_public(&base, &exp, &modulus, &mut res).unwrap();

        use num_bigint::BigUint;
        let mut base_bytes = [0u8; 256];
        for i in 0..64 {
            base_bytes[i*4..(i+1)*4].copy_from_slice(&base[i].to_le_bytes());
        }
        let mut mod_bytes = [0u8; 256];
        for i in 0..64 {
            mod_bytes[i*4..(i+1)*4].copy_from_slice(&modulus[i].to_le_bytes());
        }
        let b = BigUint::from_bytes_le(&base_bytes);
        let m = BigUint::from_bytes_le(&mod_bytes);
        let e = BigUint::from_bytes_be(&exp);
        let expected = b.modpow(&e, &m);
        let mut res_bytes = [0u8; 256];
        for i in 0..64 {
            res_bytes[i*4..(i+1)*4].copy_from_slice(&res[i].to_le_bytes());
        }
        let actual = BigUint::from_bytes_le(&res_bytes);
        assert_eq!(actual, expected, "RSA 2048-bit modexp mismatch");
    }
}
