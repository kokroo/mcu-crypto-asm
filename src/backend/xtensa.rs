//! Xtensa LX7 backend (ESP32-S2 / ESP32-S3).
//!
//! Xtensa has no `UMAAL` and, more consequentially, **no carry flag**. The
//! CIOS inner step that costs one instruction on Cortex-M4 costs eight here,
//! using `SALTU` (set-if-less-than-unsigned) as a branchless carry primitive.
//! That ratio is the honest ceiling on how close this can get to the M4.
//!
//! `SALTU` is LX7-only: it does not exist on the original ESP32 (LX6), which
//! therefore uses the portable backend. Neither chip has any ECC accelerator
//! — the ESP32-S3 has an RSA/MPI peripheral but no `SOC_ECC_SUPPORTED`.
//!
//! The assembly takes a caller-provided scratch buffer instead of building a
//! stack frame, which keeps it a pure leaf function and avoids depending on
//! the details of Xtensa's windowed frame layout.

// The assembly is NOT included via `global_asm!`: LLVM's Xtensa assembler
// does not implement `SALTU`. `build.rs` assembles `asm/xtensa_lx7.S` with the
// esp GNU toolchain and links it as a static library instead.
extern "C" {
    fn nistp_mul_mont_8(
        out: *mut u32,
        a: *const u32,
        b: *const u32,
        p: *const u32,
        scratch: *mut u32,
    );
    fn nistp_mul_mont_12(
        out: *mut u32,
        a: *const u32,
        b: *const u32,
        p: *const u32,
        scratch: *mut u32,
    );
}

/// Dispatch to assembly if a routine exists for this limb count.
#[inline]
pub fn try_mul_mont(a: &[u32], b: &[u32], p: &[u32], n0inv: u32, out: &mut [u32]) -> bool {
    // The assembly hard-codes n0' == 1 (true for both NIST primes).
    if n0inv != 1 {
        return false;
    }
    debug_assert_eq!(b.len(), a.len());
    debug_assert_eq!(p.len(), a.len());
    debug_assert_eq!(out.len(), a.len());

    // t[] needs n + 2 words; 16 covers both curves with room to spare.
    let mut scratch = [0u32; 16];

    match a.len() {
        // SAFETY: lengths are checked above, and `scratch` is 16 words while
        // the routines touch only n+2 <= 14 of them. The routines read/write
        // no other memory.
        8 => unsafe {
            nistp_mul_mont_8(
                out.as_mut_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                p.as_ptr(),
                scratch.as_mut_ptr(),
            );
            true
        },
        12 => unsafe {
            nistp_mul_mont_12(
                out.as_mut_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                p.as_ptr(),
                scratch.as_mut_ptr(),
            );
            true
        },
        _ => false,
    }
}
