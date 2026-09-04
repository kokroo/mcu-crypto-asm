//! Backend dispatch.
//!
//! Exactly one backend is compiled in per target. The assembly backends
//! implement only the sizes they have routines for (8 limbs = P-256,
//! 12 limbs = P-384) and fall through to [`portable`] for anything else.
//!
//! Every assembly routine is differential-tested against [`portable`] in
//! `tests/differential.rs`, so the reference is always the arbiter.

pub mod portable;

#[cfg(nistp_asm_cm4)]
pub mod cortex_m4;

#[cfg(nistp_asm_xtensa)]
pub mod xtensa;

/// Name of the active backend. Reported by benchmarks so results are never
/// ambiguous about what was actually measured.
pub const NAME: &str = {
    #[cfg(nistp_asm_cm4)]
    {
        "cortex-m4-umaal"
    }
    #[cfg(nistp_asm_xtensa)]
    {
        "xtensa-lx7"
    }
    #[cfg(not(any(nistp_asm_cm4, nistp_asm_xtensa)))]
    {
        "portable"
    }
};

/// `out = a * b * R^-1 mod p`
#[inline]
pub fn mul_mont(a: &[u32], b: &[u32], p: &[u32], n0inv: u32, out: &mut [u32]) {
    #[cfg(nistp_asm_cm4)]
    {
        if cortex_m4::try_mul_mont(a, b, p, n0inv, out) {
            return;
        }
    }
    #[cfg(nistp_asm_xtensa)]
    {
        if xtensa::try_mul_mont(a, b, p, n0inv, out) {
            return;
        }
    }
    portable::mul_mont(a, b, p, n0inv, out)
}

/// `out = a^2 * R^-1 mod p`
///
/// Currently routed through [`mul_mont`]. A dedicated squaring routine skips
/// roughly half the partial products and is a worthwhile follow-up, but it is
/// a pure optimisation: correctness never depends on it.
#[inline]
pub fn sqr_mont(a: &[u32], p: &[u32], n0inv: u32, out: &mut [u32]) {
    mul_mont(a, a, p, n0inv, out)
}

/// `out = a + b mod p`
#[inline]
pub fn add_mod(a: &[u32], b: &[u32], p: &[u32], out: &mut [u32]) {
    #[cfg(nistp_asm_cm4)]
    {
        if cortex_m4::try_add_mod(a, b, p, out) {
            return;
        }
    }
    portable::add_mod(a, b, p, out)
}

/// `out = a - b mod p`
#[inline]
pub fn sub_mod(a: &[u32], b: &[u32], p: &[u32], out: &mut [u32]) {
    #[cfg(nistp_asm_cm4)]
    {
        if cortex_m4::try_sub_mod(a, b, p, out) {
            return;
        }
    }
    portable::sub_mod(a, b, p, out)
}
