//! Portable 32-bit Montgomery arithmetic (CIOS).
//!
//! This is the reference implementation: every assembly backend is
//! differential-tested against it, and it is the fallback on architectures
//! with no hand-written backend.
//!
//! Everything here is constant time with respect to the *values* of the
//! operands. Loop trip counts depend only on the limb count, which is a
//! compile-time property of the curve, never a secret.

/// Coarsely Integrated Operand Scanning Montgomery multiply.
///
/// Computes `out = a * b * R^-1 mod p`, where `R = 2^(32*n)`.
///
/// `n0inv` is `-p^-1 mod 2^32`. For both P-256 and P-384 the low word of `p`
/// is `0xFFFFFFFF`, i.e. `p ≡ -1 (mod 2^32)`, so `p^-1 ≡ -1` and `n0inv == 1`.
/// The assembly backends hard-code that and drop the multiply entirely.
///
/// Requires `a.len() == b.len() == p.len() == out.len()` and `len <= 14`.
#[inline]
pub fn mul_mont(a: &[u32], b: &[u32], p: &[u32], n0inv: u32, out: &mut [u32]) {
    let n = a.len();
    debug_assert!(n <= 14 && b.len() == n && p.len() == n && out.len() == n);

    // t needs n + 2 words of headroom.
    let mut t = [0u32; 16];

    for i in 0..n {
        // --- t += a * b[i] ---
        let bi = b[i] as u64;
        let mut c: u32 = 0;
        for j in 0..n {
            // The single operation the whole design is built around:
            //   (c, t[j]) = t[j] + a[j]*b[i] + c
            // Cannot overflow 64 bits: (2^32-1)^2 + 2(2^32-1) = 2^64-1.
            // On Cortex-M4 this is one UMAAL. On Xtensa it is eight ops.
            let x = (a[j] as u64) * bi + (t[j] as u64) + (c as u64);
            t[j] = x as u32;
            c = (x >> 32) as u32;
        }
        let x = (t[n] as u64) + (c as u64);
        t[n] = x as u32;
        t[n + 1] = (x >> 32) as u32;

        // --- Montgomery reduce one word ---
        let m = t[0].wrapping_mul(n0inv);
        // Discard the low word: by construction t[0] + m*p[0] ≡ 0 mod 2^32.
        let x = (m as u64) * (p[0] as u64) + (t[0] as u64);
        c = (x >> 32) as u32;
        for j in 1..n {
            let x = (m as u64) * (p[j] as u64) + (t[j] as u64) + (c as u64);
            t[j - 1] = x as u32;
            c = (x >> 32) as u32;
        }
        let x = (t[n] as u64) + (c as u64);
        t[n - 1] = x as u32;
        t[n] = t[n + 1].wrapping_add((x >> 32) as u32);
    }

    // CIOS leaves t < 2p, so the extra word is 0 or 1 and one conditional
    // subtraction suffices.
    cond_sub_p(&t[..n], t[n], p, out);
}

/// `out = (hi:t) - p` if that does not go negative, else `out = t`.
/// Branchless and index-independent: both results are computed, one selected.
#[inline]
fn cond_sub_p(t: &[u32], hi: u32, p: &[u32], out: &mut [u32]) {
    let n = t.len();
    let mut diff = [0u32; 16];

    let mut borrow = 0u32;
    for j in 0..n {
        let (r1, b1) = t[j].overflowing_sub(p[j]);
        let (r2, b2) = r1.overflowing_sub(borrow);
        diff[j] = r2;
        borrow = (b1 as u32) | (b2 as u32);
    }

    // If hi < borrow the subtraction underflowed overall => keep t.
    //
    // NOT `(hi < borrow) as u32`: LLVM compiles that comparison to a BRANCH,
    // which made add/sub take 6 cycles longer depending on whether the
    // conditional subtraction fired — a real, measured timing leak, since
    // whether it fires depends on the operand values. Both are small, so the
    // borrow-out of `hi - borrow` is the same predicate with no branch.
    let underflow = hi.wrapping_sub(borrow) >> 31;
    let mask = underflow.wrapping_sub(1); // 0 => 0xFFFFFFFF (take diff)

    let mask = core::hint::black_box(mask);
    for j in 0..n {
        out[j] = t[j] ^ ((t[j] ^ diff[j]) & mask);
    }
}

/// `out = a + b mod p`
#[inline]
pub fn add_mod(a: &[u32], b: &[u32], p: &[u32], out: &mut [u32]) {
    let n = a.len();
    let mut t = [0u32; 16];
    let mut carry = 0u32;
    for j in 0..n {
        let (r1, c1) = a[j].overflowing_add(b[j]);
        let (r2, c2) = r1.overflowing_add(carry);
        t[j] = r2;
        carry = (c1 as u32) | (c2 as u32);
    }
    cond_sub_p(&t[..n], carry, p, out);
}

/// `out = a - b mod p`
#[inline]
pub fn sub_mod(a: &[u32], b: &[u32], p: &[u32], out: &mut [u32]) {
    let n = a.len();
    let mut t = [0u32; 16];
    let mut borrow = 0u32;
    for j in 0..n {
        let (r1, b1) = a[j].overflowing_sub(b[j]);
        let (r2, b2) = r1.overflowing_sub(borrow);
        t[j] = r2;
        borrow = (b1 as u32) | (b2 as u32);
    }
    // If it went negative, add p back. Mask is all-ones exactly when borrow=1.
    let mask = borrow.wrapping_neg();
    let mut carry = 0u32;
    for j in 0..n {
        let (r1, c1) = t[j].overflowing_add(p[j] & mask);
        let (r2, c2) = r1.overflowing_add(carry);
        out[j] = r2;
        carry = (c1 as u32) | (c2 as u32);
    }
}

// ---------------------------------------------------------------------------
// Fixed-size variants
// ---------------------------------------------------------------------------
//
// The slice versions above take runtime lengths, so LLVM emits a real loop
// with bounds checks: measured 212 cycles for an 8-limb add on Cortex-M4,
// against 994 for a full Montgomery multiply. Since the RCB point formulas use
// ~29 add/sub per point addition, that was ~30% of point-addition cost.
//
// With the limb count in the type, LLVM unrolls these into straight
// adds/adcs chains.

/// `out = a + b mod p`, limb count known at compile time.
#[inline(always)]
pub fn add_mod_n<const N: usize>(a: &[u32; N], b: &[u32; N], p: &[u32], out: &mut [u32; N]) {
    // u64 accumulation is the form LLVM turns into an adds/adcs chain. The
    // `overflowing_add` + boolean-OR spelling reads fine but blocks that:
    // measured 212 cycles either way for 8 limbs, versus ~3 instructions per
    // limb for a real carry chain.
    let mut t = [0u32; N];
    let mut carry = 0u64;
    for j in 0..N {
        let s = a[j] as u64 + b[j] as u64 + carry;
        t[j] = s as u32;
        carry = s >> 32;
    }
    cond_sub_p_n(&t, carry as u32, p, out);
}

/// `out = a - b mod p`, limb count known at compile time.
#[inline(always)]
pub fn sub_mod_n<const N: usize>(a: &[u32; N], b: &[u32; N], p: &[u32], out: &mut [u32; N]) {
    let mut t = [0u32; N];
    let mut borrow = 0i64;
    for j in 0..N {
        let d = a[j] as i64 - b[j] as i64 + borrow;
        t[j] = d as u32;
        borrow = d >> 32; // arithmetic shift: 0 or -1
    }
    // Went negative? Add p back. Mask is all-ones exactly when borrow == -1.
    // Same barrier rationale as `cond_sub_p_n`.
    let mask = core::hint::black_box(borrow as u32);
    let mut carry = 0u64;
    for j in 0..N {
        let s = t[j] as u64 + (p[j] & mask) as u64 + carry;
        out[j] = s as u32;
        carry = s >> 32;
    }
}

/// `out = (hi:t) - p` when that does not go negative, else `out = t`.
///
/// Deliberately has NO two-way select. LLVM compiles `(a & m) | (b & !m)` into
/// a select, and an N-word select is too long for a Thumb-2 IT block, so it
/// becomes a real branch on a mask derived from the operands — a measured
/// 8-cycle leak. Rewriting in XOR form did not help; LLVM reconstructs the
/// select. Instead this subtracts a MASKED modulus, the same shape as
/// `sub_mod_n`, which measured clean and needs no optimisation barrier:
/// `out = t - (p & mask)`.
///
/// The modulus is subtracted twice-over in cost (once to test, once to
/// apply), which is still cheaper than a barrier around the select.
#[inline(always)]
fn cond_sub_p_n<const N: usize>(t: &[u32; N], hi: u32, p: &[u32], out: &mut [u32; N]) {
    // Does t - p go negative?
    let mut borrow = 0i64;
    for j in 0..N {
        let d = t[j] as i64 - p[j] as i64 + borrow;
        borrow = d >> 32;
    }
    let borrow = (borrow as u32) & 1;
    // hi is the overflow word (0 or 1). Underflow overall iff hi < borrow.
    let underflow = hi.wrapping_sub(borrow) >> 31;
    // Subtract exactly when there was no underflow. The barrier is load
    // bearing: LLVM knows this mask is 0-or-all-ones and will turn the masked
    // subtraction back into a CONDITIONAL one, reintroducing the branch.
    let mask = core::hint::black_box((underflow ^ 1).wrapping_neg());

    let mut borrow2 = 0i64;
    for j in 0..N {
        let d = t[j] as i64 - (p[j] & mask) as i64 + borrow2;
        out[j] = d as u32;
        borrow2 = d >> 32;
    }
}
