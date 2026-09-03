//! Curve points and constant-time scalar multiplication.
//!
//! Uses **homogeneous projective** coordinates `(X : Y : Z)` with the
//! Renes–Costello–Batina complete addition formulas for `a = -3` (Algorithm 4
//! of "Complete addition formulas for prime order elliptic curves", 2016).
//!
//! Complete means: **one formula, no exceptions.** It is correct for `P + Q`,
//! for `P + P`, for `P + (-P)`, and for the identity, with no special cases to
//! detect. That matters far more here than raw speed — the classic way to leak
//! a scalar is a branch that fires only when the accumulator happens to equal
//! the input point. There is deliberately no separate doubling routine for the
//! same reason: `add(P, P)` is simply correct.
//!
//! The identity is `(0 : 1 : 0)`.

use crate::{comb_tables, Fe, Params};

/// A point in homogeneous projective coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point<const N: usize> {
    /// X coordinate (Montgomery form).
    pub x: Fe<N>,
    /// Y coordinate (Montgomery form).
    pub y: Fe<N>,
    /// Z coordinate (Montgomery form). Zero exactly for the identity.
    pub z: Fe<N>,
}

/// Everything the point layer needs about a curve.
#[derive(Clone, Copy)]
pub struct CurveParams {
    /// The base field.
    pub field: Params,
    /// Curve coefficient `b`, in Montgomery form.
    pub b_mont: &'static [u32],
    /// Base point x, Montgomery form.
    pub gx_mont: &'static [u32],
    /// Base point y, Montgomery form.
    pub gy_mont: &'static [u32],
    /// Order of the base point, plain integer limbs.
    pub order: &'static [u32],
}

impl<const N: usize> Point<N> {
    /// The point at infinity, `(0 : 1 : 0)`.
    pub fn identity(f: &Params) -> Self {
        let mut one = [0u32; N];
        one.copy_from_slice(f.one);
        Self {
            x: Fe::ZERO,
            y: Fe::from_mont_limbs(one),
            z: Fe::ZERO,
        }
    }

    /// The curve's base point.
    pub fn generator(c: &CurveParams) -> Self {
        let mut x = [0u32; N];
        let mut y = [0u32; N];
        let mut z = [0u32; N];
        x.copy_from_slice(c.gx_mont);
        y.copy_from_slice(c.gy_mont);
        z.copy_from_slice(c.field.one);
        Self {
            x: Fe::from_mont_limbs(x),
            y: Fe::from_mont_limbs(y),
            z: Fe::from_mont_limbs(z),
        }
    }

    /// Is this the point at infinity? `Z == 0` iff identity.
    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    /// Complete projective addition, RCB Algorithm 4 (`a = -3`).
    ///
    /// Valid for every pair of inputs including equal points and inverses, so
    /// this doubles as the doubling routine.
    pub fn add(&self, c: &CurveParams, rhs: &Self) -> Self {
        let f = &c.field;
        let mut b = [0u32; N];
        b.copy_from_slice(c.b_mont);
        let b = Fe::<N>::from_mont_limbs(b);

        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let (x2, y2, z2) = (&rhs.x, &rhs.y, &rhs.z);

        let t0 = x1.mul(f, x2);
        let t1 = y1.mul(f, y2);
        let t2 = z1.mul(f, z2);

        let t3 = x1.add(f, y1);
        let t4 = x2.add(f, y2);
        let t3 = t3.mul(f, &t4);

        let t4 = t0.add(f, &t1);
        let t3 = t3.sub(f, &t4);
        let t4 = y1.add(f, z1);

        let x3 = y2.add(f, z2);
        let t4 = t4.mul(f, &x3);
        let x3 = t1.add(f, &t2);

        let t4 = t4.sub(f, &x3);
        let x3 = x1.add(f, z1);
        let y3 = x2.add(f, z2);

        let x3 = x3.mul(f, &y3);
        let y3 = t0.add(f, &t2);
        let y3 = x3.sub(f, &y3);

        let z3 = b.mul(f, &t2);
        let x3 = y3.sub(f, &z3);
        let z3 = x3.add(f, &x3);

        let x3 = x3.add(f, &z3);
        let z3 = t1.sub(f, &x3);
        let x3 = t1.add(f, &x3);

        let y3 = b.mul(f, &y3);
        let t1 = t2.add(f, &t2);
        let t2 = t1.add(f, &t2);

        let y3 = y3.sub(f, &t2);
        let y3 = y3.sub(f, &t0);
        let t1 = y3.add(f, &y3);

        let y3 = t1.add(f, &y3);
        let t1 = t0.add(f, &t0);
        let t0 = t1.add(f, &t0);

        let t0 = t0.sub(f, &t2);
        let t1 = t4.mul(f, &y3);
        let t2 = t0.mul(f, &y3);

        let y3 = x3.mul(f, &z3);
        let y3 = y3.add(f, &t2);
        let x3 = t3.mul(f, &x3);

        let x3 = x3.sub(f, &t1);
        let z3 = t4.mul(f, &z3);
        let t1 = t3.mul(f, &t0);

        let z3 = z3.add(f, &t1);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Addition where `rhs` is affine (`Z2 == 1`), as every comb table entry
    /// is. Identical to [`add`](Self::add) with `Z2` substituted, which turns
    /// `t2 = z1*z2` into `t2 = z1` — one field multiplication saved out of 14
    /// on the operation that dominates the comb.
    ///
    /// `y2 + Z2` and `x2 + Z2` become adds with Montgomery one, supplied by
    /// the caller so it is not recomputed per call.
    pub(crate) fn add_affine(&self, c: &CurveParams, x2: &Fe<N>, y2: &Fe<N>, one: &Fe<N>) -> Self {
        let f = &c.field;
        let mut b = [0u32; N];
        b.copy_from_slice(c.b_mont);
        let b = Fe::<N>::from_mont_limbs(b);

        let (x1, y1, z1) = (&self.x, &self.y, &self.z);

        let t0 = x1.mul(f, x2);
        let t1 = y1.mul(f, y2);
        let t2 = *z1; // z1 * 1

        let t3 = x1.add(f, y1);
        let t4 = x2.add(f, y2);
        let t3 = t3.mul(f, &t4);

        let t4 = t0.add(f, &t1);
        let t3 = t3.sub(f, &t4);
        let t4 = y1.add(f, z1);

        let x3 = y2.add(f, one);
        let t4 = t4.mul(f, &x3);
        let x3 = t1.add(f, &t2);

        let t4 = t4.sub(f, &x3);
        let x3 = x1.add(f, z1);
        let y3 = x2.add(f, one);

        let x3 = x3.mul(f, &y3);
        let y3 = t0.add(f, &t2);
        let y3 = x3.sub(f, &y3);

        let z3 = b.mul(f, &t2);
        let x3 = y3.sub(f, &z3);
        let z3 = x3.add(f, &x3);

        let x3 = x3.add(f, &z3);
        let z3 = t1.sub(f, &x3);
        let x3 = t1.add(f, &x3);

        let y3 = b.mul(f, &y3);
        let t1 = t2.add(f, &t2);
        let t2 = t1.add(f, &t2);

        let y3 = y3.sub(f, &t2);
        let y3 = y3.sub(f, &t0);
        let t1 = y3.add(f, &y3);

        let y3 = t1.add(f, &y3);
        let t1 = t0.add(f, &t0);
        let t0 = t1.add(f, &t0);

        let t0 = t0.sub(f, &t2);
        let t1 = t4.mul(f, &y3);
        let t2 = t0.mul(f, &y3);

        let y3 = x3.mul(f, &z3);
        let y3 = y3.add(f, &t2);
        let x3 = t3.mul(f, &x3);

        let x3 = x3.sub(f, &t1);
        let z3 = t4.mul(f, &z3);
        let t1 = t3.mul(f, &t0);

        let z3 = z3.add(f, &t1);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Branchless select: returns `b` when `choice` is all-ones, `a` when zero.
    #[inline]
    fn select_mask(mask: u32, a: &Self, b: &Self) -> Self {
        // XOR form, not or-of-ands: LLVM turns the latter into a select, and a
        // 3N-word select is far too long for a Thumb-2 IT block, so it becomes
        // a real branch on the mask — which is derived from the secret scalar.
        let mask = core::hint::black_box(mask);
        let mut out = *a;
        for i in 0..N {
            out.x.v[i] = a.x.v[i] ^ ((a.x.v[i] ^ b.x.v[i]) & mask);
            out.y.v[i] = a.y.v[i] ^ ((a.y.v[i] ^ b.y.v[i]) & mask);
            out.z.v[i] = a.z.v[i] ^ ((a.z.v[i] ^ b.z.v[i]) & mask);
        }
        out
    }

    /// Branchless table lookup: returns `table[digit]` without ever indexing
    /// memory by a secret.
    ///
    /// Every entry is read and masked; exactly one mask is all-ones. An
    /// ordinary `table[digit]` would make the *address* depend on the scalar,
    /// which is the textbook cache/timing leak.
    #[inline]
    pub(crate) fn lookup(table: &[Self; 16], digit: u32) -> Self {
        let mut out = Self {
            x: Fe::ZERO,
            y: Fe::ZERO,
            z: Fe::ZERO,
        };
        for (i, entry) in table.iter().enumerate() {
            let d = (i as u32) ^ digit;
            // all-ones iff d == 0, with no branch
            let nz = d | d.wrapping_neg();
            let mask = ((nz >> 31) & 1).wrapping_sub(1);
            for j in 0..N {
                out.x.v[j] |= entry.x.v[j] & mask;
                out.y.v[j] |= entry.y.v[j] & mask;
                out.z.v[j] |= entry.z.v[j] & mask;
            }
        }
        out
    }

    /// `k * self`, constant time in `k`.
    ///
    /// Fixed 4-bit window. Double-and-add-always costs two point operations
    /// per bit; this costs four doublings plus one addition per *nibble*, so
    /// roughly a third fewer — 335 point operations instead of 512 for P-256.
    ///
    /// Uniformity is preserved: the window count is fixed by the scalar's
    /// width, the table lookup is a branchless masked scan, and the leading
    /// doublings are performed unconditionally (they act on the identity,
    /// which the complete formulas handle) rather than skipped by a branch.
    ///
    /// Costs a 16-entry table on the stack: 1.5 KiB for P-256, 2.3 KiB for
    /// P-384.
    pub fn mul_scalar(&self, c: &CurveParams, k: &[u32]) -> Self {
        debug_assert_eq!(k.len(), N);
        // Precompute table[i] = i * self.
        let mut table = [Self::identity(&c.field); 16];
        table[1] = *self;
        for i in 2..16 {
            table[i] = table[i - 1].add(c, self);
        }
        // Most-significant nibble first.
        let mut acc = Self::identity(&c.field);
        for nib in (0..N * 8).rev() {
            for _ in 0..4 {
                acc = acc.add(c, &acc);
            }
            let digit = (k[nib / 8] >> ((nib % 8) * 4)) & 0xF;
            let sel = Self::lookup(&table, digit);
            acc = acc.add(c, &sel);
        }
        acc
    }

    /// `k * G` using the compile-time comb table for this curve.
    ///
    /// One doubling and one addition per bit of a *block*, consuming one bit
    /// from all four blocks at once, so `D` iterations instead of the runtime
    /// window's `8N` nibbles: 128 point operations for P-256 against 334, and
    /// 192 against 494 for P-384.
    ///
    /// Only valid for the generator — [`mul_scalar`](Self::mul_scalar) remains
    /// the variable-base path (ECDH against a peer's key).
    pub fn mul_base(
        c: &CurveParams,
        k: &[u32],
        table: &[([u32; N], [u32; N])],
        d: usize,
        ntables: usize,
    ) -> Self {
        debug_assert_eq!(k.len(), N);
        debug_assert_eq!(table.len(), ntables * 16);

        let mut acc = Self::identity(&c.field);
        for i in (0..d).rev() {
            acc = Self::comb_iteration(c, &acc, k, table, d, ntables, i);
        }
        acc
    }

    /// One comb iteration: double, then add the table entry selected by bit
    /// `i` of each block. Shared by the blocking and resumable paths so they
    /// cannot drift apart.
    pub(crate) fn comb_iteration(
        c: &CurveParams,
        acc: &Self,
        k: &[u32],
        table: &[([u32; N], [u32; N])],
        d: usize,
        ntables: usize,
        i: usize,
    ) -> Self {
        let mut acc = acc.add(c, acc);
        for t in 0..ntables {
            // Gather bit `i` from this table's four blocks. Positions depend
            // only on loop indices, never on the scalar's value.
            let mut digit = 0u32;
            for b in 0..4usize {
                let bit = (t * 4 + b) * d + i;
                digit |= ((k[bit / 32] >> (bit % 32)) & 1) << b;
            }
            // `digit` is secret. Everything downstream of it is branchless by
            // construction; see the constant-time note in the crate README for
            // an OPEN issue about a residual signal at this level.
            let digit = core::hint::black_box(digit);
            let table = &table[t * 16..t * 16 + 16];

            // Branchless masked scan, as in `lookup`: never index by a secret.
            let mut px = [0u32; N];
            let mut py = [0u32; N];
            for (j, entry) in table.iter().enumerate() {
                let dd = (j as u32) ^ digit;
                let nz = dd | dd.wrapping_neg();
                // LOAD BEARING. Without this, LLVM proves exactly one mask is
                // all-ones and compiles the scan into an EARLY-EXIT SEARCH:
                // `beq` to the matching entry, `bne` to loop. The iteration
                // count then *is* the secret digit. Verified by instruction
                // trace: digit 0 and digit 15 executed disjoint PC ranges;
                // with the barrier they execute byte-identical traces.
                let mask = core::hint::black_box(((nz >> 31) & 1).wrapping_sub(1));
                for t in 0..N {
                    px[t] |= entry.0[t] & mask;
                    py[t] |= entry.1[t] & mask;
                }
            }

            // digit == 0 selects the identity entry, which is stored as
            // (0, 1); pairing it with Z = 0 gives the projective identity
            // (0 : 1 : 0). Storing (0, 0) instead would yield (0 : 0 : 0),
            // which is not a point and which the complete formulas do not
            // rescue -- that mistake produced wrong results, not a crash.
            // Also load bearing: otherwise LLVM branches on this to choose
            // between "copy Montgomery one" and "zero the array".
            let is_zero = core::hint::black_box({
                let nz = digit | digit.wrapping_neg();
                ((nz >> 31) & 1).wrapping_sub(1) // all-ones iff digit == 0
            });
            let mut z = [0u32; N];
            z.copy_from_slice(c.field.one);
            for t in 0..N {
                z[t] &= !is_zero;
            }

            let mut one_l = [0u32; N];
            one_l.copy_from_slice(c.field.one);
            let one = Fe::from_mont_limbs(one_l);
            let sel = Self {
                x: Fe::from_mont_limbs(px),
                y: Fe::from_mont_limbs(py),
                z: Fe::from_mont_limbs(z),
            };
            // NOTE: this deliberately uses the GENERAL addition, not the
            // mixed (affine) one, even though every table entry is affine and
            // the mixed formula saves a multiplication (~8%).
            //
            // The mixed path measured NON-CONSTANT-TIME in the comb: with the
            // field operations and `Point::add` both proven flat on hardware
            // (spread 0), `mul_base` still varied by ~1200 cycles (P-256) with
            // the scalar. The general formula makes adding the identity a real
            // no-op, so no `select_mask` is needed either -- and that
            // combination measures flat. The 8% is not worth an unexplained
            // timing signal on the secret scalar.
            acc = acc.add(c, &sel);
        }
        acc
    }

    /// One comb table scan, isolated, for instruction tracing.
    ///
    /// `#[inline(never)]` so it occupies a distinct PC range that a QEMU
    /// execution trace can be filtered to.
    ///
    /// Not part of the supported API.
    #[doc(hidden)]
    #[inline(never)]
    pub fn comb_scan_diag(c: &CurveParams, table: &[([u32; N], [u32; N])], digit: u32) -> Self {
        let mut px = [0u32; N];
        let mut py = [0u32; N];
        for (j, entry) in table.iter().take(16).enumerate() {
            let dd = (j as u32) ^ digit;
            let nz = dd | dd.wrapping_neg();
            // Opaque: LLVM can otherwise prove exactly one mask is all-ones
            // and compile this scan into a SWITCH on the secret digit, with
            // specialised code per value. Confirmed by instruction trace --
            // digit 0 and digit 15 executed disjoint PC ranges.
            let mask = core::hint::black_box(((nz >> 31) & 1).wrapping_sub(1));
            for q in 0..N {
                px[q] |= entry.0[q] & mask;
                py[q] |= entry.1[q] & mask;
            }
        }
        // Opaque for the same reason as the scan mask: otherwise LLVM
        // branches on it to pick between "copy one" and "zero the array".
        let is_zero = core::hint::black_box({
            let nz = digit | digit.wrapping_neg();
            ((nz >> 31) & 1).wrapping_sub(1)
        });
        let mut z = [0u32; N];
        z.copy_from_slice(c.field.one);
        for q in 0..N {
            z[q] &= !is_zero;
        }
        Self {
            x: Fe::from_mont_limbs(px),
            y: Fe::from_mont_limbs(py),
            z: Fe::from_mont_limbs(z),
        }
    }

    /// Diagnostic-only comb with selectable ablations, for localising the
    /// open scalar-dependent timing signal. Mirrors [`mul_base`](Self::mul_base)
    /// exactly at `mode == 0`.
    ///
    /// - 0 — full comb (baseline)
    /// - 1 — real scan, FIXED addend: the accumulator then evolves identically
    ///   for every scalar, so a leak here is in the SCAN
    /// - 2 — no scan, fixed addend (control; should be flat)
    /// - 4 — real scan and addend, doubling skipped
    ///
    /// ⚠ There is deliberately no "constant digit" mode: forcing the digit lets
    /// LLVM constant-fold the mask computation and collapse the scan to a
    /// direct load, so it measures flat for the wrong reason. It was a useless
    /// control and is not worth re-adding.
    ///
    /// Not part of the supported API.
    #[doc(hidden)]
    pub fn mul_base_diag(
        c: &CurveParams,
        k: &[u32],
        table: &[([u32; N], [u32; N])],
        d: usize,
        ntables: usize,
        mode: u32,
    ) -> Self {
        let fixed = Self::generator(c);
        let mut acc = Self::identity(&c.field);
        for i in (0..d).rev() {
            if mode != 4 {
                acc = acc.add(c, &acc);
            }
            for t in 0..ntables {
                let mut digit = 0u32;
                for b in 0..4usize {
                    let bit = (t * 4 + b) * d + i;
                    digit |= ((k[bit / 32] >> (bit % 32)) & 1) << b;
                }
                let digit = core::hint::black_box(digit);
                let sel = if mode == 2 {
                    fixed
                } else {
                    let tt = &table[t * 16..t * 16 + 16];
                    let mut px = [0u32; N];
                    let mut py = [0u32; N];
                    for (j, entry) in tt.iter().enumerate() {
                        let dd = (j as u32) ^ digit;
                        let nz = dd | dd.wrapping_neg();
                        let mask = core::hint::black_box(((nz >> 31) & 1).wrapping_sub(1));
                        for q in 0..N {
                            px[q] |= entry.0[q] & mask;
                            py[q] |= entry.1[q] & mask;
                        }
                    }
                    let is_zero = core::hint::black_box({
                        let nz = digit | digit.wrapping_neg();
                        ((nz >> 31) & 1).wrapping_sub(1)
                    });
                    let mut z = [0u32; N];
                    z.copy_from_slice(c.field.one);
                    for q in 0..N {
                        z[q] &= !is_zero;
                    }
                    Self {
                        x: Fe::from_mont_limbs(px),
                        y: Fe::from_mont_limbs(py),
                        z: Fe::from_mont_limbs(z),
                    }
                };
                let addend = if mode == 1 {
                    core::hint::black_box(&sel);
                    fixed
                } else {
                    sel
                };
                acc = acc.add(c, &addend);
            }
        }
        acc
    }

    /// Convert to affine `(x, y)` as plain integers. Returns `None` for the
    /// identity, which has no affine representation.
    pub fn to_affine(&self, f: &Params) -> Option<([u32; N], [u32; N])> {
        if self.is_identity() {
            return None;
        }
        let zinv = self.z.invert(f);
        let x = self.x.mul(f, &zinv);
        let y = self.y.mul(f, &zinv);
        Some((x.to_int(f), y.to_int(f)))
    }
}
