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

        Self { x: x3, y: y3, z: z3 }
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

        Self { x: x3, y: y3, z: z3 }
    }

    /// Branchless select: returns `b` when `choice` is all-ones, `a` when zero.
    #[inline]
    fn select_mask(mask: u32, a: &Self, b: &Self) -> Self {
        let mut out = *a;
        for i in 0..N {
            out.x.v[i] = (a.x.v[i] & !mask) | (b.x.v[i] & mask);
            out.y.v[i] = (a.y.v[i] & !mask) | (b.y.v[i] & mask);
            out.z.v[i] = (a.z.v[i] & !mask) | (b.z.v[i] & mask);
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
            let table = &table[t * 16..t * 16 + 16];

            // Branchless masked scan, as in `lookup`: never index by a secret.
            let mut px = [0u32; N];
            let mut py = [0u32; N];
            for (j, entry) in table.iter().enumerate() {
                let dd = (j as u32) ^ digit;
                let nz = dd | dd.wrapping_neg();
                let mask = ((nz >> 31) & 1).wrapping_sub(1);
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
            let is_zero = {
                let nz = digit | digit.wrapping_neg();
                ((nz >> 31) & 1).wrapping_sub(1) // all-ones iff digit == 0
            };
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
            // `digit` comes from the SECRET scalar, so this must not branch:
            // the mixed and general formulas cost a different number of
            // multiplications, and choosing between them with an `if` would
            // leak whether the digit is zero. Always compute the mixed
            // addition, then branchlessly keep the old accumulator when the
            // digit was zero (adding the identity is a no-op). The discarded
            // result is harmless -- the formula has no divisions or branches.
            let sum = acc.add_affine(c, &sel.x, &sel.y, &one);
            let _ = sel.z;
            acc = Self::select_mask(is_zero, &sum, &acc);
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
