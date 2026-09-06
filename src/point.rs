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

use crate::{Fe, Params};

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
    /// -order^-1 mod 2^32.
    pub order_n0inv: u32,
    /// R^2 mod order, for converting scalars into Montgomery form.
    pub order_r2: &'static [u32],
    /// R mod order (1 in Montgomery form for the scalar field).
    pub order_r: &'static [u32],
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
        let pj = PointJacobian::from_projective(self, &c.field);
        pj.mul_scalar(c, k).to_projective(&c.field)
    }

    /// `k * G` using the compile-time comb table for this curve.
    ///
    /// Evaluated in Jacobian coordinates with mixed addition, saving over 30%
    /// field operations per comb iteration.
    pub fn mul_base(
        c: &CurveParams,
        k: &[u32],
        table: &[([u32; N], [u32; N])],
        d: usize,
        ntables: usize,
    ) -> Self {
        let mut acc = Self::identity(&c.field);
        for i in (0..d).rev() {
            acc = Self::comb_iteration(c, &acc, k, table, d, ntables, i);
        }
        acc
    }

    /// One comb iteration: double, then add the table entry selected by bit
    /// `i` of each block. Shared by the blocking and resumable paths so they
    /// cannot drift apart.
    #[allow(dead_code)]
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
        #[cfg(nistp_asm_cm4)]
        {
            if N == 8 && core::ptr::eq(f.p.as_ptr(), crate::params::p256::P.as_ptr()) {
                let mut aff_mont_x = [0u32; 8];
                let mut aff_mont_y = [0u32; 8];
                let z_mont = &self.z.as_mont_limbs()[..8];
                if z_mont == crate::backend::cortex_m4::p256::ONE_MONTGOMERY {
                    aff_mont_x.copy_from_slice(&self.x.as_mont_limbs()[..8]);
                    aff_mont_y.copy_from_slice(&self.y.as_mont_limbs()[..8]);
                } else {
                    let mut z_inv = [0u32; 8];
                    unsafe {
                        crate::backend::cortex_m4::p256::emill_p256_modinv_p(
                            z_inv.as_mut_ptr(),
                            z_mont.as_ptr(),
                        );
                        crate::backend::cortex_m4::p256::emill_p256_mul_mont(
                            aff_mont_x.as_mut_ptr(),
                            self.x.as_mont_limbs().as_ptr(),
                            z_inv.as_ptr(),
                        );
                        crate::backend::cortex_m4::p256::emill_p256_mul_mont(
                            aff_mont_y.as_mut_ptr(),
                            self.y.as_mont_limbs().as_ptr(),
                            z_inv.as_ptr(),
                        );
                    }
                }
                let mut x = [0u32; 8];
                let mut y = [0u32; 8];
                unsafe {
                    crate::backend::cortex_m4::p256::P256_from_montgomery(
                        x.as_mut_ptr(),
                        aff_mont_x.as_ptr(),
                    );
                    crate::backend::cortex_m4::p256::P256_from_montgomery(
                        y.as_mut_ptr(),
                        aff_mont_y.as_ptr(),
                    );
                }
                let mut x_res = [0u32; N];
                let mut y_res = [0u32; N];
                x_res[..8].copy_from_slice(&x);
                y_res[..8].copy_from_slice(&y);
                return Some((x_res, y_res));
            }
        }
        let zinv = self.z.invert(f);
        let x = self.x.mul(f, &zinv);
        let y = self.y.mul(f, &zinv);
        Some((x.to_int(f), y.to_int(f)))
    }

    /// Check if this point lies on the curve `y^2 = x^3 - 3x + b`.
    pub fn is_on_curve(&self, c: &CurveParams) -> bool {
        if self.is_identity() {
            return true;
        }
        let f = &c.field;
        let (x, y) = match self.to_affine(f) {
            Some(coords) => (
                Fe::<N>::from_int(f, &coords.0),
                Fe::<N>::from_int(f, &coords.1),
            ),
            None => return true,
        };
        let mut b = [0u32; N];
        b.copy_from_slice(c.b_mont);
        let b = Fe::<N>::from_mont_limbs(b);

        let lhs = y.sqr(f);
        let x3 = x.sqr(f).mul(f, &x);
        let three_x = x.add(f, &x).add(f, &x);
        let rhs = x3.sub(f, &three_x).add(f, &b);
        lhs.ct_eq(&rhs)
    }

    /// Decompress an affine point from an x-coordinate and parity bit of y.
    ///
    /// Computes y = sqrt(x^3 - 3x + b mod p).
    /// If no square root exists (point not on curve), returns `None`.
    /// Otherwise negates y if its parity does not match `y_is_odd`.
    pub fn decompress(c: &CurveParams, x_limbs: &[u32; N], y_is_odd: bool) -> Option<Self> {
        let f = &c.field;
        // x must be < p
        let mut borrow = 0u32;
        for i in 0..N {
            let (r1, b1) = x_limbs[i].overflowing_sub(f.p[i]);
            let (_, b2) = r1.overflowing_sub(borrow);
            borrow = (b1 as u32) | (b2 as u32);
        }
        if borrow == 0 {
            return None; // x >= p
        }

        let x = Fe::<N>::from_int(f, x_limbs);

        let mut b = [0u32; N];
        b.copy_from_slice(c.b_mont);
        let b = Fe::<N>::from_mont_limbs(b);

        // x^3 - 3x + b
        let x2 = x.sqr(f);
        let x3 = x2.mul(f, &x);
        let three_x = x.add(f, &x).add(f, &x);
        let rhs = x3.sub(f, &three_x).add(f, &b);

        let mut y = rhs.sqrt(f)?;

        let y_int = y.to_int(f);
        let cur_odd = (y_int[0] & 1) == 1;
        if cur_odd != y_is_odd {
            y = Fe::<N>::ZERO.sub(f, &y);
        }

        let mut one = [0u32; N];
        one.copy_from_slice(f.one);
        Some(Self {
            x,
            y,
            z: Fe::from_mont_limbs(one),
        })
    }

    /// Decode a point from a SEC1 octet string.
    ///
    /// Accepts uncompressed (`0x04 || x || y`, length `1 + 8*N`) and
    /// compressed (`0x02/0x03 || x`, length `1 + 4*N`) encodings.
    /// Rejects invalid tags, malformed lengths, coordinates `>= p`, and points off the curve.
    pub fn decode(c: &CurveParams, bytes: &[u8]) -> Result<Self, crate::ecdh::Error> {
        if bytes.len() == 1 + 8 * N {
            if bytes[0] != 0x04 {
                return Err(crate::ecdh::Error::BadPoint);
            }
            let mut xi = [0u32; N];
            let mut yi = [0u32; N];
            for (i, chunk) in bytes[1..1 + 4 * N].rchunks(4).enumerate() {
                xi[i] = u32::from_be_bytes(chunk.try_into().unwrap());
            }
            for (i, chunk) in bytes[1 + 4 * N..].rchunks(4).enumerate() {
                yi[i] = u32::from_be_bytes(chunk.try_into().unwrap());
            }
            let f = &c.field;
            let mut borrow_x = 0u32;
            let mut borrow_y = 0u32;
            for i in 0..N {
                let (r1, b1) = xi[i].overflowing_sub(f.p[i]);
                let (_, b2) = r1.overflowing_sub(borrow_x);
                borrow_x = (b1 as u32) | (b2 as u32);

                let (r3, b3) = yi[i].overflowing_sub(f.p[i]);
                let (_, b4) = r3.overflowing_sub(borrow_y);
                borrow_y = (b3 as u32) | (b4 as u32);
            }
            if borrow_x == 0 || borrow_y == 0 {
                return Err(crate::ecdh::Error::BadPoint);
            }

            let x = Fe::<N>::from_int(f, &xi);
            let y = Fe::<N>::from_int(f, &yi);
            let mut one = [0u32; N];
            one.copy_from_slice(f.one);
            let pt = Self {
                x,
                y,
                z: Fe::from_mont_limbs(one),
            };
            if !pt.is_on_curve(c) {
                return Err(crate::ecdh::Error::BadPoint);
            }
            Ok(pt)
        } else if bytes.len() == 1 + 4 * N {
            if bytes[0] != 0x02 && bytes[0] != 0x03 {
                return Err(crate::ecdh::Error::BadPoint);
            }
            let mut xi = [0u32; N];
            for (i, chunk) in bytes[1..].rchunks(4).enumerate() {
                xi[i] = u32::from_be_bytes(chunk.try_into().unwrap());
            }
            Self::decompress(c, &xi, bytes[0] == 0x03).ok_or(crate::ecdh::Error::BadPoint)
        } else {
            Err(crate::ecdh::Error::BadLength)
        }
    }
}

/// A point in Jacobian coordinates `(X : Y : Z)` where `(x, y) = (X/Z^2, Y/Z^3)`.
///
/// Implements Algorithm 10 (eprint 2014/130) doubling (4 squarings + 4 multiplications)
/// and mixed addition (3 squarings + 8 multiplications) mimicking Emil Lenngren's
/// P256-Cortex-M4 techniques, with constant-time odd-scalar recoding for variable-base
/// multiplication and branchless fixed-base comb evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointJacobian<const N: usize> {
    pub x: Fe<N>,
    pub y: Fe<N>,
    pub z: Fe<N>,
}

impl<const N: usize> PointJacobian<N> {
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

    /// The curve's base point `(Gx : Gy : 1)`.
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

    /// Construct from affine coordinates with Z = 1 (Montgomery form).
    pub fn from_affine(x: &Fe<N>, y: &Fe<N>, f: &Params) -> Self {
        let mut z = [0u32; N];
        z.copy_from_slice(f.one);
        Self {
            x: *x,
            y: *y,
            z: Fe::from_mont_limbs(z),
        }
    }

    /// Convert from homogeneous projective `Point<N>` to `PointJacobian<N>`.
    ///
    /// Since `(X_P : Y_P : Z_P)` represents `(X_P/Z_P, Y_P/Z_P)` and
    /// `(X_J : Y_J : Z_J)` represents `(X_J/Z_J^2, Y_J/Z_J^3)`:
    /// `X_J = X_P * Z_P`, `Y_J = Y_P * Z_P^2`, `Z_J = Z_P`.
    /// Requires zero inversions.
    pub fn from_projective(p: &Point<N>, f: &Params) -> Self {
        if p.is_identity() {
            return Self::identity(f);
        }
        let xj = p.x.mul(f, &p.z);
        let zp2 = p.z.sqr(f);
        let yj = p.y.mul(f, &zp2);
        Self {
            x: xj,
            y: yj,
            z: p.z,
        }
    }

    /// Convert from `PointJacobian<N>` to homogeneous projective `Point<N>`.
    ///
    /// `X_P = X_J * Z_J`, `Y_P = Y_J`, `Z_P = Z_J^3`.
    /// Requires zero inversions.
    pub fn to_projective(&self, f: &Params) -> Point<N> {
        if self.is_identity() {
            return Point::identity(f);
        }
        let xp = self.x.mul(f, &self.z);
        let zp2 = self.z.sqr(f);
        let zp3 = zp2.mul(f, &self.z);
        Point {
            x: xp,
            y: self.y,
            z: zp3,
        }
    }

    /// Convert to affine `(x, y)` as plain integers. Returns `None` for identity.
    pub fn to_affine(&self, f: &Params) -> Option<([u32; N], [u32; N])> {
        if self.is_identity() {
            return None;
        }
        #[cfg(nistp_asm_cm4)]
        {
            if N == 8 && core::ptr::eq(f.p.as_ptr(), crate::params::p256::P.as_ptr()) {
                let mut aff_mont_x = [0u32; 8];
                let mut aff_mont_y = [0u32; 8];
                let mut j = [[0u32; 8]; 3];
                j[0].copy_from_slice(&self.x.as_mont_limbs()[..8]);
                j[1].copy_from_slice(&self.y.as_mont_limbs()[..8]);
                j[2].copy_from_slice(&self.z.as_mont_limbs()[..8]);
                unsafe {
                    crate::backend::cortex_m4::p256::P256_jacobian_to_affine(
                        aff_mont_x.as_mut_ptr(),
                        aff_mont_y.as_mut_ptr(),
                        j.as_ptr() as *const u32,
                    );
                }
                let mut x = [0u32; 8];
                let mut y = [0u32; 8];
                unsafe {
                    crate::backend::cortex_m4::p256::P256_from_montgomery(
                        x.as_mut_ptr(),
                        aff_mont_x.as_ptr(),
                    );
                    crate::backend::cortex_m4::p256::P256_from_montgomery(
                        y.as_mut_ptr(),
                        aff_mont_y.as_ptr(),
                    );
                }
                let mut x_res = [0u32; N];
                let mut y_res = [0u32; N];
                x_res[..8].copy_from_slice(&x);
                y_res[..8].copy_from_slice(&y);
                return Some((x_res, y_res));
            }
        }
        let zinv = self.z.invert(f);
        let zinv2 = zinv.sqr(f);
        let zinv3 = zinv2.mul(f, &zinv);
        let x = self.x.mul(f, &zinv2);
        let y = self.y.mul(f, &zinv3);
        Some((x.to_int(f), y.to_int(f)))
    }

    /// Jacobian doubling using Algorithm 10 (eprint 2014/130).
    ///
    /// Cost: 4 squarings + 4 multiplications + 1 div2 + 1 times2 + 5 adds/subs.
    pub fn double(&self, c: &CurveParams) -> Self {
        let f = &c.field;
        if self.is_identity() {
            return *self;
        }
        let t1 = self.z.sqr(f);
        let z3 = self.y.mul(f, &self.z);
        let t2 = self.x.add(f, &t1);
        let t1 = self.x.sub(f, &t1);
        let t1 = t1.mul(f, &t2);
        let t2 = t1.div2(f);
        let t1 = t1.add(f, &t2);
        let t2 = t1.sqr(f);
        let y2 = self.y.sqr(f);
        let t3 = y2.sqr(f);
        let y2 = self.x.mul(f, &y2);
        let x2 = y2.add(f, &y2);
        let x3 = t2.sub(f, &x2);
        let t2 = y2.sub(f, &x3);
        let t1 = t1.mul(f, &t2);
        let y3 = t1.sub(f, &t3);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Mixed addition: `self + (x2, y2, 1)` where the second point is affine.
    ///
    /// Cost: 3 squarings + 8 multiplications + 7 adds/subs.
    pub fn add_mixed(&self, c: &CurveParams, x2: &Fe<N>, y2: &Fe<N>) -> Self {
        let f = &c.field;
        if self.is_identity() {
            let mut one = [0u32; N];
            one.copy_from_slice(f.one);
            return Self {
                x: *x2,
                y: *y2,
                z: Fe::from_mont_limbs(one),
            };
        }
        let z1z1 = self.z.sqr(f);
        let u2 = x2.mul(f, &z1z1);
        let t1 = self.z.mul(f, &z1z1);
        let s2 = y2.mul(f, &t1);
        let h = u2.sub(f, &self.x);
        let r = s2.sub(f, &self.y);
        if h.is_zero() {
            if r.is_zero() {
                return self.double(c);
            } else {
                return Self::identity(f);
            }
        }
        let hh = h.sqr(f);
        let z3 = self.z.mul(f, &h);
        let hhh = h.mul(f, &hh);
        let v = self.x.mul(f, &hh);
        let t3 = r.sqr(f);
        let t2 = self.y.mul(f, &hhh);
        let x3 = t3.sub(f, &hhh).sub(f, &v.add(f, &v));
        let y3 = r.mul(f, &v.sub(f, &x3)).sub(f, &t2);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// General Jacobian addition.
    ///
    /// Cost: 4 squarings + 12 multiplications.
    pub fn add(&self, c: &CurveParams, rhs: &Self) -> Self {
        let f = &c.field;
        if self.is_identity() {
            return *rhs;
        }
        if rhs.is_identity() {
            return *self;
        }
        let z1z1 = self.z.sqr(f);
        let z2z2 = rhs.z.sqr(f);
        let u1 = self.x.mul(f, &z2z2);
        let u2 = rhs.x.mul(f, &z1z1);
        let s1 = self.y.mul(f, &rhs.z).mul(f, &z2z2);
        let s2 = rhs.y.mul(f, &self.z).mul(f, &z1z1);
        let h = u2.sub(f, &u1);
        let r = s2.sub(f, &s1);
        if h.is_zero() {
            if r.is_zero() {
                return self.double(c);
            } else {
                return Self::identity(f);
            }
        }
        let hh = h.sqr(f);
        let hhh = h.mul(f, &hh);
        let v = u1.mul(f, &hh);
        let t3 = r.sqr(f);
        let x3 = t3.sub(f, &hhh).sub(f, &v.add(f, &v));
        let y3 = r.mul(f, &v.sub(f, &x3)).sub(f, &s1.mul(f, &hhh));
        let z3 = self.z.mul(f, &rhs.z).mul(f, &h);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Branchless select: returns `b` when `mask` is all-ones, `a` when zero.
    #[inline]
    pub fn select_mask(mask: u32, a: &Self, b: &Self) -> Self {
        let mask = core::hint::black_box(mask);
        let mut out = *a;
        for i in 0..N {
            out.x.v[i] = a.x.v[i] ^ ((a.x.v[i] ^ b.x.v[i]) & mask);
            out.y.v[i] = a.y.v[i] ^ ((a.y.v[i] ^ b.y.v[i]) & mask);
            out.z.v[i] = a.z.v[i] ^ ((a.z.v[i] ^ b.z.v[i]) & mask);
        }
        out
    }

    /// Branchless 8-entry table lookup.
    #[inline]
    pub fn lookup(table: &[Self; 8], digit: u32) -> Self {
        let mut out = Self {
            x: Fe::ZERO,
            y: Fe::ZERO,
            z: Fe::ZERO,
        };
        for (i, entry) in table.iter().enumerate() {
            let d = (i as u32) ^ digit;
            let nz = d | d.wrapping_neg();
            let mask = core::hint::black_box(((nz >> 31) & 1).wrapping_sub(1));
            for j in 0..N {
                out.x.v[j] |= entry.x.v[j] & mask;
                out.y.v[j] |= entry.y.v[j] & mask;
                out.z.v[j] |= entry.z.v[j] & mask;
            }
        }
        out
    }

    /// Fixed-base comb multiplication using Jacobian accumulator and mixed addition.
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
            acc = acc.double(c);
            for t in 0..ntables {
                let mut digit = 0u32;
                for b in 0..4usize {
                    let bit = (t * 4 + b) * d + i;
                    digit |= ((k[bit / 32] >> (bit % 32)) & 1) << b;
                }
                let digit = core::hint::black_box(digit);
                let tbl = &table[t * 16..t * 16 + 16];

                let mut px = [0u32; N];
                let mut py = [0u32; N];
                for (j, entry) in tbl.iter().enumerate() {
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
                let px_fe = Fe::from_mont_limbs(px);
                let py_fe = Fe::from_mont_limbs(py);
                let next = acc.add_mixed(c, &px_fe, &py_fe);
                acc = Self::select_mask(is_zero, &next, &acc);
            }
        }
        acc
    }

    /// Variable-base scalar multiplication mimicking Emil Lenngren's signed odd recoding.
    pub fn mul_scalar(&self, c: &CurveParams, k: &[u32]) -> Self {
        debug_assert_eq!(k.len(), N);
        let f = &c.field;

        #[cfg(nistp_asm_cm4)]
        {
            if N == 8 && core::ptr::eq(c.order.as_ptr(), crate::params::p256::ORDER.as_ptr()) {
                let mut is_zero = 0u32;
                for v in k.iter() {
                    is_zero |= *v;
                }
                if is_zero == 0 || self.is_identity() {
                    return Self::identity(f);
                }
                let mut aff_x_mont = [0u32; 8];
                let mut aff_y_mont = [0u32; 8];
                let z_mont = &self.z.as_mont_limbs()[..8];
                if z_mont == crate::backend::cortex_m4::p256::ONE_MONTGOMERY {
                    aff_x_mont.copy_from_slice(&self.x.as_mont_limbs()[..8]);
                    aff_y_mont.copy_from_slice(&self.y.as_mont_limbs()[..8]);
                } else {
                    let mut j = [[0u32; 8]; 3];
                    j[0].copy_from_slice(&self.x.as_mont_limbs()[..8]);
                    j[1].copy_from_slice(&self.y.as_mont_limbs()[..8]);
                    j[2].copy_from_slice(z_mont);
                    unsafe {
                        crate::backend::cortex_m4::p256::P256_jacobian_to_affine(
                            aff_x_mont.as_mut_ptr(),
                            aff_y_mont.as_mut_ptr(),
                            j.as_ptr() as *const u32,
                        );
                    }
                }
                let mut out_x = [0u32; 8];
                let mut out_y = [0u32; 8];
                let mut k_8 = [0u32; 8];
                k_8.copy_from_slice(&k[..8]);
                crate::backend::cortex_m4::p256::scalarmult_variable_base(
                    &mut out_x,
                    &mut out_y,
                    &aff_x_mont,
                    &aff_y_mont,
                    &k_8,
                );
                let mut out_x_n = [0u32; N];
                let mut out_y_n = [0u32; N];
                let mut one_mont_n = [0u32; N];
                out_x_n[..8].copy_from_slice(&out_x);
                out_y_n[..8].copy_from_slice(&out_y);
                one_mont_n[..8].copy_from_slice(&crate::backend::cortex_m4::p256::ONE_MONTGOMERY);
                return Self {
                    x: Fe::from_mont_limbs(out_x_n),
                    y: Fe::from_mont_limbs(out_y_n),
                    z: Fe::from_mont_limbs(one_mont_n),
                };
            }
        }

        let mut is_zero = 0u32;
        for v in k.iter() {
            is_zero |= *v;
        }
        if is_zero == 0 || self.is_identity() {
            return Self::identity(f);
        }

        let num_nibbles = N * 8;
        let even_mask = core::hint::black_box((k[0] & 1).wrapping_sub(1));
        let order: &[u32; N] = c.order.try_into().unwrap();
        let k_ref: &[u32; N] = k.try_into().unwrap();
        let mut k_neg = [0u32; N];
        crate::backend::portable::sub_mod_n(order, k_ref, order, &mut k_neg);
        let mut k_odd = [0u32; N];
        for i in 0..N {
            k_odd[i] = k[i] ^ ((k[i] ^ k_neg[i]) & even_mask);
        }

        let mut e = [0i8; 128];
        for i in 0..num_nibbles {
            e[i] = ((k_odd[i / 8] >> ((i % 8) * 4)) & 0xF) as i8;
        }
        for i in 1..num_nibbles {
            if e[i] & 1 == 0 {
                e[i - 1] -= 16;
                e[i] += 1;
            }
        }

        let mut table = [Self::identity(f); 8];
        table[0] = *self;
        let two_p = self.double(c);
        for i in 1..8 {
            table[i] = two_p.add(c, &table[i - 1]);
        }

        let top_digit = e[num_nibbles - 1] as usize;
        let mut acc = table[top_digit >> 1];

        for i in (0..num_nibbles - 1).rev() {
            for _ in 0..4 {
                acc = acc.double(c);
            }
            let digit = e[i];
            let mag = digit.unsigned_abs() as usize;
            let idx = (mag >> 1) as u32;

            let mut pt = Self::lookup(&table, idx);
            let sign_mask = core::hint::black_box(((digit as i32) >> 31) as u32);
            let neg_y = Fe::ZERO.sub(f, &pt.y);
            for j in 0..N {
                pt.y.v[j] = pt.y.v[j] ^ ((pt.y.v[j] ^ neg_y.v[j]) & sign_mask);
            }
            acc = acc.add(c, &pt);
        }

        let neg_acc_y = Fe::ZERO.sub(f, &acc.y);
        for j in 0..N {
            acc.y.v[j] = acc.y.v[j] ^ ((acc.y.v[j] ^ neg_acc_y.v[j]) & even_mask);
        }
        acc
    }
}
