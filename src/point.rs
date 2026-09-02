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

    /// Branchless select: returns `b` when `choice == 1`, `a` when `choice == 0`.
    ///
    /// `choice` must be exactly 0 or 1.
    #[inline]
    fn select(choice: u32, a: &Self, b: &Self) -> Self {
        let mask = choice.wrapping_neg(); // 0 or 0xFFFFFFFF
        let mut out = *a;
        for i in 0..N {
            out.x.v[i] = (a.x.v[i] & !mask) | (b.x.v[i] & mask);
            out.y.v[i] = (a.y.v[i] & !mask) | (b.y.v[i] & mask);
            out.z.v[i] = (a.z.v[i] & !mask) | (b.z.v[i] & mask);
        }
        out
    }

    /// `k * self`, constant time in `k`.
    ///
    /// Double-and-add-always, most-significant bit first: every bit performs
    /// exactly one doubling and one addition, and a branchless select decides
    /// whether the addition is kept. Combined with complete formulas there are
    /// no exceptional cases, so the instruction trace is identical for every
    /// scalar. The loop trip count is the bit length of the curve order, which
    /// is public.
    pub fn mul_scalar(&self, c: &CurveParams, k: &[u32]) -> Self {
        debug_assert_eq!(k.len(), N);
        let mut acc = Self::identity(&c.field);
        for i in (0..N).rev() {
            for bit in (0..32).rev() {
                acc = acc.add(c, &acc); // doubling, via the complete formula
                let sum = acc.add(c, self);
                let choice = (k[i] >> bit) & 1;
                acc = Self::select(choice, &acc, &sum);
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
