//! Resumable scalar multiplication, for cooperative schedulers.
//!
//! # Why this exists
//!
//! A scalar multiplication is not a small operation. Measured on an nRF52840
//! at 64 MHz: **100 ms for P-256 and 284 ms for P-384**. Running that as one
//! blocking call inside an embassy executor stalls every other task for that
//! whole period — long enough to drop BLE connection events and miss packet
//! deadlines.
//!
//! On a single core with no ECC accelerator, `async` cannot make the work
//! happen elsewhere; the CPU still has to do it. What it *can* do is let the
//! work be **interleaved**: [`ScalarMul`] performs a bounded number of point
//! operations per call and returns, so the executor can run everything else in
//! between.
//!
//! One point operation is the atom, costing roughly **190 µs (P-256)** or
//! **370 µs (P-384)** at 64 MHz. A budget of 1 therefore caps the blocking
//! time at about that, at the price of more scheduler round-trips.
//!
//! # Constant time
//!
//! Chunking does not weaken the timing guarantee: the total number of point
//! operations is fixed by the curve, never by the scalar
//! ([`ScalarMul::total_ops`]), the window digits are consumed in a fixed
//! order, and the table lookup is a branchless masked scan. Two different
//! scalars produce the same number of steps and the same work per step.
//!
//! # Memory
//!
//! The state holds a 16-entry precomputed table: ~1.6 KiB for P-256 and
//! ~2.6 KiB for P-384. That lives in the future / caller's state, so put it
//! somewhere deliberate rather than deep on a small task stack.

use crate::{CurveParams, Point};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// A scalar multiplication in progress.
pub struct ScalarMul<const N: usize> {
    table: [Point<N>; 16],
    acc: Point<N>,
    base: Point<N>,
    k: [u32; N],
    /// Next table entry to precompute; 16 once the table is complete.
    ti: usize,
    /// Nibbles left to process, counting down. 0 means finished.
    nib: usize,
    /// Position within a window: 0..3 are doublings, 4 is the addition.
    sub: u8,
}

impl<const N: usize> ScalarMul<N> {
    /// Begin computing `k * point`.
    pub fn new(c: &CurveParams, point: &Point<N>, k: &[u32; N]) -> Self {
        let mut table = [Point::identity(&c.field); 16];
        table[1] = *point;
        Self {
            table,
            acc: Point::identity(&c.field),
            base: *point,
            k: *k,
            ti: 2,
            nib: N * 8,
            sub: 0,
        }
    }

    /// Total point operations for this curve: 14 to finish the table, then
    /// four doublings and one addition per nibble.
    ///
    /// Fixed for the curve and **independent of the scalar** — which is what
    /// makes the chunked form as constant-time as the blocking one.
    pub const fn total_ops() -> u32 {
        14 + (N as u32) * 8 * 5
    }

    /// Perform at most `budget` point operations.
    ///
    /// Returns `Some(result)` once finished, `None` if there is more to do.
    /// `budget` is clamped to at least 1 so a zero budget cannot spin forever.
    pub fn step(&mut self, c: &CurveParams, budget: u32) -> Option<Point<N>> {
        let budget = budget.max(1);
        let mut done = 0;
        while done < budget {
            if self.ti < 16 {
                self.table[self.ti] = self.table[self.ti - 1].add(c, &self.base);
                self.ti += 1;
            } else if self.nib > 0 {
                if self.sub < 4 {
                    self.acc = self.acc.add(c, &self.acc);
                    self.sub += 1;
                } else {
                    let idx = self.nib - 1;
                    let digit = (self.k[idx / 8] >> ((idx % 8) * 4)) & 0xF;
                    let sel = Point::lookup(&self.table, digit);
                    self.acc = self.acc.add(c, &sel);
                    self.sub = 0;
                    self.nib -= 1;
                }
            } else {
                return Some(self.acc);
            }
            done += 1;
        }
        if self.ti >= 16 && self.nib == 0 {
            Some(self.acc)
        } else {
            None
        }
    }

    /// Run to completion without yielding. Equivalent to [`Point::mul_scalar`].
    pub fn finish(mut self, c: &CurveParams) -> Point<N> {
        loop {
            if let Some(p) = self.step(c, u32::MAX) {
                return p;
            }
        }
    }
}

/// Yield once to the executor.
///
/// Written out rather than pulled from a dependency: it is six lines, and this
/// crate should not force a particular async ecosystem on its users. Works
/// with any executor, embassy included.
struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// `k * point`, yielding to the executor every `budget` point operations.
///
/// This does not run the arithmetic anywhere other than the calling CPU — it
/// simply refuses to hold it for more than `budget` point operations at a
/// time. Pick `budget` from the longest stall the rest of the system can
/// absorb: 1 gives roughly 190 µs (P-256) or 370 µs (P-384) at 64 MHz.
pub async fn mul_scalar_yielding<const N: usize>(
    c: &CurveParams,
    point: &Point<N>,
    k: &[u32; N],
    budget: u32,
) -> Point<N> {
    let mut state = ScalarMul::new(c, point, k);
    loop {
        if let Some(result) = state.step(c, budget) {
            return result;
        }
        YieldNow(false).await;
    }
}

/// A fixed-base (`k * G`) comb multiplication in progress.
///
/// Same contract as [`ScalarMul`], but for the compile-time comb table: one
/// doubling and one addition per iteration, `D` iterations, no precompute
/// phase. Roughly 2.6x less work than the variable-base path.
pub struct CombMul<const N: usize> {
    acc: Point<N>,
    k: [u32; N],
    table: &'static [([u32; N], [u32; N])],
    d: usize,
    ntables: usize,
    /// Iterations remaining, counting down. 0 means finished.
    i: usize,
}

impl<const N: usize> CombMul<N> {
    /// Begin computing `k * G` with the given comb table.
    pub fn new(
        k: &[u32; N],
        table: &'static [([u32; N], [u32; N])],
        d: usize,
        ntables: usize,
    ) -> Self {
        Self {
            acc: Point {
                x: crate::Fe::ZERO,
                y: crate::Fe::ZERO,
                z: crate::Fe::ZERO,
            },
            k: *k,
            table,
            d,
            ntables,
            i: d,
        }
    }

    /// Total point operations: one doubling plus `ntables` additions per
    /// iteration. Independent of the scalar.
    pub fn total_ops(d: usize, ntables: usize) -> u32 {
        (d as u32) * (1 + ntables as u32)
    }

    /// Perform at most `budget` comb iterations (each a doubling plus an
    /// addition). Returns `Some(result)` once finished.
    pub fn step(&mut self, c: &CurveParams, budget: u32) -> Option<Point<N>> {
        if self.i == self.d {
            self.acc = Point::identity(&c.field); // first call: real identity
        }
        let budget = budget.max(1);
        for _ in 0..budget {
            if self.i == 0 {
                return Some(self.acc);
            }
            self.i -= 1;
            self.acc =
                Point::comb_iteration(c, &self.acc, &self.k, self.table, self.d, self.ntables, self.i);
        }
        if self.i == 0 {
            Some(self.acc)
        } else {
            None
        }
    }
}

/// `k * G` via the comb, yielding to the executor every `budget` iterations.
pub async fn mul_base_yielding<const N: usize>(
    c: &CurveParams,
    k: &[u32; N],
    table: &'static [([u32; N], [u32; N])],
    d: usize,
    ntables: usize,
    budget: u32,
) -> Point<N> {
    let mut state = CombMul::new(k, table, d, ntables);
    loop {
        if let Some(result) = state.step(c, budget) {
            return result;
        }
        YieldNow(false).await;
    }
}
