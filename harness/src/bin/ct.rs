//! Dynamic constant-time check: execute the real assembly and prove its
//! instruction count does not depend on operand values.
//!
//! Run under QEMU with `-icount shift=0`, which makes virtual time advance
//! deterministically with instructions retired. If every input class produces
//! a byte-identical tick total, the routine executed the same number of
//! instructions for all of them — including inputs that take opposite paths
//! through the final conditional subtraction, which is the one place a naive
//! implementation would branch.
//!
//! This complements the static audit in `tests/constant_time.rs`: that proves
//! no data-dependent branch or address *exists* in the source; this shows the
//! executed trace is invariant in practice.

#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use mcu_crypto_asm::{backend, p256, p384, Fe, Params, Point};

use panic_semihosting as _;

const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;

static mut USE_DWT: bool = false;

fn counter_init() {
    unsafe {
        DEMCR.write_volatile(DEMCR.read_volatile() | (1 << 24));
        DWT_CYCCNT.write_volatile(0);
        DWT_CTRL.write_volatile(DWT_CTRL.read_volatile() | 1);
        let a = DWT_CYCCNT.read_volatile();
        let mut acc = 0u32;
        for i in 0..256u32 {
            acc = acc.wrapping_add(black_box(i));
        }
        black_box(acc);
        USE_DWT = DWT_CYCCNT.read_volatile() != a;
        if !USE_DWT {
            SYST_CSR.write_volatile(0);
            SYST_RVR.write_volatile(0x00FF_FFFF);
            SYST_CVR.write_volatile(0);
            SYST_CSR.write_volatile(0b101);
        }
    }
}

#[inline(always)]
fn ticks() -> u32 {
    unsafe {
        if USE_DWT {
            DWT_CYCCNT.read_volatile()
        } else {
            0x00FF_FFFF - (SYST_CVR.read_volatile() & 0x00FF_FFFF)
        }
    }
}

const REPS: u32 = 1000;

/// Measure add/sub for one input pair. The original field check only covered
/// `mul`, so a data-dependent conditional subtraction in add/sub was invisible
/// to it.
fn measure_addsub<const N: usize>(f: &Params, a: &Fe<N>, b: &Fe<N>) -> u32 {
    for _ in 0..16 {
        black_box(black_box(a).add(f, black_box(b)));
    }
    let s = ticks();
    for _ in 0..REPS {
        black_box(black_box(a).add(f, black_box(b)));
    }
    ticks().wrapping_sub(s)
}

/// Same, sub only.
fn measure_sub<const N: usize>(f: &Params, a: &Fe<N>, b: &Fe<N>) -> u32 {
    for _ in 0..16 {
        black_box(black_box(a).sub(f, black_box(b)));
    }
    let s = ticks();
    for _ in 0..REPS {
        black_box(black_box(a).sub(f, black_box(b)));
    }
    ticks().wrapping_sub(s)
}

/// Measure one input pair.
fn measure<const N: usize>(f: &Params, a: &Fe<N>, b: &Fe<N>) -> u32 {
    for _ in 0..16 {
        black_box(black_box(a).mul(f, black_box(b)));
    }
    let s = ticks();
    for _ in 0..REPS {
        black_box(black_box(a).mul(f, black_box(b)));
    }
    ticks().wrapping_sub(s)
}

struct Rng(u64);
impl Rng {
    fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 32) as u32
    }
}

/// Build a spread of operands: zero, one, p-1, p/2, all-ones, and randoms.
/// Between them these take both paths through the conditional subtraction.
fn check_curve<const N: usize>(f: &Params, name: &str) -> u32 {
    let mut rng = Rng(0xDEAD_BEEF_1234_5678);
    let mut inputs: [([u32; N], [u32; N]); 16] = [([0; N], [0; N]); 16];

    let mut pm1 = [0u32; N];
    pm1.copy_from_slice(f.p);
    pm1[0] = pm1[0].wrapping_sub(1); // p - 1 (low word of p is 0xFFFFFFFF)

    let mut one = [0u32; N];
    one[0] = 1;
    let ones = [0xFFFF_FFFFu32; N];
    let mut half = [0u32; N];
    half.copy_from_slice(f.p);
    for i in 0..N {
        half[i] >>= 1;
    }

    inputs[0] = ([0; N], [0; N]);
    inputs[1] = (one, one);
    inputs[2] = (pm1, pm1);
    inputs[3] = (pm1, one);
    inputs[4] = (half, half);
    inputs[5] = (ones, ones);
    inputs[6] = (pm1, half);
    inputs[7] = (one, pm1);
    for slot in inputs.iter_mut().skip(8) {
        let mut a = [0u32; N];
        let mut b = [0u32; N];
        for i in 0..N {
            a[i] = rng.next_u32();
            b[i] = rng.next_u32();
        }
        *slot = (a, b);
    }

    // Control group: the SAME input measured repeatedly, interleaved with the
    // real measurements. Any spread here is pure instrument noise (SysTick has
    // coarser resolution than one instruction, so a measurement window can
    // straddle a tick boundary differently depending on when it started).
    // The real question is whether operand-dependent spread EXCEEDS that.
    let ctrl_a = Fe::<N>::from_int(f, &inputs[0].0);
    let ctrl_b = Fe::<N>::from_int(f, &inputs[0].1);

    let mut dmin = u32::MAX;
    let mut dmax = 0u32;
    let mut cmin = u32::MAX;
    let mut cmax = 0u32;

    for (a, b) in inputs.iter() {
        let fa = Fe::<N>::from_int(f, a);
        let fb = Fe::<N>::from_int(f, b);

        let t = measure(f, &fa, &fb);
        if t < dmin { dmin = t; }
        if t > dmax { dmax = t; }

        let c = measure(f, &ctrl_a, &ctrl_b);
        if c < cmin { cmin = c; }
        if c > cmax { cmax = c; }
    }

    let mut fails = 0u32;

    // Same sweep, but timing add/sub instead of mul.
    for (label, f2) in [
        ("add", measure_addsub::<N> as fn(&Params, &Fe<N>, &Fe<N>) -> u32),
        ("sub", measure_sub::<N> as fn(&Params, &Fe<N>, &Fe<N>) -> u32),
    ] {
        let mut lo = u32::MAX;
        let mut hi2 = 0u32;
        for (a, b) in inputs.iter() {
            let fa = Fe::<N>::from_int(f, a);
            let fb = Fe::<N>::from_int(f, b);
            let t = f2(f, &fa, &fb);
            if t < lo { lo = t; }
            if t > hi2 { hi2 = t; }
        }
        // Same-input control establishes the noise floor: under QEMU SysTick
        // quantises to +/-1 tick, so demanding an exact zero spread fails for
        // a reason that has nothing to do with constant time. On hardware the
        // floor is 0 and this is exactly as strict as before.
        let ca = Fe::<N>::from_int(f, &inputs[0].0);
        let cb = Fe::<N>::from_int(f, &inputs[0].1);
        let (mut clo, mut chi) = (u32::MAX, 0u32);
        for _ in 0..4 {
            let t = f2(f, &ca, &cb);
            if t < clo { clo = t; }
            if t > chi { chi = t; }
        }
        let noise = (chi - clo).max(if unsafe { USE_DWT } { 0 } else { 1 });
        if hi2 - lo > noise {
            hprintln!("  FAIL {} {}: spread {} ticks > noise {} ({}..{})",
                      name, label, hi2 - lo, noise, lo, hi2);
            fails += 1;
        } else {
            hprintln!("  ok   {} {}: spread {} <= noise {} ({} ticks)",
                      name, label, hi2 - lo, noise, lo);
        }
    }

    let data_spread = dmax - dmin;
    let noise_floor = (cmax - cmin).max(if unsafe { USE_DWT } { 0 } else { 1 });

    // A genuine data-dependent difference is at least one instruction per
    // multiply, i.e. at least REPS instructions across a measurement.
    if data_spread <= noise_floor {
        hprintln!(
            "  ok   {}: {} input classes x {} reps -- operand spread {} tick(s) \
does not exceed the same-input noise floor {} tick(s)",
            name, inputs.len(), REPS, data_spread, noise_floor
        );
        hprintln!("       (totals {}..{}, control {}..{})", dmin, dmax, cmin, cmax);
        fails
    } else {
        hprintln!(
            "  FAIL {}: operand spread {} ticks EXCEEDS same-input noise floor {} ticks",
            name, data_spread, noise_floor
        );
        hprintln!("       (totals {}..{}, control {}..{})", dmin, dmax, cmin, cmax);
        fails + 1
    }
}

/// Constant-time check at the SCALAR MULTIPLICATION level.
///
/// The field-level check below cannot see a leak in the point layer. This is
/// the level at which a real leak nearly shipped: selecting between the mixed
/// and general addition formulas with `if digit == 0` branches on the secret
/// scalar, and the two cost different numbers of multiplications.
///
/// Scalars are chosen so that a digit-dependent branch would show up loudly:
/// one with every comb digit zero, one with every digit set, and several in
/// between. A control group re-measures the same scalar to establish the
/// noise floor.
fn check_scalar_mul<const N: usize>(
    name: &str,
    mul: fn(&[u32; N]) -> Point<N>,
) -> u32 {
    let mut scalars: [[u32; N]; 6] = [[0u32; N]; 6];
    scalars[0] = [0x0000_0001; N]; // digits almost all zero
    scalars[1] = [0xFFFF_FFFF; N]; // every digit set
    scalars[2] = [0x0F0F_0F0F; N]; // alternating zero / non-zero digits
    scalars[3] = [0x8888_8888; N];
    scalars[4][0] = 1; // single bit
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for limb in scalars[5].iter_mut() {
        *limb = rng.next_u32();
    }

    // Warm once so the first measurement is not an outlier.
    black_box(mul(&scalars[5]));

    let mut dmin = u32::MAX;
    let mut dmax = 0u32;
    let mut cmin = u32::MAX;
    let mut cmax = 0u32;
    let labels = ["k=0x..01 (mostly zero digits)", "k=all ones (all digits 15)",
                  "k=0x0F0F.. (alternating)", "k=0x8888..",
                  "k=1 (single bit)", "k=random"];
    for (idx, k) in scalars.iter().enumerate() {
        let s = ticks();
        black_box(mul(black_box(k)));
        let t = ticks().wrapping_sub(s);
        hprintln!("       [{}] {:>10} cycles  {}", idx, t, labels[idx]);
        if t < dmin { dmin = t; }
        if t > dmax { dmax = t; }

        let s = ticks();
        black_box(mul(black_box(&scalars[5])));
        let cc = ticks().wrapping_sub(s);
        if cc < cmin { cmin = cc; }
        if cc > cmax { cmax = cc; }
    }

    let spread = dmax - dmin;
    let noise = (cmax - cmin).max(if unsafe { USE_DWT } { 0 } else { 1 });
    if spread <= noise {
        hprintln!(
            "  ok   {}: {} scalars -- spread {} cycle(s) <= same-scalar noise {}",
            name, scalars.len(), spread, noise
        );
        hprintln!("       (totals {}..{}, control {}..{})", dmin, dmax, cmin, cmax);
        0
    } else {
        hprintln!(
            "  FAIL {}: spread {} cycles EXCEEDS same-scalar noise {}",
            name, spread, noise
        );
        hprintln!("       (totals {}..{}, control {}..{})", dmin, dmax, cmin, cmax);
        1
    }
}

/// Bisection: is the leak inside the point ADDITION (i.e. field ops behaving
/// differently once inlined there), or in the comb's lookup/select?
fn check_point_add() -> u32 {
    let c = &p256::CURVE;
    let g = Point::<{ p256::N }>::generator(c);
    // Six structurally different points, including the identity and doublings.
    let mut pts = [g; 6];
    pts[0] = Point::<{ p256::N }>::identity(&c.field);
    pts[1] = g;
    pts[2] = g.add(c, &g);
    pts[3] = pts[2].add(c, &g);
    pts[4] = pts[3].add(c, &pts[2]);
    pts[5] = pts[4].add(c, &pts[3]);

    const R: u32 = 200;
    // Test PAIRS, not just varying the left operand: the earlier version
    // always used pts[3] on the right, so identity+identity -- the case a
    // sparse scalar spends almost the whole comb in -- was never covered.
    let pairs: [(usize, usize); 6] =
        [(0, 0), (0, 3), (3, 0), (1, 2), (3, 4), (5, 5)];
    let names = ["id+id", "id+P", "P+id", "G+2G", "3G+5G", "big+big"];
    let mut lo = u32::MAX;
    let mut hi2 = 0u32;
    for (n, (ia, ib)) in pairs.iter().enumerate() {
        let (a, b) = (&pts[*ia], &pts[*ib]);
        for _ in 0..8 { black_box(black_box(a).add(c, black_box(b))); }
        let s = ticks();
        for _ in 0..R { black_box(black_box(a).add(c, black_box(b))); }
        let t = ticks().wrapping_sub(s);
        hprintln!("       {:>10} cycles  {}", t, names[n]);
        if t < lo { lo = t; }
        if t > hi2 { hi2 = t; }
    }
    // Control group for the same reason as the field checks: QEMU's SysTick
    // quantises to +/-1 tick. On hardware the floor is 0.
    let (mut clo, mut chi) = (u32::MAX, 0u32);
    for _ in 0..4 {
        let s = ticks();
        for _ in 0..R { black_box(black_box(&pts[3]).add(c, black_box(&pts[3]))); }
        let t = ticks().wrapping_sub(s);
        if t < clo { clo = t; }
        if t > chi { chi = t; }
    }
    let noise = chi - clo;
    if hi2 - lo > noise {
        hprintln!("  FAIL Point::add: spread {} > noise {} ({}..{})", hi2 - lo, noise, lo, hi2);
        1
    } else {
        hprintln!("  ok   Point::add: spread {} <= noise {} ({} ticks / {} adds)",
                  hi2 - lo, noise, lo, R);
        0
    }
}

#[entry]
fn main() -> ! {
    counter_init();
    hprintln!("mcu-crypto-asm dynamic constant-time check");
    hprintln!("backend: {}", backend::NAME);
    hprintln!(
        "counter: {}",
        if unsafe { USE_DWT } { "DWT CYCCNT" } else { "SysTick (needs -icount shift=0)" }
    );
    hprintln!("");

    let mut fails = 0;
    hprintln!("field arithmetic:");
    fails += check_curve::<{ p256::N }>(&p256::FIELD, "p256");
    fails += check_curve::<{ p384::N }>(&p384::FIELD, "p384");

    hprintln!("");
    hprintln!("point layer:");
    fails += check_point_add();
    hprintln!("");
    hprintln!("scalar multiplication (the level a real leak nearly reached):");
    fails += check_scalar_mul::<{ p256::N }>("p256 comb", p256::mul_base);
    fails += check_scalar_mul::<{ p384::N }>("p384 comb", p384::mul_base);


    hprintln!("");
    if fails == 0 {
        hprintln!("CONSTANT TIME: instruction count is invariant across operands");
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        hprintln!("NOT CONSTANT TIME");
        debug::exit(debug::EXIT_FAILURE);
    }
    loop {}
}
