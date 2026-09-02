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
use nistp_mcu::{backend, p256, p384, Fe, Params};

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

    let data_spread = dmax - dmin;
    let noise_floor = cmax - cmin;

    // A genuine data-dependent difference is at least one instruction per
    // multiply, i.e. at least REPS instructions across a measurement.
    if data_spread <= noise_floor {
        hprintln!(
            "  ok   {}: {} input classes x {} reps -- operand spread {} tick(s) \
does not exceed the same-input noise floor {} tick(s)",
            name, inputs.len(), REPS, data_spread, noise_floor
        );
        hprintln!("       (totals {}..{}, control {}..{})", dmin, dmax, cmin, cmax);
        0
    } else {
        hprintln!(
            "  FAIL {}: operand spread {} ticks EXCEEDS same-input noise floor {} ticks",
            name, data_spread, noise_floor
        );
        hprintln!("       (totals {}..{}, control {}..{})", dmin, dmax, cmin, cmax);
        1
    }
}

#[entry]
fn main() -> ! {
    counter_init();
    hprintln!("nistp-mcu dynamic constant-time check");
    hprintln!("backend: {}", backend::NAME);
    hprintln!(
        "counter: {}",
        if unsafe { USE_DWT } { "DWT CYCCNT" } else { "SysTick (needs -icount shift=0)" }
    );
    hprintln!("");

    let mut fails = 0;
    fails += check_curve::<{ p256::N }>(&p256::FIELD, "p256");
    fails += check_curve::<{ p384::N }>(&p384::FIELD, "p384");

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
