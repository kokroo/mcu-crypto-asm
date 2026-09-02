//! Cycle-count benchmark: this crate's assembly vs `fiat-crypto`.
//!
//! `fiat-crypto`'s `p256_32` / `p384_32` are the formally-verified generated
//! Montgomery field arithmetic that the RustCrypto `p256` / `p384` crates
//! vendor internally, so `fiat_p256_mul` is the *same operation* as our
//! `mul_mont` — a genuine head-to-head rather than a comparison across
//! different abstraction levels.
//!
//! Measured with DWT CYCCNT. On real hardware that is an exact cycle count.
//! Under QEMU it is only meaningful if the DWT is emulated — the harness
//! checks and says so rather than printing a fabricated number.

#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use nistp_mcu::{backend, p256, p384};

use panic_semihosting as _;

const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;

const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;

/// Which counter is providing the numbers.
///
/// DWT CYCCNT is an exact cycle count and is what real hardware uses. QEMU's
/// mps2 models do not implement the DWT, so we fall back to SysTick, which
/// QEMU does emulate; run QEMU with `-icount shift=0` and SysTick advances
/// deterministically with instructions executed. Absolute values are then not
/// hardware cycles, but *ratios between implementations are exact*, which is
/// what a comparison needs.
#[derive(PartialEq, Clone, Copy)]
enum Counter {
    Dwt,
    SysTick,
    None,
}

static mut COUNTER: Counter = Counter::None;

fn counter_init() -> Counter {
    unsafe {
        // Try DWT first.
        DEMCR.write_volatile(DEMCR.read_volatile() | (1 << 24)); // TRCENA
        DWT_CYCCNT.write_volatile(0);
        DWT_CTRL.write_volatile(DWT_CTRL.read_volatile() | 1); // CYCCNTENA
        if ticking(|| DWT_CYCCNT.read_volatile()) {
            COUNTER = Counter::Dwt;
            return Counter::Dwt;
        }
        // Fall back to SysTick: free-running, processor clock, 24-bit down-counter.
        SYST_CSR.write_volatile(0);
        SYST_RVR.write_volatile(0x00FF_FFFF);
        SYST_CVR.write_volatile(0);
        SYST_CSR.write_volatile(0b101); // ENABLE | CLKSOURCE=processor
        if ticking(|| SYST_CVR.read_volatile()) {
            COUNTER = Counter::SysTick;
            return Counter::SysTick;
        }
        COUNTER = Counter::None;
        Counter::None
    }
}

/// Does `read` change across a chunk of work the optimiser cannot delete?
fn ticking(read: impl Fn() -> u32) -> bool {
    let a = read();
    let mut acc = 0u32;
    for i in 0..256u32 {
        acc = acc.wrapping_add(black_box(i).wrapping_mul(3));
    }
    black_box(acc);
    read() != a
}

/// Monotonically increasing tick count, whichever counter is live.
#[inline(always)]
fn cyccnt() -> u32 {
    unsafe {
        match COUNTER {
            Counter::Dwt => DWT_CYCCNT.read_volatile(),
            // SysTick counts DOWN; negate so the caller can always subtract.
            Counter::SysTick => 0x00FF_FFFF - (SYST_CVR.read_volatile() & 0x00FF_FFFF),
            Counter::None => 0,
        }
    }
}

/// Large enough that per-op quantisation is negligible, small enough that the
/// 24-bit SysTick cannot wrap inside one measurement.
const ITERS: u32 = 1000;

/// Returns TOTAL ticks, not ticks/op: ratios are computed from totals so that
/// integer division never rounds away the difference being measured.
macro_rules! bench {
    ($label:expr, $iters:expr, $body:expr) => {{
        // Warm caches / branch predictors so iteration one is not an outlier.
        for _ in 0..16 {
            $body
        }
        let start = cyccnt();
        for _ in 0..$iters {
            $body
        }
        let total = cyccnt().wrapping_sub(start);
        // Fixed-point ticks/op to two decimals, no floating point.
        let per100 = (total as u64 * 100) / $iters as u64;
        hprintln!(
            "  {:<28} {:>7}.{:02} ticks/op  ({} total)",
            $label, per100 / 100, per100 % 100, total
        );
        total
    }};
}

/// The counter is only trustworthy if ticks scale linearly with work done.
/// Measure the same operation at 1x and 4x and check the ratio is ~4x; if it
/// is not, the timer is not measuring what we think and the numbers are void.
fn linearity_ok<F: Fn()>(op: F) -> (bool, u32, u32) {
    for _ in 0..16 {
        op();
    }
    let s1 = cyccnt();
    for _ in 0..250 {
        op();
    }
    let t1 = cyccnt().wrapping_sub(s1);
    let s4 = cyccnt();
    for _ in 0..1000 {
        op();
    }
    let t4 = cyccnt().wrapping_sub(s4);
    // Expect t4 ~= 4*t1; allow 10% slack.
    let expect = t1.wrapping_mul(4);
    let lo = expect - expect / 10;
    let hi = expect + expect / 10;
    (t4 >= lo && t4 <= hi && t1 > 0, t1, t4)
}

#[entry]
fn main() -> ! {
    let counter = counter_init();
    hprintln!("nistp-mcu field-multiply benchmark");
    hprintln!("backend: {}", backend::NAME);
    match counter {
        Counter::Dwt => hprintln!("counter: DWT CYCCNT (exact hardware cycles)"),
        Counter::SysTick => {
            hprintln!("counter: SysTick (QEMU; run with -icount shift=0)");
            hprintln!("         absolute values are not hardware cycles - RATIOS are exact")
        }
        Counter::None => {
            hprintln!("no usable cycle counter on this machine");
            debug::exit(debug::EXIT_FAILURE);
            loop {}
        }
    }
    hprintln!("iterations per measurement: {}", ITERS);

    // --- validate the instrument before trusting any number it produces ---
    let probe_a = p256::from_int(&[7, 0, 0, 0, 0, 0, 0, 0]);
    let probe_b = p256::from_int(&[11, 0, 0, 0, 0, 0, 0, 0]);
    let (ok, t1, t4) = linearity_ok(|| {
        black_box(black_box(&probe_a).mul(&p256::FIELD, black_box(&probe_b)));
    });
    if !ok {
        hprintln!("");
        hprintln!("COUNTER FAILED LINEARITY CHECK: 250 ops -> {} ticks, 1000 ops -> {} ticks", t1, t4);
        hprintln!("(expected ~4x). Timer resolution is too coarse or nonlinear here;");
        hprintln!("refusing to report numbers. Run on real hardware with DWT CYCCNT.");
        debug::exit(debug::EXIT_FAILURE);
        loop {}
    }
    hprintln!("linearity check: 250 ops={} ticks, 1000 ops={} ticks (~4x) OK", t1, t4);
    hprintln!("");

    // --- P-256 ---
    hprintln!("P-256 modular multiplication:");
    let a256 = p256::from_int(&[
        0x1234_5678, 0x9abc_def0, 0x0f1e_2d3c, 0x4b5a_6978, 0xdead_beef, 0xcafe_babe,
        0x0badc0de, 0x1337_4269,
    ]);
    let b256 = p256::from_int(&[
        0xfedc_ba98, 0x7654_3210, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00,
        0xa5a5_5a5a, 0x0f0f_f0f0,
    ]);
    let ours256 = bench!("nistp-mcu (asm)", ITERS, {
        black_box(black_box(&a256).mul(&p256::FIELD, black_box(&b256)));
    });

    use fiat_crypto::p256_32::{fiat_p256_montgomery_domain_field_element as Fp256, fiat_p256_mul};
    let fa = Fp256(*a256.as_mont_limbs());
    let fb = Fp256(*b256.as_mont_limbs());
    let mut fo = Fp256([0; 8]);
    let fiat256 = bench!("fiat-crypto p256_32", ITERS, {
        fiat_p256_mul(black_box(&mut fo), black_box(&fa), black_box(&fb));
    });

    // --- P-384 ---
    hprintln!("P-384 modular multiplication:");
    let a384 = p384::from_int(&[
        0x1234_5678, 0x9abc_def0, 0x0f1e_2d3c, 0x4b5a_6978, 0xdead_beef, 0xcafe_babe,
        0x0badc0de, 0x1337_4269, 0x2468_ace0, 0x1357_bdf9, 0xfeed_face, 0x0123_4567,
    ]);
    let b384 = p384::from_int(&[
        0xfedc_ba98, 0x7654_3210, 0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0xddee_ff00,
        0xa5a5_5a5a, 0x0f0f_f0f0, 0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888,
    ]);
    let ours384 = bench!("nistp-mcu (asm)", ITERS, {
        black_box(black_box(&a384).mul(&p384::FIELD, black_box(&b384)));
    });

    use fiat_crypto::p384_32::{fiat_p384_montgomery_domain_field_element as Fp384, fiat_p384_mul};
    let ga = Fp384(*a384.as_mont_limbs());
    let gb = Fp384(*b384.as_mont_limbs());
    let mut go = Fp384([0; 12]);
    let fiat384 = bench!("fiat-crypto p384_32", ITERS, {
        fiat_p384_mul(black_box(&mut go), black_box(&ga), black_box(&gb));
    });

    hprintln!("");
    hprintln!("speedup vs fiat-crypto:");
    report("P-256", fiat256, ours256);
    report("P-384", fiat384, ours384);

    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

/// Print a x.xx ratio without pulling in floating point.
fn report(name: &str, baseline: u32, ours: u32) {
    if ours == 0 {
        hprintln!("  {}: measurement too small", name);
        return;
    }
    let hundredths = (baseline as u64 * 100) / ours as u64;
    hprintln!(
        "  {}: {}.{:02}x faster ({} -> {} ticks)",
        name,
        hundredths / 100,
        hundredths % 100,
        baseline,
        ours
    );
}
