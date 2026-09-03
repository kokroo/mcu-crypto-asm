//! Minimal, fast ablation harness for the open scalar-timing issue.
//!
//! Deliberately small: P-256 only, two scalars, one measurement each. The
//! full `ct` binary grew slow enough to hit its runner timeout, which I twice
//! mistook for a crash.
//!
//! Compares a SPARSE scalar (k=1, nearly every comb digit zero, so the
//! accumulator sits at the identity almost throughout) against a DENSE one
//! (all ones, no zero digits). Those were the extremes of the measured spread.

#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use mcu_crypto_asm::{comb_tables, p256, Point};

use panic_semihosting as _;

const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;

const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
static mut USE_DWT: bool = false;

fn init() {
    unsafe {
        DEMCR.write_volatile(DEMCR.read_volatile() | (1 << 24));
        DWT_CYCCNT.write_volatile(0);
        DWT_CTRL.write_volatile(DWT_CTRL.read_volatile() | 1);
        let a = DWT_CYCCNT.read_volatile();
        let mut acc = 0u32;
        for i in 0..256u32 { acc = acc.wrapping_add(black_box(i)); }
        black_box(acc);
        USE_DWT = DWT_CYCCNT.read_volatile() != a;
        if !USE_DWT {
            // QEMU: no DWT. SysTick under -icount is exact enough that a
            // data-dependent path still shows as a difference.
            SYST_CSR.write_volatile(0);
            SYST_RVR.write_volatile(0x00FF_FFFF);
            SYST_CVR.write_volatile(0);
            SYST_CSR.write_volatile(0b101);
        }
    }
}
#[inline(always)]
fn cyc() -> u32 {
    unsafe {
        if USE_DWT { DWT_CYCCNT.read_volatile() }
        else { 0x00FF_FFFF - (SYST_CVR.read_volatile() & 0x00FF_FFFF) }
    }
}

const N: usize = p256::N;

fn run(mode: u32, k: &[u32; N]) -> u32 {
    let s = cyc();
    black_box(Point::<N>::mul_base_diag(
        &p256::CURVE,
        black_box(k),
        &comb_tables::P256_COMB,
        p256::COMB_D,
        p256::COMB_T,
        mode,
    ));
    cyc().wrapping_sub(s)
}

#[entry]
fn main() -> ! {
    init();
    hprintln!("ablation: which part of the comb depends on the scalar?");
    hprintln!("counter: {}", if unsafe { USE_DWT } { "DWT (hardware)" } else { "SysTick (QEMU, use -icount shift=0)" });
    hprintln!("");

    let mut sparse = [0u32; N];
    sparse[0] = 1; // almost every digit zero
    let dense = [0xFFFF_FFFFu32; N]; // no zero digits

    let names = [
        "0  full comb (baseline)",
        "1  real scan, FIXED addend",
        "2  no scan, fixed addend",
        "3  full comb, digit forced constant",
        "4  real scan+addend, no doubling",
    ];

    for mode in 0..5u32 {
        // Warm, then measure each scalar once; the counter is exact so a
        // single measurement is repeatable to the cycle.
        black_box(run(mode, &dense));
        let a = run(mode, &sparse);
        let b = run(mode, &dense);
        let ctrl = run(mode, &dense);
        let diff = if a > b { a - b } else { b - a };
        let noise = if b > ctrl { b - ctrl } else { ctrl - b };
        hprintln!(
            "  mode {}  sparse {:>9}  dense {:>9}  diff {:>6}  noise {}",
            names[mode as usize], a, b, diff, noise
        );
    }

    hprintln!("");
    hprintln!("diff >> noise  => that mode still depends on the scalar");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
