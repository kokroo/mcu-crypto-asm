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
use mcu_crypto_asm::{backend, p256, p384, Point};

use panic_semihosting as _;

use fiat_crypto::p256_32::{
    fiat_p256_add, fiat_p256_montgomery_domain_field_element as Fp256, fiat_p256_mul,
    fiat_p256_square, fiat_p256_sub,
};
use fiat_crypto::p384_32::{
    fiat_p384_add, fiat_p384_montgomery_domain_field_element as Fp384, fiat_p384_mul,
    fiat_p384_square, fiat_p384_sub,
};

// Emill's hand-optimised P-256 Montgomery multiply, wrapped in AAPCS by
// `third_party/emill/shim.S`. This is the reference implementation for P-256
// on Cortex-M4 — the thing to actually beat.
#[cfg(emill)]
extern "C" {
    fn emill_p256_mulmod(out: *mut u32, a: *const u32, b: *const u32);
}

#[cfg(emill)]
static mut EMILL_TICKS: u32 = 0;

const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;
const DWT_LAR: *mut u32 = 0xE000_1FB0 as *mut u32;

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
        // ARMv8-M (Cortex-M33 / STM32H5) requires software unlock via DWT_LAR before
        // writing to DWT registers. On ARMv7-M (Cortex-M4) this write is harmless.
        DWT_LAR.write_volatile(0xC5AC_CE55);
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
    hprintln!("mcu-crypto-asm field-multiply benchmark");
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
    let mut ours_out256 = [0u32; 8];
    let ours256 = bench!("mcu-crypto-asm (asm)", ITERS, {
        p256::mul_mont(
            black_box(&mut ours_out256),
            black_box(a256.as_mont_limbs()),
            black_box(b256.as_mont_limbs()),
        );
    });

    let fa = Fp256(*a256.as_mont_limbs());
    let fb = Fp256(*b256.as_mont_limbs());
    let mut fo = Fp256([0; 8]);
    let fiat256 = bench!("fiat-crypto p256_32 mul", ITERS, {
        fiat_p256_mul(black_box(&mut fo), black_box(&fa), black_box(&fb));
    });

    let mut port_out256 = [0u32; 8];
    let port256 = bench!("portable p256 mul", ITERS, {
        mcu_crypto_asm::backend::portable::mul_mont(
            black_box(a256.as_mont_limbs()),
            black_box(b256.as_mont_limbs()),
            black_box(p256::FIELD.p),
            p256::FIELD.n0inv,
            black_box(&mut port_out256),
        );
    });

    // Emill: the hand-optimised P-256 reference.
    #[cfg(emill)]
    {
        let mut eo = [0u32; 8];
        // Cross-check first: an independent implementation agreeing on the
        // result validates both, and catches any Montgomery-convention
        // mismatch that would make the timing comparison meaningless.
        unsafe {
            emill_p256_mulmod(
                eo.as_mut_ptr(),
                a256.as_mont_limbs().as_ptr(),
                b256.as_mont_limbs().as_ptr(),
            );
        }
        let ours = a256.mul(&p256::FIELD, &b256);
        if &eo == ours.as_mont_limbs() {
            let emill = bench!("Emill P256_mulmod (asm)", ITERS, {
                unsafe {
                    emill_p256_mulmod(
                        black_box(eo.as_mut_ptr()),
                        black_box(a256.as_mont_limbs().as_ptr()),
                        black_box(b256.as_mont_limbs().as_ptr()),
                    );
                }
            });
            unsafe { EMILL_TICKS = emill };
        } else {
            hprintln!("  Emill P256_mulmod: RESULT MISMATCH - not comparable");
            hprintln!("    ours  {:08x?}", ours.as_mont_limbs());
            hprintln!("    emill {:08x?}", eo);
        }
    }

    hprintln!("field add/sub/sqr:");
    let mut ours_sqr_out256 = [0u32; 8];
    let ours256_sqr = bench!("P-256 sqr_mont (asm)", ITERS, {
        p256::sqr_mont(
            black_box(&mut ours_sqr_out256),
            black_box(a256.as_mont_limbs()),
        );
    });
    let fiat256_sqr = bench!("P-256 sqr (fiat-crypto)", ITERS, {
        fiat_p256_square(black_box(&mut fo), black_box(&fa));
    });
    let mut ours_add_out256 = [0u32; 8];
    let ours256_add = bench!("P-256 add_mod (asm)", ITERS, {
        p256::add_mod(
            black_box(&mut ours_add_out256),
            black_box(a256.as_mont_limbs()),
            black_box(b256.as_mont_limbs()),
        );
    });
    let fiat256_add = bench!("P-256 add (fiat-crypto)", ITERS, {
        fiat_p256_add(black_box(&mut fo), black_box(&fa), black_box(&fb));
    });
    let mut ours_sub_out256 = [0u32; 8];
    let ours256_sub = bench!("P-256 sub_mod (asm)", ITERS, {
        p256::sub_mod(
            black_box(&mut ours_sub_out256),
            black_box(a256.as_mont_limbs()),
            black_box(b256.as_mont_limbs()),
        );
    });
    let fiat256_sub = bench!("P-256 sub (fiat-crypto)", ITERS, {
        fiat_p256_sub(black_box(&mut fo), black_box(&fa), black_box(&fb));
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
    let mut ours_out384 = [0u32; 12];
    let ours384 = bench!("mcu-crypto-asm (asm)", ITERS, {
        p384::mul_mont(
            black_box(&mut ours_out384),
            black_box(a384.as_mont_limbs()),
            black_box(b384.as_mont_limbs()),
        );
    });

    let ga = Fp384(*a384.as_mont_limbs());
    let gb = Fp384(*b384.as_mont_limbs());
    let mut go = Fp384([0; 12]);
    let fiat384 = bench!("fiat-crypto p384_32 mul", ITERS, {
        fiat_p384_mul(black_box(&mut go), black_box(&ga), black_box(&gb));
    });

    let mut port_out384 = [0u32; 12];
    let port384 = bench!("portable p384 mul", ITERS, {
        mcu_crypto_asm::backend::portable::mul_mont(
            black_box(a384.as_mont_limbs()),
            black_box(b384.as_mont_limbs()),
            black_box(p384::FIELD.p),
            p384::FIELD.n0inv,
            black_box(&mut port_out384),
        );
    });

    let mut ours_sqr_out384 = [0u32; 12];
    let ours384_sqr = bench!("P-384 sqr_mont (asm)", ITERS, {
        p384::sqr_mont(
            black_box(&mut ours_sqr_out384),
            black_box(a384.as_mont_limbs()),
        );
    });
    let fiat384_sqr = bench!("P-384 sqr (fiat-crypto)", ITERS, {
        fiat_p384_square(black_box(&mut go), black_box(&ga));
    });
    let mut ours_add_out384 = [0u32; 12];
    let ours384_add = bench!("P-384 add_mod (asm)", ITERS, {
        p384::add_mod(
            black_box(&mut ours_add_out384),
            black_box(a384.as_mont_limbs()),
            black_box(b384.as_mont_limbs()),
        );
    });
    let fiat384_add = bench!("P-384 add (fiat-crypto)", ITERS, {
        fiat_p384_add(black_box(&mut go), black_box(&ga), black_box(&gb));
    });
    let mut ours_sub_out384 = [0u32; 12];
    let ours384_sub = bench!("P-384 sub_mod (asm)", ITERS, {
        p384::sub_mod(
            black_box(&mut ours_sub_out384),
            black_box(a384.as_mont_limbs()),
            black_box(b384.as_mont_limbs()),
        );
    });
    let fiat384_sub = bench!("P-384 sub (fiat-crypto)", ITERS, {
        fiat_p384_sub(black_box(&mut go), black_box(&ga), black_box(&gb));
    });

    // --- scalar multiplication: what actually blocks an executor ---
    hprintln!("");
    hprintln!("scalar multiplication (k*G), the operation that blocks:");
    {
        let k256 = [0x9e37_79b9u32, 0x7f4a_7c15, 0x1234_5678, 0x9abc_def0,
                    0x0f1e_2d3c, 0x4b5a_6978, 0xdead_beef, 0x0badc0de];
        let g = Point::<{ p256::N }>::generator(&p256::CURVE);
        let s0 = cyccnt();
        black_box(black_box(&g).mul_scalar(&p256::CURVE, black_box(&k256)));
        let c = cyccnt().wrapping_sub(s0);
        hprintln!("  P-256 k*G   {:>10} cycles  ({} ms @ 64 MHz)", c, c / 64_000);

        let k384 = [0x9e37_79b9u32, 0x7f4a_7c15, 0x1234_5678, 0x9abc_def0,
                    0x0f1e_2d3c, 0x4b5a_6978, 0xdead_beef, 0x0badc0de,
                    0x2468_ace0, 0x1357_bdf9, 0xfeed_face, 0x0123_4567];
        let g4 = Point::<{ p384::N }>::generator(&p384::CURVE);
        let s0 = cyccnt();
        black_box(black_box(&g4).mul_scalar(&p384::CURVE, black_box(&k384)));
        let c = cyccnt().wrapping_sub(s0);
        hprintln!("  P-384 k*G   {:>10} cycles  ({} ms @ 64 MHz)", c, c / 64_000);
    }

    // --- worst-case blocking per chunk, which is what an executor feels ---
    hprintln!("");
    hprintln!("k*G via fixed-base comb (derive_public_key path):");
    {
        let k256 = [0x9e37_79b9u32, 0x7f4a_7c15, 0x1234_5678, 0x9abc_def0,
                    0x0f1e_2d3c, 0x4b5a_6978, 0xdead_beef, 0x0badc0de];
        let s0 = cyccnt();
        black_box(p256::mul_base(black_box(&k256)));
        let c = cyccnt().wrapping_sub(s0);
        hprintln!("  P-256 comb  {:>10} cycles  ({} ms @ 64 MHz)", c, c / 64_000);

        let k384 = [0x9e37_79b9u32, 0x7f4a_7c15, 0x1234_5678, 0x9abc_def0,
                    0x0f1e_2d3c, 0x4b5a_6978, 0xdead_beef, 0x0badc0de,
                    0x2468_ace0, 0x1357_bdf9, 0xfeed_face, 0x0123_4567];
        let s0 = cyccnt();
        black_box(p384::mul_base(black_box(&k384)));
        let c = cyccnt().wrapping_sub(s0);
        hprintln!("  P-384 comb  {:>10} cycles  ({} ms @ 64 MHz)", c, c / 64_000);
    }

    // The real end-to-end operation: comb + the final inversion in to_affine.
    hprintln!("");
    hprintln!("derive_public_key (comb + to_affine inversion):");
    {
        let mut sk = [0u8; 48];
        sk[0] = 0x11;
        sk[31] = 0x07;
        let mut pk = [0u8; 97];
        let s0 = cyccnt();
        p256::derive_public_key(black_box(&sk[..32]), black_box(&mut pk[..65])).unwrap();
        let c = cyccnt().wrapping_sub(s0);
        hprintln!("  P-256  {:>10} cycles  ({} ms @ 64 MHz)", c, c / 64_000);

        sk[47] = 0x07;
        let s0 = cyccnt();
        p384::derive_public_key(black_box(&sk[..48]), black_box(&mut pk[..97])).unwrap();
        let c = cyccnt().wrapping_sub(s0);
        hprintln!("  P-384  {:>10} cycles  ({} ms @ 64 MHz)", c, c / 64_000);
    }

    hprintln!("");
    hprintln!("ECDSA sign & verify:");
    {
        let d256 = [0x11u8; 32];
        let mut pk256 = [0u8; 65];
        p256::derive_public_key(&d256, &mut pk256).unwrap();
        let msg = [0x42u8; 32];
        let k = [0x77u8; 32];
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];

        let s0 = cyccnt();
        p256::ecdsa::sign(&d256, &msg, &k, &mut r, &mut s).unwrap();
        let c_sign = cyccnt().wrapping_sub(s0);

        let s0 = cyccnt();
        p256::ecdsa::verify(&pk256, &msg, &r, &s).unwrap();
        let c_ver = cyccnt().wrapping_sub(s0);

        hprintln!("  P-256 sign    {:>10} cycles  ({} ms @ 64 MHz)", c_sign, c_sign / 64_000);
        hprintln!("  P-256 verify  {:>10} cycles  ({} ms @ 64 MHz)", c_ver, c_ver / 64_000);

        let d384 = [0x11u8; 48];
        let mut pk384 = [0u8; 97];
        p384::derive_public_key(&d384, &mut pk384).unwrap();
        let msg384 = [0x42u8; 48];
        let k384 = [0x77u8; 48];
        let mut r384 = [0u8; 48];
        let mut s384 = [0u8; 48];

        let s0 = cyccnt();
        p384::ecdsa::sign(&d384, &msg384, &k384, &mut r384, &mut s384).unwrap();
        let c_sign384 = cyccnt().wrapping_sub(s0);

        let s0 = cyccnt();
        p384::ecdsa::verify(&pk384, &msg384, &r384, &s384).unwrap();
        let c_ver384 = cyccnt().wrapping_sub(s0);

        hprintln!("  P-384 sign    {:>10} cycles  ({} ms @ 64 MHz)", c_sign384, c_sign384 / 64_000);
        hprintln!("  P-384 verify  {:>10} cycles  ({} ms @ 64 MHz)", c_ver384, c_ver384 / 64_000);
    }


    hprintln!("");
    hprintln!("Point::add (complete projective addition):");
    let pt_ours256 = {
        let g256 = Point::<{ p256::N }>::generator(&p256::CURVE);
        let g256_2 = g256.add(&p256::CURVE, &g256);
        bench!("P-256 Point::add (asm)", 100, {
            black_box(black_box(&g256).add(&p256::CURVE, black_box(&g256_2)));
        })
    };
    let pt_fiat256 = {
        let g256 = Point::<{ p256::N }>::generator(&p256::CURVE);
        let g256_2 = g256.add(&p256::CURVE, &g256);
        let fa_x = Fp256(*g256.x.as_mont_limbs());
        let fa_y = Fp256(*g256.y.as_mont_limbs());
        let fa_z = Fp256(*g256.z.as_mont_limbs());
        let fb_x = Fp256(*g256_2.x.as_mont_limbs());
        let fb_y = Fp256(*g256_2.y.as_mont_limbs());
        let fb_z = Fp256(*g256_2.z.as_mont_limbs());
        let b256_mont = Fp256(p256::CURVE.b_mont.try_into().unwrap());
        bench!("P-256 Point::add (fiat-crypto)", 100, {
            black_box(point_add_fiat256(
                black_box(&fa_x), black_box(&fa_y), black_box(&fa_z),
                black_box(&fb_x), black_box(&fb_y), black_box(&fb_z),
                black_box(&b256_mont),
            ));
        })
    };

    let pt_ours384 = {
        let g384 = Point::<{ p384::N }>::generator(&p384::CURVE);
        let g384_2 = g384.add(&p384::CURVE, &g384);
        bench!("P-384 Point::add (asm)", 100, {
            black_box(black_box(&g384).add(&p384::CURVE, black_box(&g384_2)));
        })
    };
    let pt_fiat384 = {
        let g384 = Point::<{ p384::N }>::generator(&p384::CURVE);
        let g384_2 = g384.add(&p384::CURVE, &g384);
        let ga_x = Fp384(*g384.x.as_mont_limbs());
        let ga_y = Fp384(*g384.y.as_mont_limbs());
        let ga_z = Fp384(*g384.z.as_mont_limbs());
        let gb_x = Fp384(*g384_2.x.as_mont_limbs());
        let gb_y = Fp384(*g384_2.y.as_mont_limbs());
        let gb_z = Fp384(*g384_2.z.as_mont_limbs());
        let b384_mont = Fp384(p384::CURVE.b_mont.try_into().unwrap());
        bench!("P-384 Point::add (fiat-crypto)", 100, {
            black_box(point_add_fiat384(
                black_box(&ga_x), black_box(&ga_y), black_box(&ga_z),
                black_box(&gb_x), black_box(&gb_y), black_box(&gb_z),
                black_box(&b384_mont),
            ));
        })
    };

    hprintln!("");
    hprintln!("=== SPEEDUP COMPARISON vs FIAT-CRYPTO (RustCrypto backend) ===");
    report("P-256 modular mul", fiat256, ours256);
    report("P-256 modular sqr", fiat256_sqr, ours256_sqr);
    report("P-256 modular add", fiat256_add, ours256_add);
    report("P-256 modular sub", fiat256_sub, ours256_sub);
    report("P-256 Point::add", pt_fiat256, pt_ours256);
    hprintln!("");
    report("P-384 modular mul", fiat384, ours384);
    report("P-384 modular sqr", fiat384_sqr, ours384_sqr);
    report("P-384 modular add", fiat384_add, ours384_add);
    report("P-384 modular sub", fiat384_sub, ours384_sub);
    report("P-384 Point::add", pt_fiat384, pt_ours384);

    hprintln!("");
    hprintln!("=== SPEEDUP COMPARISON vs PORTABLE SOFTWARE (Generic CIOS) ===");
    report("P-256 modular mul vs portable", port256, ours256);
    report("P-384 modular mul vs portable", port384, ours384);

    #[cfg(emill)]
    unsafe {
        let emill_ticks = core::ptr::read_volatile(&raw const EMILL_TICKS);
        if emill_ticks != 0 {
            hprintln!("");
            hprintln!("vs Emill P256-Cortex-M4 (hand-optimised P-256 reference):");
            if emill_ticks < ours256 {
                let h = (ours256 as u64 * 100) / emill_ticks as u64;
                hprintln!(
                    "  P-256: Emill is {}.{:02}x FASTER than us ({} vs {} ticks)",
                    h / 100, h % 100, emill_ticks, ours256
                );
            } else if ours256 < emill_ticks {
                let h = (emill_ticks as u64 * 100) / ours256 as u64;
                hprintln!(
                    "  P-256: mcu-crypto-asm is {}.{:02}x FASTER than Emill ({} vs {} ticks)",
                    h / 100, h % 100, ours256, emill_ticks
                );
            } else {
                hprintln!(
                    "  P-256: 1.00x - exact cycle parity with Emill reference ({} vs {} ticks)",
                    ours256, emill_ticks
                );
            }
            hprintln!("  P-384: no comparison exists - Emill implements P-256 only");
        }
    }

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

fn point_add_fiat256(
    x1: &Fp256, y1: &Fp256, z1: &Fp256,
    x2: &Fp256, y2: &Fp256, z2: &Fp256,
    b_mont: &Fp256,
) -> (Fp256, Fp256, Fp256) {
    let fmul = |a: &Fp256, b: &Fp256| -> Fp256 {
        let mut out = Fp256([0; 8]);
        fiat_crypto::p256_32::fiat_p256_mul(&mut out, a, b);
        out
    };
    let fadd = |a: &Fp256, b: &Fp256| -> Fp256 {
        let mut out = Fp256([0; 8]);
        fiat_crypto::p256_32::fiat_p256_add(&mut out, a, b);
        out
    };
    let fsub = |a: &Fp256, b: &Fp256| -> Fp256 {
        let mut out = Fp256([0; 8]);
        fiat_crypto::p256_32::fiat_p256_sub(&mut out, a, b);
        out
    };

    let t0 = fmul(x1, x2);
    let t1 = fmul(y1, y2);
    let t2 = fmul(z1, z2);

    let t3 = fadd(x1, y1);
    let t4 = fadd(x2, y2);
    let t3 = fmul(&t3, &t4);

    let t4 = fadd(&t0, &t1);
    let t3 = fsub(&t3, &t4);
    let t4 = fadd(y1, z1);

    let x3 = fadd(y2, z2);
    let t4 = fmul(&t4, &x3);
    let x3 = fadd(&t1, &t2);

    let t4 = fsub(&t4, &x3);
    let x3 = fadd(x1, z1);
    let y3 = fadd(x2, z2);

    let x3 = fmul(&x3, &y3);
    let y3 = fadd(&t0, &t2);
    let y3 = fsub(&x3, &y3);

    let z3 = fmul(b_mont, &t2);
    let x3 = fsub(&y3, &z3);
    let z3 = fadd(&x3, &x3);

    let x3 = fadd(&x3, &z3);
    let z3 = fsub(&t1, &x3);
    let x3 = fadd(&t1, &x3);

    let y3 = fmul(b_mont, &y3);
    let t1 = fadd(&t2, &t2);
    let t2 = fadd(&t1, &t2);

    let y3 = fsub(&y3, &t2);
    let y3 = fsub(&y3, &t0);
    let t1 = fadd(&y3, &y3);

    let y3 = fadd(&t1, &y3);
    let t1 = fadd(&t0, &t0);
    let t0 = fadd(&t1, &t0);

    let t0 = fsub(&t0, &t2);
    let t1 = fmul(&t4, &y3);
    let t2 = fmul(&t0, &y3);

    let y3 = fmul(&x3, &z3);
    let y3 = fadd(&y3, &t2);
    let x3 = fmul(&t3, &x3);

    let x3 = fsub(&x3, &t1);
    let z3 = fmul(&t4, &z3);
    let t1 = fmul(&t3, &t0);

    let z3 = fadd(&z3, &t1);

    (x3, y3, z3)
}

fn point_add_fiat384(
    x1: &Fp384, y1: &Fp384, z1: &Fp384,
    x2: &Fp384, y2: &Fp384, z2: &Fp384,
    b_mont: &Fp384,
) -> (Fp384, Fp384, Fp384) {
    let fmul = |a: &Fp384, b: &Fp384| -> Fp384 {
        let mut out = Fp384([0; 12]);
        fiat_crypto::p384_32::fiat_p384_mul(&mut out, a, b);
        out
    };
    let fadd = |a: &Fp384, b: &Fp384| -> Fp384 {
        let mut out = Fp384([0; 12]);
        fiat_crypto::p384_32::fiat_p384_add(&mut out, a, b);
        out
    };
    let fsub = |a: &Fp384, b: &Fp384| -> Fp384 {
        let mut out = Fp384([0; 12]);
        fiat_crypto::p384_32::fiat_p384_sub(&mut out, a, b);
        out
    };

    let t0 = fmul(x1, x2);
    let t1 = fmul(y1, y2);
    let t2 = fmul(z1, z2);

    let t3 = fadd(x1, y1);
    let t4 = fadd(x2, y2);
    let t3 = fmul(&t3, &t4);

    let t4 = fadd(&t0, &t1);
    let t3 = fsub(&t3, &t4);
    let t4 = fadd(y1, z1);

    let x3 = fadd(y2, z2);
    let t4 = fmul(&t4, &x3);
    let x3 = fadd(&t1, &t2);

    let t4 = fsub(&t4, &x3);
    let x3 = fadd(x1, z1);
    let y3 = fadd(x2, z2);

    let x3 = fmul(&x3, &y3);
    let y3 = fadd(&t0, &t2);
    let y3 = fsub(&x3, &y3);

    let z3 = fmul(b_mont, &t2);
    let x3 = fsub(&y3, &z3);
    let z3 = fadd(&x3, &x3);

    let x3 = fadd(&x3, &z3);
    let z3 = fsub(&t1, &x3);
    let x3 = fadd(&t1, &x3);

    let y3 = fmul(b_mont, &y3);
    let t1 = fadd(&t2, &t2);
    let t2 = fadd(&t1, &t2);

    let y3 = fsub(&y3, &t2);
    let y3 = fsub(&y3, &t0);
    let t1 = fadd(&y3, &y3);

    let y3 = fadd(&t1, &y3);
    let t1 = fadd(&t0, &t0);
    let t0 = fadd(&t1, &t0);

    let t0 = fsub(&t0, &t2);
    let t1 = fmul(&t4, &y3);
    let t2 = fmul(&t0, &y3);

    let y3 = fmul(&x3, &z3);
    let y3 = fadd(&y3, &t2);
    let x3 = fmul(&t3, &x3);

    let x3 = fsub(&x3, &t1);
    let z3 = fmul(&t4, &z3);
    let t1 = fmul(&t3, &t0);

    let z3 = fadd(&z3, &t1);

    (x3, y3, z3)
}

