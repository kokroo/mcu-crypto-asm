//! Emits exactly two isolated comb scans — a zero digit then a non-zero one —
//! so a QEMU execution trace can be filtered to `comb_scan_diag` and the two
//! invocations diffed instruction by instruction.
#![no_std]
#![no_main]
use core::hint::black_box;
use cortex_m_rt::entry;
use cortex_m_semihosting::debug;
use nistp_mcu::{comb_tables, p256, Point};
use panic_semihosting as _;

#[entry]
fn main() -> ! {
    let t = &comb_tables::P256_COMB;
    // Same code, two digits. black_box keeps both calls real.
    black_box(Point::<{ p256::N }>::comb_scan_diag(&p256::CURVE, t, black_box(0)));
    black_box(Point::<{ p256::N }>::comb_scan_diag(&p256::CURVE, t, black_box(15)));
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
