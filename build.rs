//! Select the assembly backend from the concrete target triple.
//!
//! `target_feature = "dsp"` / `"v7"` are NOT exposed as cfgs for the bare-metal
//! ARM targets, so gating on them silently compiles the portable fallback and
//! you benchmark the wrong thing. Match the triple instead, and shout if the
//! target looks like one where this code would be *incorrect* rather than
//! merely slow.

fn main() {
    println!("cargo:rerun-if-changed=asm/cortex_m4.S");
    println!("cargo:rerun-if-changed=asm/xtensa_lx7.S");
    println!("cargo:rustc-check-cfg=cfg(nistp_asm_cm4)");
    println!("cargo:rustc-check-cfg=cfg(nistp_asm_xtensa)");

    let target = std::env::var("TARGET").unwrap_or_default();
    let forced_portable = std::env::var("CARGO_FEATURE_FORCE_PORTABLE").is_ok();
    if forced_portable {
        return;
    }

    // UMAAL + a single-cycle, constant-latency multiplier.
    // Cortex-M4 / M7 (thumbv7em) and Cortex-M33 (thumbv8m.main).
    let cm4 = target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main");

    // Cortex-M3 is ARMv7-M and does have UMAAL, but its multiplier is
    // variable-latency, so this code would leak timing there. Refuse.
    if target.starts_with("thumbv7m") {
        println!(
            "cargo:warning=nistp-mcu: {target} is Cortex-M3. It has UMAAL but a \
             variable-latency multiplier, so the assembly backend would NOT be \
             constant time. Using the portable backend instead."
        );
    }

    if cm4 {
        println!("cargo:rustc-cfg=nistp_asm_cm4");
    }

    if target.starts_with("xtensa") {
        println!("cargo:rustc-cfg=nistp_asm_xtensa");
    }
}
