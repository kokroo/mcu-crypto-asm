//! Select and build the assembly backend for the concrete target triple.
//!
//! Two traps this exists to avoid:
//!
//! 1. `target_feature = "dsp"` / `"v7"` are NOT exposed as cfgs for bare-metal
//!    ARM targets, so gating on them silently compiles the portable fallback
//!    and you benchmark the wrong thing. Match the triple instead.
//! 2. LLVM's Xtensa assembler does not implement `SALTU`, which the LX7
//!    backend is built on, so that file cannot go through `global_asm!`. It is
//!    assembled here with the esp GNU toolchain and linked as a static lib.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=asm/cortex_m4.S");
    println!("cargo:rerun-if-changed=asm/cortex_m4_p256.S");
    println!("cargo:rerun-if-changed=asm/cortex_m0_p256.S");
    println!("cargo:rerun-if-changed=asm/cortex_m_fe25519.S");
    println!("cargo:rerun-if-changed=asm/cortex_m_curve25519.S");
    println!("cargo:rerun-if-changed=asm/cortex_m_ed25519.S");
    println!("cargo:rerun-if-changed=asm/cortex_m_bignum.S");
    println!("cargo:rerun-if-changed=asm/xtensa_lx7.S");
    println!("cargo:rustc-check-cfg=cfg(nistp_asm_cm4)");
    println!("cargo:rustc-check-cfg=cfg(nistp_asm_cm0)");
    println!("cargo:rustc-check-cfg=cfg(nistp_asm_xtensa)");

    if std::env::var("CARGO_FEATURE_FORCE_PORTABLE").is_ok() {
        return;
    }
    let target = std::env::var("TARGET").unwrap_or_default();

    // --- Cortex-M4 / M7 / M33: UMAAL, constant-latency multiplier ---
    if target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main") {
        println!("cargo:rustc-cfg=nistp_asm_cm4");
    }

    // --- Cortex-M0 / M0+: ARMv6-M (Thumb-1 only, no UMAAL) ---
    if target.starts_with("thumbv6m") || target.starts_with("thumbv8m.base") {
        println!("cargo:rustc-cfg=nistp_asm_cm0");
    }

    // Cortex-M3 is ARMv7-M and does have UMAAL, but its multiplier is
    // variable-latency, so this code would not be constant time there.
    if target.starts_with("thumbv7m") {
        println!(
            "cargo:warning=mcu-crypto-asm: {target} is Cortex-M3 — UMAAL exists but the \
             multiplier is variable-latency, so the assembly would not be constant \
             time. Using the portable backend."
        );
    }

    // --- Xtensa LX7: ESP32-S2 / ESP32-S3 only. LX6 (plain ESP32) has no
    //     SALTU, so it stays on the portable backend. ---
    let xtensa_core = match target.as_str() {
        "xtensa-esp32s3-none-elf" | "xtensa-esp32s3-espidf" => Some("esp32s3"),
        "xtensa-esp32s2-none-elf" | "xtensa-esp32s2-espidf" => Some("esp32s2"),
        _ => None,
    };
    if let Some(core) = xtensa_core {
        match build_xtensa_asm(core) {
            Ok(()) => println!("cargo:rustc-cfg=nistp_asm_xtensa"),
            Err(e) => println!(
                "cargo:warning=mcu-crypto-asm: falling back to the portable backend on \
                 {target}: {e}"
            ),
        }
    }
}

/// Assemble `asm/xtensa_lx7.S` with the esp GNU toolchain and link it.
fn build_xtensa_asm(core: &str) -> Result<(), String> {
    let tc = find_xtensa_toolchain().ok_or_else(|| {
        "xtensa-esp-elf-gcc not found on PATH or under ~/.rustup/toolchains \
         (install it with `espup install`)"
            .to_string()
    })?;
    let gcc = tc.join("bin/xtensa-esp-elf-gcc");
    let ar = tc.join("bin/xtensa-esp-elf-ar");

    // The core config is selected by an env var, not -mcpu.
    let cfg = tc.join(format!("lib/xtensa_{core}.so"));
    if !cfg.exists() {
        return Err(format!("missing core config {}", cfg.display()));
    }

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let obj = out.join("nistp_xtensa.o");
    let lib = out.join("libnistp_xtensa_asm.a");

    let st = Command::new(&gcc)
        .env("XTENSA_GNU_CONFIG", &cfg)
        .args(["-c", "asm/xtensa_lx7.S", "-o"])
        .arg(&obj)
        .status()
        .map_err(|e| format!("running {}: {e}", gcc.display()))?;
    if !st.success() {
        return Err("assembling asm/xtensa_lx7.S failed".into());
    }

    let _ = std::fs::remove_file(&lib);
    let st = Command::new(&ar)
        .arg("rcs")
        .arg(&lib)
        .arg(&obj)
        .status()
        .map_err(|e| format!("running {}: {e}", ar.display()))?;
    if !st.success() {
        return Err("archiving the Xtensa assembly failed".into());
    }

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=nistp_xtensa_asm");
    Ok(())
}

/// Locate the esp GNU toolchain root (the dir containing `bin/` and `lib/`).
fn find_xtensa_toolchain() -> Option<PathBuf> {
    // Explicit override wins.
    if let Ok(p) = std::env::var("XTENSA_ESP_ELF_ROOT") {
        let p = PathBuf::from(p);
        if p.join("bin/xtensa-esp-elf-gcc").exists() {
            return Some(p);
        }
    }
    // On PATH (espup's export-esp.sh puts it there).
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join("xtensa-esp-elf-gcc").exists() {
                if let Some(root) = dir.parent() {
                    return Some(root.to_path_buf());
                }
            }
        }
    }
    // Fall back to scanning rustup's esp toolchains.
    let home = std::env::var("HOME").ok()?;
    let toolchains = Path::new(&home).join(".rustup/toolchains");
    let mut found = None;
    for tc in std::fs::read_dir(&toolchains).ok()? {
        let base = tc.ok()?.path().join("xtensa-esp-elf");
        let Ok(versions) = std::fs::read_dir(&base) else {
            continue;
        };
        for v in versions.flatten() {
            let root = v.path().join("xtensa-esp-elf");
            if root.join("bin/xtensa-esp-elf-gcc").exists() {
                found = Some(root);
            }
        }
    }
    found
}
