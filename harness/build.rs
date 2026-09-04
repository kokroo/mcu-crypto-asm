fn main() {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    // NOTE: there must be NO `memory.x` in the crate root. cortex-m-rt's
    // link.x does `INCLUDE memory.x`, which the linker resolves from the
    // working directory FIRST -- a root copy silently wins over the generated
    // one and you link for the wrong address map.
    // NISTP_MEMORY_X selects the layout: default is the QEMU mps2 map; set it
    // to memory-nrf-ram.x to run from RAM on a real nRF52840 without writing
    // a single byte of flash.
    let which = std::env::var("NISTP_MEMORY_X").unwrap_or_else(|_| "memory-qemu-mps2.x".into());
    println!("cargo:rerun-if-env-changed=NISTP_MEMORY_X");
    println!("cargo:rerun-if-changed={which}");
    let layout = std::fs::read(&which).unwrap_or_else(|e| panic!("{which}: {e}"));
    std::fs::write(out.join("memory.x"), layout).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");

    // The library's build script sets this for the library only. The harness
    // needs it too, or the differential test silently reports "no assembly
    // backend" and skips the very thing it exists to check.
    println!("cargo:rustc-check-cfg=cfg(nistp_asm_cm4)");
    println!("cargo:rustc-check-cfg=cfg(nistp_asm_xtensa)");
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main") {
        println!("cargo:rustc-cfg=nistp_asm_cm4");
    }
    if target.starts_with("xtensa") {
        println!("cargo:rustc-cfg=nistp_asm_xtensa");
    }

    println!("cargo:rustc-check-cfg=cfg(emill)");
    if target.starts_with("thumbv7em") {
        println!("cargo:rustc-cfg=emill");
    }
}

/// Assemble Emill's P-256 assembly plus our AAPCS shim.
///
/// The shim must live in the SAME assembly unit as `P256_mulmod` (an internal,
/// non-global symbol), so we concatenate rather than edit the vendored file.
fn build_emill() -> Result<(), String> {
    use std::path::PathBuf;
    use std::process::Command;

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let src = std::path::Path::new("../third_party/emill");
    if !src.join("p256-cortex-m4-asm-gcc.S").exists() {
        return Err("vendored sources missing".into());
    }

    let upstream = std::fs::read_to_string(src.join("p256-cortex-m4-asm-gcc.S"))
        .map_err(|e| e.to_string())?;
    let shim = std::fs::read_to_string(src.join("shim.S")).map_err(|e| e.to_string())?;
    // The upstream file ends with `.end`, which tells the assembler to stop.
    // Appending after it is SILENTLY discarded -- the shim assembles to
    // nothing and the link fails with an undefined symbol. Drop it first.
    let trimmed = {
        let mut lines: Vec<&str> = upstream.lines().collect();
        while let Some(last) = lines.last() {
            let t = last.trim();
            if t.is_empty() || t == ".end" {
                let was_end = t == ".end";
                lines.pop();
                if was_end {
                    break;
                }
            } else {
                return Err("expected the vendored asm to end with `.end`".into());
            }
        }
        lines.join("\n")
    };
    let combined = out.join("emill_combined.S");
    std::fs::write(&combined, format!("{trimmed}\n{shim}\n\t.end\n"))
        .map_err(|e| e.to_string())?;

    let obj = out.join("emill.o");
    let lib = out.join("libemill.a");
    let st = Command::new("arm-none-eabi-gcc")
        .args(["-c", "-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=hard", "-mfpu=fpv4-sp-d16", "-I"])
        .arg(src)
        .arg(&combined)
        .arg("-o")
        .arg(&obj)
        .status()
        .map_err(|e| format!("arm-none-eabi-gcc: {e}"))?;
    if !st.success() {
        return Err("assembling Emill's sources failed".into());
    }
    let _ = std::fs::remove_file(&lib);
    let st = Command::new("arm-none-eabi-ar")
        .arg("rcs").arg(&lib).arg(&obj)
        .status()
        .map_err(|e| format!("arm-none-eabi-ar: {e}"))?;
    if !st.success() {
        return Err("archiving failed".into());
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=emill");
    Ok(())
}
