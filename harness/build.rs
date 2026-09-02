fn main() {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("memory.x"), include_bytes!("memory.x")).unwrap();
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
}
