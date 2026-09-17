use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let memory_x = env::var("TELEPROBE_MEMORY_X").unwrap_or_else(|_| "memory-h5-ram.x".into());
    println!("cargo:rerun-if-env-changed=TELEPROBE_MEMORY_X");
    println!("cargo:rerun-if-changed={memory_x}");

    let content = fs::read(&memory_x).unwrap_or_else(|e| panic!("{memory_x}: {e}"));
    fs::write(out.join("memory.x"), content).unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
}
