# fiat-crypto (vendored, MIT / Apache-2.0 / BSD-1-Clause)

Upstream: https://github.com/mit-plv/fiat-crypto — `fiat-c/src/{p256_32,p384_32}.c`,
unmodified. Formally verified generated Montgomery field arithmetic; the same
code the RustCrypto `p256` / `p384` crates vendor.

Used as the **baseline** for the Xtensa benchmark. The Cortex-M4 harness uses
the equivalent Rust crate; this is the C form so the bare-metal ESP32-S3
harness (which must be C, because LLVM's Xtensa assembler cannot assemble
SALTU) can link it.

`fiat_*_mul` are `static inline`, so `shim.c` provides external wrappers.
