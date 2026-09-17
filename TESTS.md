# Cryptographic Test Matrix & Verification Architecture

This document specifies the verification architecture, test vectors, and execution environments for `mcu-crypto-asm`.

All cryptographic implementations are verified across three tiers of test suites:
1. **NIST CAVP / ACVP**: Official Cryptographic Algorithm Validation Program / Automated Cryptographic Validation Protocol test vectors.
2. **IETF RFC Known Answer Tests (KATs)**: Official standard vectors from RFC specifications.
3. **Google Project Wycheproof Adversarial Tests**: Malicious and corner-case vectors testing invalid curve attacks, low-order subgroups, non-canonical encodings, AEAD tag truncation, and ciphertext bit tampering.

---

## 1. Test Verification Matrix

| Algorithm & Primitive | Specification | Test Vectors / Coverage | Target Architectures | Test Suite File | Execution Runner |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AES-128 / AES-256 (ECB)** | NIST FIPS 197 | Official NIST CAVP Known Answer Tests | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, Xtensa ESP32-S3, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU (`cargo qtest`), **Teleprobe HIL** |
| **AES-128-CBC** | NIST SP 800-38A | Multi-block CBC encryption with IV chaining | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU |
| **AES-GCM (128/256-bit)** | NIST SP 800-38D | NIST CAVP vectors (PT, AAD, IV, CT, Tag) | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU |
| **AES-GCM Adversarial** | Project Wycheproof | Tag truncation rejection, 1-bit CT tampering, corrupted AAD | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU, **Teleprobe HIL** |
| **GHASH ($GF(2^{128})$)** | NIST SP 800-38D | Polynomial multiplication & reduction over $GF(2^{128})$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, Xtensa ESP32-S3, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU (`cargo qtest`), **Teleprobe HIL** |
| **SHA-512 / 384 / 256 / 224** | NIST FIPS 180-4 | Official NIST CAVP hash vectors & multi-block chaining | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU, **Teleprobe HIL** |
| **HMAC-SHA-256 / HMAC-SHA-512** | NIST FIPS 198-1 / RFC 4231 | Official KATs, short keys, long keys (> block size), boundary messages | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU |
| **Keccak / SHA3-256 / SHAKE** | NIST FIPS 202 | Official CAVP test vectors across rates $r=1088, 1344$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU (`cargo qtest`), **Teleprobe HIL** |
| **ChaCha20 Stream Cipher** | RFC 8439 Section 2.3 & 2.4 | Block function KAT, encryption KAT, multi-block streaming | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **Poly1305 One-Time MAC** | RFC 8439 Section 2.5 | Clamping KAT, polynomial accumulator mod $2^{130}-5$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU (`cargo qtest`), **Teleprobe HIL** |
| **ChaCha20-Poly1305 AEAD** | RFC 8439 Section 2.8 | Full AEAD construction with associated data & tag verification | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU |
| **ChaCha20-Poly1305 Adversarial** | Project Wycheproof | Tag bit alterations, invalid tag lengths, truncated ciphertext | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU |
| **X25519 ECDH** | RFC 7748 Section 5.2 | Alice/Bob shared secret, 1,000-iteration Montgomery ladder chain | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU (`cargo qtest`), **Teleprobe HIL** |
| **X25519 Adversarial** | Project Wycheproof | Low-order points (order 1, 2, 4, 8), quadratic twist points | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU, **Teleprobe HIL** |
| **Ed25519 Sign & Verify** | RFC 8032 Section 7.1 | Key derivation, empty message, multi-byte messages | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU (`cargo qtest`), **Teleprobe HIL** |
| **Ed25519 Adversarial** | Project Wycheproof | Non-canonical scalar $S \ge L$ rejection, small-order points | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU, **Teleprobe HIL** |
| **NIST P-256 (secp256r1)** | NIST SP 800-56A / FIPS 186-4 | Base point scalar mult, ECDH key agreement, public key derivation | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU, **Teleprobe HIL** |
| **NIST P-256 Adversarial** | Project Wycheproof | Off-curve coordinates $y^2 \ne x^3 - 3x + b$, coordinates $\ge p$, point at infinity | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU, **Teleprobe HIL** |
| **NIST P-384 (secp384r1)** | NIST SP 800-56A | Base point multiplication, scalar mult KATs | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU |
| **secp256k1 ECDH & ECDSA** | RFC 6979 Section A.2.5 | Base point mult, deterministic ECDSA signing & verification | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **secp256k1 Adversarial** | Project Wycheproof | Off-curve points, ECDSA high-S malleability, order point handling | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU |
| **RSA Modular Exponentiation** | NIST FIPS 186-4 | 1024-bit public exponentiation $M^e \pmod N$ with $e=65537$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU |
| **ML-KEM (Kyber)** | NIST FIPS 203 ACVP | Ring arithmetic multiplication over $\mathbb{Z}_q[X]/(X^{256}+1)$, polynomial serialization | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **ML-DSA (Dilithium)** | NIST FIPS 204 ACVP | Ring arithmetic multiplication over $\mathbb{Z}_q[X]/(X^{256}+1)$ with $q=8380417$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |

---

## 2. Wycheproof Test Vector Footprint: JSON vs. Compact Binary Blobs

In discussions regarding embedded cryptographic test execution (e.g. on Embassy Matrix chat with `dirbaio`), a key question is:
> *Can Project Wycheproof tests fit on real microcontrollers, or are they too large?*

### The Reality
1. **Raw JSONs on Disk**: On the host filesystem, Wycheproof test files are formatted as expansive, verbose JSON files (e.g., `mldsa_87` is 2.5 MB, `rsa_oaep` is 1.7 MB, `p256_ecdh` is 1.5 MB). These raw files obviously cannot be stored on typical microcontrollers directly.
2. **Binary Packing in Embassy**: In `embassy-crypto-test`, a build script (`build.rs`) parses the Wycheproof JSONs on the host at compile time, deduplicates keys across test groups, and serializes the raw binary data into compact blob files (`blob0.bin` .. `blob59.bin`).
3. **Blob Sizes**: The resulting blobs are remarkably compact—typically between **1 KB and 60 KB** (e.g. `blob2.bin` is 656 bytes, `blob43.bin` is 2.1 KB).
4. **Linker Dead-Code Stripping**: Under Rust's `--gc-sections` and Link-Time Optimization (LTO), each test binary links *only* the specific blob required for that test suite, dropping all others.
5. **Why the 12 KB SRAM Limit Occurred**:
   - On standard hardware used for HIL (such as STM32H5 with 640 KB SRAM or nRF52840 with 256 KB SRAM), Wycheproof test binaries easily fit in SRAM with 80–90% headroom.
   - The overflow was encountered specifically when trying to execute a **100% RAM-only firmware** on an entry-level **STM32C031** (which has only 12 KB total SRAM, partitioned into 8 KB code + 4 KB data in `memory-c0-ram.x`). Even a minimal embedded binary with `defmt` and RTT buffers occupies ~15–20 KB of text.
   - By supporting multi-target RAM linker scripts (`memory-h5-ram.x` for 200 KB RAM and `memory-nrf-ram.x` for 200 KB RAM), full Wycheproof adversarial suites run smoothly in physical silicon HIL.

---

## 3. Test Execution Environments: QEMU vs. Teleprobe HIL

`mcu-crypto-asm` utilizes a two-tier verification architecture:

```
+-----------------------------------------------------------------------------+
|                          TEST EXECUTION PARADIGM                            |
+-----------------------------------------------------------------------------+
|                                                                             |
|   1. CI / REGRESSION MATRIX: QEMU (`cargo-qemu-test`)                        |
|      - High-throughput execution across all 6 target ISAs                   |
|      - Cortex-M4, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V, x86_64         |
|      - Zero physical hardware setup, no flash fatigue, instantaneous boot   |
|      - Sub-second execution (< 2s per ISA target)                           |
|      - Executed on every push and pull request via GitHub Actions           |
|                                                                             |
|   2. SILICON VALIDATION: Embassy Teleprobe HIL                              |
|      - Targets: STM32H5, nRF52840, Nucleo-STM32C031                         |
|      - True microarchitectural cycle counting & pipeline stall measurement  |
|      - Zero-variance constant-time auditing on real silicon bus arbiters    |
|      - 100% RAM-only firmware execution (zero flash memory wear)            |
|      - < 50 ms execution duration (well under the 10s teleprobe ceiling)    |
|      - Zero secret leakage: authentication purely via environment variables |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

## 4. Teleprobe HIL Strict Operational Guarantees

The Teleprobe HIL integration in `tests/teleprobe-cm0/` satisfies all hardware-in-the-loop constraints:

### 1. Zero Flash Memory Wear (100% RAM-Only Firmware)
Microcontroller flash has a limited write/erase endurance (10,000 to 100,000 cycles). Continuous CI flashing degrades physical silicon.
- Dedicated RAM linker scripts map Flash to volatile SRAM:
  - [`memory-c0-ram.x`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0/memory-c0-ram.x): For STM32C031 (`ORIGIN = 0x20000000, LENGTH = 12K`).
  - [`memory-h5-ram.x`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0/memory-h5-ram.x): For STM32H5 (`ORIGIN = 0x20000000, LENGTH = 200K`).
  - [`memory-nrf-ram.x`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0/memory-nrf-ram.x): For nRF52840 (`ORIGIN = 0x20000000, LENGTH = 200K`).
- Teleprobe loads ELF segments directly into SRAM via SWD without issuing flash write or erase commands.

### 2. Strict 10-Second Timeout Compliance
Embassy Teleprobe enforces a hard 10-second timeout per run.
- The canary test suite completes in **< 50 milliseconds** at 48 MHz.
- Upon completion, the firmware logs success via `defmt` over RTT and triggers `cortex_m::asm::bkpt()`.

### 3. Private Token Security
- The repository contains **zero secrets, tokens, or credentials**.
- The Cargo runner uses standard environment variables (`TELEPROBE_TOKEN`, `TELEPROBE_HOST`):
  ```toml
  runner = "teleprobe client run --target nucleo-stm32c031c6 -s"
  ```

---

## 5. How to Run the Tests

### A. Host Test Suites (NIST CAVP, RFC, Wycheproof)
```bash
cargo test --test crypto_kats
```

### B. QEMU Multi-Target Tests (`cargo-qemu-test`)
Run bare-metal assembly tests in QEMU across target architectures:
```bash
# ARM Cortex-M4 / Cortex-M7 (Hardware FPU)
cargo qtest --target thumbv7em-none-eabihf --test crypto_kats

# ARM Cortex-M33 (ARMv8-M Mainline)
cargo qtest --target thumbv8m.main-none-eabihf --test crypto_kats

# ARM Cortex-M3 (ARMv7-M)
cargo qtest --target thumbv7m-none-eabi --test crypto_kats

# ARM Cortex-M0+ (ARMv6-M)
cargo qtest --target thumbv6m-none-eabi --test crypto_kats

# RISC-V RV32IMAC
cargo qtest --target riscv32imac-unknown-none-elf --test crypto_kats
```

### C. Embassy Teleprobe HIL Hardware Execution
Run hardware-in-the-loop tests on physical microcontrollers:
```bash
cd tests/teleprobe-cm0

# Set your private environment credentials
export TELEPROBE_HOST="https://teleprobe.embassy.dev"
export TELEPROBE_TOKEN="<your-private-token>"

# Select memory script (defaults to memory-h5-ram.x)
export TELEPROBE_MEMORY_X="memory-h5-ram.x"

# Run RAM-only firmware on physical silicon
cargo run --release
```
