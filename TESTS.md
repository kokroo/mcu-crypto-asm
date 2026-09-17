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
| **AES-128 / AES-256 (ECB)** | NIST FIPS 197 | Official NIST CAVP Known Answer Tests | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, Xtensa ESP32-S3, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **AES-128-CBC** | NIST SP 800-38A | Multi-block CBC encryption with IV chaining | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs) | Host, QEMU |
| **AES-GCM (128/256-bit)** | NIST SP 800-38D | NIST CAVP vectors (PT, AAD, IV, CT, Tag) | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs) | Host, QEMU |
| **AES-GCM Adversarial** | Project Wycheproof | Tag truncation rejection, 1-bit CT tampering, corrupted AAD | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs) | Host |
| **GHASH ($GF(2^{128})$)** | NIST SP 800-38D | Polynomial multiplication & reduction over $GF(2^{128})$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, Xtensa ESP32-S3, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **SHA-512 / 384 / 256 / 224** | NIST FIPS 180-4 | Official NIST CAVP hash vectors & multi-block chaining | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs) | Host, QEMU |
| **HMAC-SHA-256 / HMAC-SHA-512** | NIST FIPS 198-1 / RFC 4231 | Official KATs, short keys, long keys (> block size), boundary messages | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs) | Host, QEMU |
| **Keccak / SHA3-256 / SHAKE** | NIST FIPS 202 | Official CAVP test vectors across rates $r=1088, 1344$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **ChaCha20 Stream Cipher** | RFC 8439 Section 2.3 & 2.4 | Block function KAT, encryption KAT, multi-block streaming | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **Poly1305 One-Time MAC** | RFC 8439 Section 2.5 | Clamping KAT, polynomial accumulator mod $2^{130}-5$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **ChaCha20-Poly1305 AEAD** | RFC 8439 Section 2.8 | Full AEAD construction with associated data & tag verification | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs) | Host, QEMU |
| **ChaCha20-Poly1305 Adversarial** | Project Wycheproof | Tag bit alterations, invalid tag lengths, truncated ciphertext | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs) | Host |
| **X25519 ECDH** | RFC 7748 Section 5.2 | Alice/Bob shared secret, 1,000-iteration Montgomery ladder chain | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **X25519 Adversarial** | Project Wycheproof | Low-order points (order 1, 2, 4, 8), quadratic twist points | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs) | Host |
| **Ed25519 Sign & Verify** | RFC 8032 Section 7.1 | Key derivation, empty message, multi-byte messages | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **Ed25519 Adversarial** | Project Wycheproof | Non-canonical scalar $S \ge L$ rejection, small-order points | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs) | Host |
| **NIST P-256 (secp256r1)** | NIST SP 800-56A / FIPS 186-4 | Base point scalar mult, ECDH key agreement, public key derivation | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/teleprobe-cm0`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0) | Host, QEMU, **Teleprobe HIL** |
| **NIST P-256 Adversarial** | Project Wycheproof | Off-curve coordinates $y^2 \ne x^3 - 3x + b$, coordinates $\ge p$, point at infinity | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs) | Host |
| **NIST P-384 (secp384r1)** | NIST SP 800-56A | Base point multiplication, scalar mult KATs | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs) | Host, QEMU |
| **secp256k1 ECDH & ECDSA** | RFC 6979 Section A.2.5 | Base point mult, deterministic ECDSA signing & verification | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/rfc_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/rfc_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **secp256k1 Adversarial** | Project Wycheproof | Off-curve points, ECDSA high-S malleability, order point handling | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/wycheproof_adversarial.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/wycheproof_adversarial.rs) | Host |
| **RSA Modular Exponentiation** | NIST FIPS 186-4 | 1024-bit public exponentiation $M^e \pmod N$ with $e=65537$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs) | Host, QEMU |
| **ML-KEM (Kyber)** | NIST FIPS 203 ACVP | Ring arithmetic multiplication over $\mathbb{Z}_q[X]/(X^{256}+1)$, polynomial serialization | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |
| **ML-DSA (Dilithium)** | NIST FIPS 204 ACVP | Ring arithmetic multiplication over $\mathbb{Z}_q[X]/(X^{256}+1)$ with $q=8380417$ | Cortex-M4/M7, Cortex-M33, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64 | [`tests/cavp_tests.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/cavp_tests.rs), [`tests/crypto_kats.rs`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/crypto_kats.rs) | Host, QEMU (`cargo qtest`) |

---

## 2. Test Execution Environments: QEMU vs. Teleprobe HIL

To achieve both **fast, exhaustive regression coverage** and **true physical microarchitectural validation**, `mcu-crypto-asm` leverages a two-tier strategy:

```
+-----------------------------------------------------------------------------+
|                          TEST EXECUTION PARADIGM                            |
+-----------------------------------------------------------------------------+
|                                                                             |
|   1. CI / REGRESSION MATRIX: QEMU (`cargo-qemu-test`)                        |
|      - High-throughput execution across all 5 target ISAs                   |
|      - Cortex-M4, Cortex-M3, Cortex-M0+, RISC-V RV32IMAC, x86_64            |
|      - Zero physical hardware setup, no flash fatigue, instantaneous boot   |
|      - Sub-second execution (< 0.5s per ISA target)                         |
|      - Executed on every push and pull request via GitHub Actions           |
|                                                                             |
|   2. SILICON VALIDATION: Embassy Teleprobe HIL                              |
|      - Target: Nucleo-STM32C031, STM32H5, nRF52840                          |
|      - True microarchitectural cycle counting & pipeline stall measurement  |
|      - Zero-variance constant-time auditing on real silicon bus arbiters    |
|      - 100% RAM-only firmware execution (zero flash memory wear)            |
|      - < 50 ms execution duration (well under the 10s teleprobe ceiling)    |
|      - Zero secret leakage: authentication purely via environment variables |
|                                                                             |
+-----------------------------------------------------------------------------+
```

### Why QEMU (`cargo-qemu-test`) for Vector Regression?
1. **Speed & Scalability**: QEMU tests execute the exact embedded binaries in virtual hardware with semihosting exit in milliseconds (e.g. 0.25s for Cortex-M4, 0.48s for RISC-V).
2. **Exhaustive Vector Coverage**: Testing thousands of CAVP, RFC, and Wycheproof vectors on physical microcontrollers is constrained by queue times and communication bandwidth. QEMU enables running all 100+ test suites on every commit.
3. **No Hardware Infrastructure Bottlenecks**: Developers can run bare-metal assembly tests locally without needing a physical debug probe or board rack.

### Why Embassy Teleprobe HIL for Silicon Verification?
1. **Microarchitectural Faithfulness**: QEMU does not accurately model MCU multi-cycle non-constant-time multiplier units, bus contention, wait-states, or interrupt latency.
2. **Cycle-Accurate Benchmarking**: Hardware DWT (Data Watchpoint and Trace) cycle counters on real ARM Cortex cores measure exact cycle timings for Montgomery multiplications, ladder steps, and NTT butterflies.
3. **Silicon Constant-Time Auditing**: Verifies that branch predictors or memory caches on Cortex-M7/M33 do not induce secret-dependent timing variations.

---

## 3. Teleprobe HIL Strict Operational Guarantees

The Teleprobe HIL integration in `tests/teleprobe-cm0/` is engineered to strictly satisfy all hardware-in-the-loop constraints:

### 1. Zero Flash Memory Wear (100% RAM-Only Firmware)
Physical microcontroller flash has a limited write/erase endurance (typically 10,000 to 100,000 cycles). Continuous CI flashing will destroy the device.
- `mcu-crypto-asm` provides dedicated RAM linker scripts:
  - [`memory-c0-ram.x`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0/memory-c0-ram.x): For STM32C031 SRAM (`ORIGIN = 0x20000000, LENGTH = 12K`).
  - [`memory-h5-ram.x`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0/memory-h5-ram.x): For STM32H5 SRAM (`ORIGIN = 0x20000000, LENGTH = 200K`).
  - [`memory-nrf-ram.x`](file:///home/geek/Documents/GitHub/mcu-crypto-asm/tests/teleprobe-cm0/memory-nrf-ram.x): For nRF52840 SRAM (`ORIGIN = 0x20000000, LENGTH = 200K`).
- Linker mapping assigns `FLASH : ORIGIN = 0x20000000`. The probe loads ELF segments directly into volatile SRAM via SWD/JTAG without issuing flash erase or program commands.

### 2. Strict 10-Second Timeout Compliance
Embassy Teleprobe enforces a hard 10-second timeout per run.
- The canary test suite executes Montgomery arithmetic and full P-256 ECDH key exchange in **< 50 milliseconds** at 48 MHz.
- Upon completion, the firmware logs success via `defmt` over RTT and triggers `cortex_m::asm::bkpt()`.

### 3. Private Token Security
- The repository contains **zero secrets, tokens, or credentials**.
- The Cargo runner is configured as:
  ```toml
  runner = "teleprobe client run --target nucleo-stm32c031c6 -s"
  ```
- `teleprobe client` automatically authenticates using standard environment variables:
  - `TELEPROBE_TOKEN`: Private API token.
  - `TELEPROBE_HOST`: Teleprobe server endpoint.

---

## 4. How to Run the Tests

### A. Host Test Suites (NIST CAVP, RFC, Wycheproof)
Run all 100+ native host test suites:
```bash
# Run all host tests
cargo test

# Run specific suites
cargo test --test cavp_tests
cargo test --test rfc_tests
cargo test --test wycheproof_adversarial
```

### B. QEMU Multi-Target Tests (`cargo-qemu-test`)
Run bare-metal assembly tests in QEMU across target architectures:
```bash
# ARM Cortex-M4 / Cortex-M7 (Hardware FPU)
cargo qtest --target thumbv7em-none-eabihf --test crypto_kats

# ARM Cortex-M3
cargo qtest --target thumbv7m-none-eabi --test crypto_kats

# ARM Cortex-M0+
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
export TELEPROBE_MEMORY_X="memory-c0-ram.x"

# Run RAM-only firmware on physical silicon
cargo run --release
```
