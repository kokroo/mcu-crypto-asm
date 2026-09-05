# mcu-crypto-asm

**Hand-written assembly cryptography for 32-bit microcontrollers** — constant-time, `no_std`, zero allocator, zero dependencies.

Fast, audited assembly kernels for **P-256 and P-384** on **ARM Cortex-M4/M7/M33** and **Xtensa LX7** (ESP32-S2/S3), with a clean portable Rust fallback for any other 32-bit target. All benchmarks are verified on silicon.

```toml
[dependencies]
mcu-crypto-asm = "0.1"
```

```rust
use mcu_crypto_asm::{p256, p384};

// Fast in-place Montgomery field operations:
let mut out = [0u32; 8];
p256::mul_mont(&mut out, &a, &b);
p256::sqr_mont(&mut out, &a);
p256::add_mod(&mut out, &a, &b);
p256::sub_mod(&mut out, &a, &b);

// Public key derivation (SEC1 uncompressed: 0x04 || x || y)
let mut pk = [0u8; 65];
p256::derive_public_key(&secret, &mut pk)?;

// Point decoding (supports compressed 0x02/0x03 and uncompressed 0x04)
let point = p256::decode_point(&compressed_pk)?;

// ECDH shared secret (validates peer point on-curve)
let mut shared = [0u8; 32];
p256::ecdh::shared_secret(&secret, &peer_pk, &mut shared)?;

// ECDSA sign & verify
let mut r = [0u8; 32];
let mut s = [0u8; 32];
p256::ecdsa::sign(&secret, &msg_hash, &nonce, &mut r, &mut s)?;
p256::ecdsa::verify(&pk, &msg_hash, &r, &s)?;
```

---

## Scope & Adoption

| Target / Primitive | Status | Recommended Implementation |
|---|---|---|
| **P-384** (all MCUs) | ✅ Done | **mcu-crypto-asm** (2.5x–3x faster than fiat-crypto / portable) |
| **ESP32-S2 / S3** (P-256 & P-384) | ✅ Done | **mcu-crypto-asm** (no on-chip ECC hardware on LX7) |
| **P-256** on Cortex-M4/M7/M33 | ✅ Done | **mcu-crypto-asm** (hand-optimised assembly, outperforming Emill reference) |
| MCUs with dedicated PKA/ECC | N/A | Dedicated hardware accelerator (e.g. STM32 PKA, ESP32-C6/H2 ECC) |

---

## Measured Performance

Exact hardware cycle counts (DWT CYCCNT / Xtensa CCOUNT) measured on silicon, running from RAM.

### P-256 Field & Point Operations (nRF52840 Cortex-M4 @ 64 MHz)

Measured against `fiat-crypto` (vendored by RustCrypto) and `Emill` (Emil Lenngren's hand-optimised reference assembly):

| Operation | fiat-crypto | Emill Reference | mcu-crypto-asm | Speedup vs fiat | Speedup vs Emill |
|---|---|---|---|---|---|
| `mul_mont` | 2 248 | 394 | **392** | **5.73x** | **1.01x (faster)** |
| `sqr_mont` | 2 038 | 360 | **336** | **6.06x** | **1.07x (faster)** |
| `add_mod` | 253 | 156 | **133** | **1.88x** | **1.17x (faster)** |
| `sub_mod` | 152 | 137 | **114** | **1.31x** | **1.20x (faster)** |
| `Point::add` (complete projective) | 36 291 | *(not implemented)* | **9 031** | **4.01x** | — |

*Note: Emil's upstream library does not implement Renes-Costello-Batina complete projective addition (`Point::add`), only Jacobian mixed addition.*

### P-256 High-Level Protocols vs Emill Reference (nRF52840 Cortex-M4 @ 64 MHz)

Head-to-head comparison against Emil Lenngren's reference Cortex-M4 assembly implementation:

| Operation | Emill Reference | mcu-crypto-asm | Time (@ 64 MHz) | Hardware Cycles Saved | Speedup vs Emill |
|---|---|---|---|---|---|
| ECDH Shared Secret (`k*P`) | 1 521 655 | **1 393 454** | **21 ms** | **+128 201 cycles** | **1.09x faster** |
| `ECDSA verify` | 1 433 648 | **1 413 118** | **22 ms** | **+20 530 cycles** | **1.01x faster** |
| `ECDSA sign` | 588 282 | **585 074** | **9 ms** | **+3 208 cycles** | **1.01x faster** |
| Comb Base Mul (`k*G`) | 521 229 | **517 953** | **8 ms** | **+3 276 cycles** | **1.01x faster** |
| `derive_public_key` | 522 081 | **518 809** | **8 ms** | **+3 272 cycles** | **1.01x faster** |

### P-384 Performance (nRF52840 Cortex-M4 @ 64 MHz)

Comparison against `fiat-crypto` and generic portable 32-bit software *(note: Emil Lenngren only implemented P-256; no P-384 implementation exists in Emill)*:

| Operation | Portable Rust | fiat-crypto | mcu-crypto-asm | Speedup vs fiat | Speedup vs Portable |
|---|---|---|---|---|---|
| `mul_mont` | 6 336 | 3 842 | **1 352** | **2.84x** | **4.68x** |
| `sqr_mont` | 6 300 | 3 503 | **1 358** | **2.57x** | **4.64x** |
| `add_mod` | 392 | 392 | **222** | **1.76x** | **1.76x** |
| `sub_mod` | 266 | 266 | **180** | **1.47x** | **1.47x** |
| `Point::add` (complete projective) | 63 844 | 63 844 | **24 867** | **2.56x** | **2.56x** |

**P-384 End-to-End Protocols (mcu-crypto-asm)**:
- Comb Base Mul (`k*G`): **3 343 369 cycles** (52 ms @ 64 MHz)
- `derive_public_key`: **3 902 412 cycles** (60 ms @ 64 MHz)
- `ECDSA sign`: **5 176 025 cycles** (80 ms @ 64 MHz)
- `ECDSA verify`: **12 775 178 cycles** (199 ms @ 64 MHz)
- ECDH Shared Secret (`k*P`): **7 567 832 cycles** (118 ms @ 64 MHz)

### ESP32-S3 Performance (Xtensa LX7 @ 240 MHz)

| Operation | fiat-crypto | mcu-crypto-asm | Speedup vs fiat |
|---|---|---|---|
| P-256 `mul_mont` | 2 795 | **1 272** | **2.20x** |
| P-384 `mul_mont` | 8 538 | **2 884** | **2.96x** |

---

## Constant Time & Verification

All operations execute in strictly constant time with zero operand-dependent branches or memory lookup tables. Verification uses three complementary layers:

1. **Static Assembly Audit** (`cargo test --test constant_time`): Verifies generated assembly contains zero branches, all loads use fixed `[reg, #imm]` offsets, and only constant-latency instructions are used.
2. **Dynamic Hardware Timing** (`harness/src/bin/ct.rs`): Tests diverse operand classes against same-input controls on real silicon using DWT CYCCNT (zero cycle spread across all operations).
3. **Instruction Tracing** (`harness/src/bin/scantrace.rs`): QEMU single-step execution tracing diffs PC execution traces to prove identical instruction sequences across inputs.

> **Security Note**: Constant time is guaranteed with respect to secret scalars and field element values. Not hardened against physical side-channels (power/EM) or fault injection. Cortex-M3 is deliberately excluded due to its variable-latency multiplier.

---

## Design Highlights

- **Unrolled FIOS Montgomery Multiplication**: Fused Inversion-Output-Shift minimizes memory roundtrips, fully unrolled to eliminate branch overhead.
- **Target-Specific Assembly**:
  - **Cortex-M4 / M7 / M33**: Uses 1-cycle `UMAAL` instructions (`RdHi:RdLo = Rn*Rm + RdHi + RdLo`).
  - **Xtensa LX7**: Synthesizes branchless carry chains using `SALTU`.
- **Jacobian Coordinates & Algorithm 10 Doubling**: eprint 2014/130 doubling (4 sqr + 4 mul) and mixed addition mimicking Emil Lenngren's P256-Cortex-M4 techniques, cutting variable-base scalar multiplication latency.
- **Affine Table Batch Inversion**: Converts precomputed odd multiplier tables to affine coordinates ($Z=1$) using Montgomery batch inversion. Loop additions switch from full Jacobian ($11M + 5S$) to mixed affine ($7M + 4S$), cutting variable-base scalar multiplication by >128k cycles.
- **Signed Odd-Scalar Recoding ($w=4$)**: Constant-time odd recoding with an 8-point precomputed table eliminates zero doublings/additions.
- **Fast Inversionless ECDSA Verification**: Verifies signatures directly in projective/Jacobian coordinates via $r \cdot Z^2 \equiv X \pmod p$, eliminating the expensive modular field inversion.
- **Complete Projective Formulas**: Renes-Costello-Batina complete addition formulas ($a = -3$) eliminate special cases for general point additions.
- **Fixed-Base Comb**: Precomputed tables accelerate base point multiplication (`k*G`) down to 8 ms (P-256) / 52 ms (P-384).
- **Direct In-Place Field APIs**: Zero-overhead Montgomery multiplication, squaring, modular addition, and subtraction directly callable as leaf functions avoiding struct-by-value return copies.
- **Input Validation**: Rejects points off-curve or not in the valid subgroup before computation, preventing invalid-curve attacks.

---

## Supported Targets

| Target Triple | Core / Hardware | Backend | Notes |
|---|---|---|---|
| `thumbv7em-none-eabi(hf)` | Cortex-M4 / M7 | Hand-written Assembly | Hardware `UMAAL` |
| `thumbv8m.main-none-eabi(hf)` | Cortex-M33 (STM32H5, nRF5340, etc.) | Hand-written Assembly | Hardware `UMAAL` + DWT LAR unlock |
| `xtensa-esp32s3-none-elf` | Xtensa LX7 (ESP32-S3) | Hand-written Assembly | Needs Espressif toolchain |
| `xtensa-esp32s2-none-elf` | Xtensa LX7 (ESP32-S2) | Hand-written Assembly | Needs Espressif toolchain |
| `*` (Any other target) | Host / RISC-V / Cortex-M0+ | Portable Rust | Constant-time fallback |

---

## Building and Testing

```sh
# Host tests (portable reference, BigInt oracle, constant-time audit)
cargo test

# Full multi-target test under QEMU
./run-all.sh
```

### Running on Real Hardware (RAM Execution)

Binaries execute directly from RAM to avoid Flash wear.

**nRF52840 (Cortex-M4):**
```sh
cd harness
# Correctness harness (KATs + differential testing):
NISTP_MEMORY_X=memory-nrf-ram.x cargo build --release --bin nistp-harness
probe-rs run --chip nRF52840_xxAA target/thumbv7em-none-eabihf/release/nistp-harness

# Cycle benchmarks:
NISTP_MEMORY_X=memory-nrf-ram.x cargo build --release --bin bench
probe-rs run --chip nRF52840_xxAA target/thumbv7em-none-eabihf/release/bench

# Constant-time verification:
NISTP_MEMORY_X=memory-nrf-ram.x cargo build --release --bin ct
probe-rs run --chip nRF52840_xxAA target/thumbv7em-none-eabihf/release/ct
```

**STM32H563 (Cortex-M33):**

Runs both P-256 and P-384 with hardware `UMAAL` on ARMv8-M Mainline (e.g. NUCLEO-H563ZI). The benchmark harness unlocks `DWT_LAR` automatically to enable DWT cycle counting.

```sh
# 1. Install toolchain target (once):
rustup target add thumbv8m.main-none-eabihf

cd harness

# 2. Correctness harness (P-256 & P-384 KATs, 500 rounds differential testing, sign/verify):
NISTP_MEMORY_X=memory-stm32h5-ram.x cargo build --release --target thumbv8m.main-none-eabihf --bin nistp-harness
probe-rs run --chip STM32H563ZI target/thumbv8m.main-none-eabihf/release/nistp-harness

# 3. Exact cycle benchmarks (DWT CYCCNT on silicon):
NISTP_MEMORY_X=memory-stm32h5-ram.x cargo build --release --target thumbv8m.main-none-eabihf --bin bench
probe-rs run --chip STM32H563ZI target/thumbv8m.main-none-eabihf/release/bench

# 4. Constant-time verification (dynamic timing audit):
NISTP_MEMORY_X=memory-stm32h5-ram.x cargo build --release --target thumbv8m.main-none-eabihf --bin ct
probe-rs run --chip STM32H563ZI target/thumbv8m.main-none-eabihf/release/ct
```

*(To flash to internal Flash at `0x08000000` instead of RAM, build with `NISTP_MEMORY_X=memory-stm32h5.x`.)*

---

## Roadmap & Future Algorithms

See [TODO.md](TODO.md) for our comprehensive cross-architecture algorithm optimization matrix, reference implementation survey (including Emill, PQM4, etc.), and implementation roadmap spanning Cortex-M0/M0+, Cortex-M3, Xtensa, RISC-V, Curve25519/Ed25519, Poly1305, ChaCha20, RSA, and Post-Quantum ML-KEM / ML-DSA.

---

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
