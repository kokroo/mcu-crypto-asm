# mcu-crypto-asm

**Hand-written assembly cryptography for 32-bit microcontrollers** — constant-time, `no_std`, zero allocator, zero dependencies.

Fast, audited assembly kernels for **P-256 and P-384** on **ARM Cortex-M4/M7/M33** and **Xtensa LX7** (ESP32-S2/S3), with a clean portable Rust fallback for any other 32-bit target. All benchmarks are verified on silicon.

```toml
[dependencies]
mcu-crypto-asm = "0.1"
```

```rust
use mcu_crypto_asm::{p256, p384};

// Public key derivation (SEC1 uncompressed: 0x04 || x || y)
let mut pk = [0u8; 65];
p256::derive_public_key(&secret, &mut pk)?;

// Point decompression (SEC1 compressed: 0x02/0x03 || x)
let mut decompressed_pk = [0u8; 65];
p256::decompress_point(&compressed_pk, &mut decompressed_pk)?;

// ECDH shared secret (validates peer points on-curve)
let mut shared = [0u8; 32];
mcu_crypto_asm::ecdh::shared_secret::<{ p256::N }>(&p256::CURVE, &secret, &peer_pk, &mut shared)?;

// ECDSA sign & verify
let mut r = [0u8; 32];
let mut s = [0u8; 32];
p256::ecdsa::sign(&secret, &msg_hash, &nonce, &mut r, &mut s)?;
p256::ecdsa::verify(&pk, &msg_hash, &r, &s)?;
```

For embassy or async executors, non-blocking yielding variants (`derive_public_key_yielding`, `shared_secret_yielding`, `sign_yielding`, `verify_yielding`) cooperatively yield every ~350–640 µs so other tasks never stall.

---

## Scope & Adoption

| Target / Primitive | Status | Recommended Implementation |
|---|---|---|
| **P-384** (all MCUs) | ✅ Done | **mcu-crypto-asm** (2.5x–3x faster than fiat-crypto / portable) |
| **ESP32-S2 / S3** (P-256 & P-384) | ✅ Done | **mcu-crypto-asm** (no on-chip ECC hardware on LX7) |
| **P-256** on Cortex-M4/M7/M33 | ✅ Done | **mcu-crypto-asm** (or [Emill](https://github.com/Emill/P256-Cortex-M4) if raw P-256 speed is all you need) |
| MCUs with dedicated PKA/ECC | N/A | Dedicated hardware accelerator (e.g. STM32 PKA, ESP32-C6/H2 ECC) |

---

## Measured Performance

Exact hardware cycle counts (DWT CYCCNT / Xtensa CCOUNT) measured on silicon, running from RAM.

### Field & Point Operations vs fiat-crypto

Head-to-head comparison against `fiat-crypto` (the backend vendored by RustCrypto):

**nRF52840 (Cortex-M4 @ 64 MHz)**

| Operation | fiat-crypto | mcu-crypto-asm | Emill | Speedup vs fiat |
|---|---|---|---|---|
| P-256 `mul_mont` | 2 238 | **824** | **392** | **2.71x** |
| P-256 `sqr_mont` | 2 080 | **793** | — | **2.62x** |
| P-256 `Point::add` | 36 137 | **17 085** | — | **2.11x** |
| P-384 `mul_mont` | 3 858 | **1 474** | — | **2.61x** |
| P-384 `sqr_mont` | 3 507 | **1 426** | — | **2.45x** |
| P-384 `Point::add` | 64 174 | **30 131** | — | **2.12x** |

**ESP32-S3 (Xtensa LX7 @ 240 MHz)**

| Operation | fiat-crypto | mcu-crypto-asm | Speedup vs fiat |
|---|---|---|---|
| P-256 `mul_mont` | 2 795 | **1 272** | **2.20x** |
| P-384 `mul_mont` | 8 538 | **2 884** | **2.96x** |

### High-Level Operations (nRF52840 @ 64 MHz)

| Operation | P-256 Cycles | P-256 Time | P-384 Cycles | P-384 Time |
|---|---|---|---|---|
| Comb Base Mul (`k*G`) | 1 530 713 | **23 ms** | 3 970 297 | **62 ms** |
| `derive_public_key` | 1 807 503 | **28 ms** | 4 570 000 | **71 ms** |
| `decompress_point` | 586 288 | **9 ms** | 1 328 107 | **21 ms** |
| `ECDSA sign` | 3 035 547 | **47 ms** | 7 621 429 | **119 ms** |
| `ECDSA verify` | 8 961 720 | **140 ms** | 22 977 261 | **359 ms** |
| ECDH Shared Secret (`k*P`) | 5 909 009 | **92 ms** | 15 354 470 | **239 ms** |

---

## Constant Time & Verification

All operations execute in strictly constant time with zero operand-dependent branches or memory lookup tables. Verification uses three complementary layers:

1. **Static Assembly Audit** (`cargo test --test constant_time`): Verifies generated assembly contains zero branches, all loads use fixed `[reg, #imm]` offsets, and only constant-latency instructions are used.
2. **Dynamic Hardware Timing** (`harness/src/bin/ct.rs`): Tests diverse operand classes against same-input controls on real silicon using DWT CYCCNT.
3. **Instruction Tracing** (`harness/src/bin/scantrace.rs`): QEMU single-step execution tracing diffs PC execution traces to prove identical instruction sequences across inputs.

> **Security Note**: Constant time is guaranteed with respect to secret scalars and field element values. Not hardened against physical side-channels (power/EM) or fault injection. Cortex-M3 is deliberately excluded due to its variable-latency multiplier.

---

## Non-Blocking Async Execution

On single-core MCUs, blocking for 20–240 ms stalls the executor and drops radio/BLE deadlines. The yielding APIs cooperatively pause execution with zero async runtime dependencies:

```rust
// Yielding ECDH: yields every ~640 µs, total overhead < 0.2%
let shared = shared_secret_yielding(&p384::CURVE, &secret, &peer_pk, 1).await?;

// Or drive via state machine:
let mut sm = ScalarMul::new(&p384::CURVE, &point, &k);
while sm.step(&p384::CURVE, 4).is_none() { /* yield / poll hardware */ }
```

| Operation | Blocking Duration | Longest Uninterrupted Chunk (`budget = 1`) |
|---|---|---|
| P-256 `k*P` | 92 ms | **345 µs** |
| P-384 `k*P` | 239 ms | **640 µs** |

---

## Design Highlights

- **Unrolled FIOS Montgomery Multiplication**: Fused Inversion-Output-Shift minimizes memory roundtrips, fully unrolled to eliminate branch overhead.
- **Target-Specific Assembly**:
  - **Cortex-M4 / M7 / M33**: Uses 1-cycle `UMAAL` instructions (`RdHi:RdLo = Rn*Rm + RdHi + RdLo`).
  - **Xtensa LX7**: Synthesizes branchless carry chains using `SALTU`.
- **Complete Projective Formulas**: Renes-Costello-Batina complete addition formulas ($a = -3$) eliminate special cases for point doubling vs addition.
- **Fixed-Base Comb**: Precomputed tables accelerate base point multiplication (`k*G`) down to 23 ms (P-256) / 62 ms (P-384).
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
NISTP_MEMORY_X=memory-nrf-ram.x cargo build --release --bin bench
probe-rs run --chip nRF52840_xxAA target/thumbv7em-none-eabihf/release/bench
```

**STM32H563 (Cortex-M33):**
```sh
# Correctness harness (KATs + differential testing):
NISTP_MEMORY_X=memory-stm32h5-ram.x cargo build --release --target thumbv8m.main-none-eabihf --bin nistp-harness
probe-rs run --chip STM32H563ZI target/thumbv8m.main-none-eabihf/release/nistp-harness

# Cycle benchmarks:
NISTP_MEMORY_X=memory-stm32h5-ram.x cargo build --release --target thumbv8m.main-none-eabihf --bin bench
probe-rs run --chip STM32H563ZI target/thumbv8m.main-none-eabihf/release/bench
```

*(To flash to internal Flash at `0x08000000`, build with `NISTP_MEMORY_X=memory-stm32h5.x`.)*

---

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
