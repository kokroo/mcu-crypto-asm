# mcu-crypto-asm

**Hand-written assembly cryptography for 32-bit microcontrollers** — constant-time, `no_std`, zero allocator, zero dependencies.

Fast assembly kernels for **P-256 and P-384** on **ARM Cortex-M4/M7/M33** and **Xtensa LX7** (ESP32-S2/S3), tested against Wycheproof with a clean portable Rust fallback for any other 32-bit target. All benchmarks are verified on silicon.

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

For the full test matrix (NIST CAVP/ACVP, RFC KATs, Project Wycheproof), multi-ISA QEMU validation, and Embassy Teleprobe HIL execution, see [TESTS.md](TESTS.md).

```sh
# Host tests (portable reference, BigInt oracle, constant-time audit, CAVP, RFC, Wycheproof)
cargo test

# QEMU bare-metal test suite across targets
cargo qtest --target thumbv7em-none-eabihf --test crypto_kats
cargo qtest --target thumbv7m-none-eabi --test crypto_kats
cargo qtest --target thumbv6m-none-eabi --test crypto_kats
cargo qtest --target riscv32imac-unknown-none-elf --test crypto_kats

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

## Attribution & Provenance Matrix

`mcu-crypto-asm` combines **original hand-written assembly** engineered specifically for this project with **ports and adaptations of state-of-the-art open-source assembly routines** from the cryptographic community. All original authors and upstream projects are credited below:

| Primitive | Target Architecture / ISA | Component / Routine | Author(s) & Provenance | License |
| :--- | :--- | :--- | :--- | :--- |
| **NIST P-256** | **Target 5** (Xtensa LX7: ESP32-S2/S3) | Branchless `SALTU` Montgomery multiplication (`nistp_mul_mont_8`), squaring (`nistp_sqr_mont_8`), and modular add/sub (Windowed & Call0 ABIs) | **Shiv Kokroo** (Original ASM) | BSD-3-Clause |
| **NIST P-256** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Inversionless Projective ECDSA verification ($r \cdot Z^2 \equiv X \pmod p$), Interleaved Double-Scalar Multiplication (Shamir's Trick), Fixed-Base Comb Tables | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **NIST P-256** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Montgomery `UMAAL` field multiplication (`P256_mulmod`), squaring (`P256_sqrmod`), add/sub, affine tables (`asm/cortex_m4_p256.S`) | **Emil Lenngren** ([`Emill/P256-Cortex-M4`](https://github.com/Emill/P256-Cortex-M4)) & Shortcut Labs AB | BSD-2-Clause / MIT |
| **NIST P-256** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Pure 16-bit Thumb-1 field arithmetic (`asm/cortex_m0_p256.S`) | **Emil Lenngren** ([`Emill/P256-cortex-ecdh`](https://github.com/Emill/P256-cortex-ecdh)); mul/sqr based on µNaCl by Ana Helena Sánchez & Björn Haase | BSD-2-Clause / Public Domain |
| **NIST P-384** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | 12-limb unrolled `UMAAL` Montgomery multiplication (`nistp_mul_mont_12`), squaring, add/sub with VFP register allocation (`asm/cortex_m4.S`, `gen/gen_asm_cortex_m4.py`) | **Shiv Kokroo** (Original ASM) | BSD-3-Clause |
| **NIST P-384** | **Target 5** (Xtensa LX7: ESP32-S2/S3) | 12-limb unrolled branchless `SALTU` Montgomery multiplication (`nistp_mul_mont_12`), squaring, modular add/sub (Windowed & Call0 ABIs) | **Shiv Kokroo** (Original ASM) | BSD-3-Clause |
| **NIST P-384** | All MCU Targets | 12-limb Comb fixed-base multiplication (3.3M cycles) & Projective ECDSA verification | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **Curve25519 / X25519** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Constant-time field arithmetic (`cortex_m_fe25519.S`) and scalar multiplication (`cortex_m_curve25519.S`) | **Emil Lenngren** ([`Emill/X25519-Cortex-M4`](https://github.com/Emill/X25519-Cortex-M4)) & Akiles Technologies / Dario Nieuwenhuis ([`embassy-rs/cortex25519`](https://github.com/embassy-rs/cortex25519)) | BSD-2-Clause |
| **Curve25519 / X25519** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Constant-time pure 16-bit Thumb-1 X25519 scalar multiplication (`asm/cortex_m0_curve25519.S`) | **Thomas Pornin** ([`pornin/x25519-cm0`](https://github.com/pornin/x25519-cm0) / BearSSL); ported by Shiv Kokroo | MIT |
| **Ed25519** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Extended twisted Edwards point operations (`asm/cortex_m_ed25519.S`) | **Akiles Technologies** & Dario Nieuwenhuis ([`embassy-rs/cortex25519`](https://github.com/embassy-rs/cortex25519)) | BSD-2-Clause |
| **Ed25519** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Constant-time Edwards arithmetic, RFC 8032 square-root decompression, 256-bit scalar mul | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **secp256k1** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Multi-precision `UMAAL` multiplication engine (`asm/cortex_m_bignum.S`) | **Emil Lenngren** ([`Emill/rsa-armv7`](https://github.com/Emill/rsa-armv7)) | BSD-2-Clause |
| **secp256k1** | **Target 1** & **Target 2** | Solinas reduction ($2^{256}-2^{32}-977$), complete Renes-Costello-Batina ($a=0$) addition, Comba multiplier engine, Montgomery ladder | **Shiv Kokroo** (Original Implementation; inspiration from Kenneth MacKay / [`micro-ecc`](https://github.com/kmackay/micro-ecc)) | BSD-3-Clause |
| **Poly1305** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | 26-bit limb constant-time multiplication using `UMLAL` (`asm/cortex_m_poly1305.S`) | **Andrew Moon** ([`floodyberry/poly1305-opt`](https://github.com/floodyberry/poly1305-opt), [`poly1305-donna`](https://github.com/floodyberry/poly1305-donna)) | MIT / Public Domain |
| **Poly1305** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Constant-time 32-bit Poly1305 evaluation (~127 c/byte) | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **ChaCha20** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Register-packed quarter-round unrolled block assembly (`asm/cortex_m_chacha20.S`) | **Mick de Pauw** ([`Mickdep/ChaCha20-Optimization`](https://github.com/Mickdep/ChaCha20-Optimization)) & **Andy Polyakov** ([OpenSSL](https://github.com/openssl/openssl)) | MIT / Apache-2.0 |
| **ChaCha20** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Constant-time 32-bit quarter-round implementation | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **RSA-1024 / 2048 / 4096** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Bignum Montgomery multiplication & squaring engine (`asm/cortex_m_bignum.S`) | **Emil Lenngren** ([`Emill/rsa-armv7`](https://github.com/Emill/rsa-armv7)) | BSD-2-Clause |
| **RSA-1024 / 2048 / 4096** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Constant-time CIOS Montgomery reduction engine | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **ML-KEM (Kyber)** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Plantard arithmetic and DSP SIMD NTT/InvNTT/Basemul assembly (`asm/cortex_m_mlkem.S`) | **Junhao Huang** ([eprint 2022/956](https://eprint.iacr.org/2022/956.pdf)) & **PQM4 Contributors** ([`mupq/pqm4`](https://github.com/mupq/pqm4)) | CC0 / Apache-2.0 |
| **ML-KEM (Kyber)** | All MCU Targets | Safe `Polynomial` API, 12-bit serialization, ring arithmetic | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **ML-DSA (Dilithium)** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | DSP SIMD NTT/InvNTT and pointwise Montgomery multiplication (`asm/cortex_m_mldsa.S`) | **Amin Abdulrahman, Vincent Hwang, Nele Mentens, Julian Wälde** ([`mupq/pqm4`](https://github.com/mupq/pqm4)) | CC0 / Apache-2.0 |
| **ML-DSA (Dilithium)** | All MCU Targets | Safe `Polynomial` API, Montgomery reduction, pointwise accumulation | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **SHA-512 / SHA-384** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | Paired 32-bit register assembly compression function (`asm/cortex_m_sha512.S`) | **Andy Polyakov** & **The OpenSSL Project Authors** ([OpenSSL `sha512-armv4.pl`](https://github.com/openssl/openssl)) | Apache-2.0 / OpenSSL |
| **SHA-512 / SHA-384** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Boolean logic minimization for 64-bit word pairs | **Thomas Pornin** ([`BearSSL`](https://bearssl.org/)) & **Shiv Kokroo** | MIT / BSD-3-Clause |
| **Keccak-f[1600] / SHAKE** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | 32-bit interleaved bit-sliced ARM assembly (`asm/cortex_m_keccak.S`) | **Alexandre Adomnicăi** ([eprint 2023/773](https://eprint.iacr.org/2023/773)); based on Ronny Van Keer / [XKCP](https://github.com/XKCP/XKCP) | CC0 / Apache-2.0 / MIT |
| **Keccak-f[1600] / SHAKE** | All MCU Targets | FIPS 202 sponge implementation (SHA3-256/512, SHAKE-128/256) | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **Fixsliced AES** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | 2-block parallel Fixsliced AES-128 and AES-256 encryption (`asm/cortex_m_aes_encrypt.S`, `asm/cortex_m_aes_keyschedule.S`) | **Alexandre Adomnicăi** & **Thomas Peyrin** ([`Rvch7/Fixslicing-AES`](https://github.com/Rvch7/Fixslicing-AES)) | MIT |
| **Bitsliced AES** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Constant-time Boyar-Peralta S-box bitsliced AES (0 RAM tables) | **Thomas Pornin** ([`BearSSL`](https://bearssl.org/)) | MIT |
| **AES Cipher Modes** | All MCU Targets | Constant-time ECB, CBC, CTR, GCM cipher modes | **Shiv Kokroo** (Original Implementation) | BSD-3-Clause |
| **GHASH (GCM)** | **Target 1** (ARMv7E-M / ARMv8-M: Cortex-M4/M7/M33) | 4-bit windowed GF(2^128) polynomial multiplier (`asm/cortex_m_ghash.S`) | **Andy Polyakov** & **The OpenSSL Project Authors** ([OpenSSL `ghash-armv4.pl`](https://github.com/openssl/openssl) / CRYPTOGAMS) | Apache-2.0 / Cryptogams BSD |
| **GHASH (GCM)** | **Target 2** (ARMv6-M: Cortex-M0/M0+) | Constant-time 32-bit Karatsuba polynomial multiplier (`ghash_ctmul32`) | **Thomas Pornin** ([`BearSSL`](https://bearssl.org/)) | MIT |
| **Multi-Target Architecture** | All Supported Targets | Target dispatch layer, trait abstraction, and Embassy cryptographic driver framework (`src/embassy.rs`, `src/backend/`) | **Shiv Kokroo** (Original Architecture) | BSD-3-Clause |

---

## Licence

This project is licensed under the **BSD 3-Clause License**. See [LICENSE](LICENSE) for the full license text.

### Mandatory Attribution
The BSD 3-Clause license strictly mandates that copyright notices and attribution to **Shiv Kokroo**, project contributors, and original upstream authors must be retained and reproduced in **both source code distributions and compiled binary distributions** (such as firmware images, embedded binaries, SDKs, and accompanying documentation) no matter how it is redistributed.

For detailed attribution of original works and third-party upstream components, see [NOTICE](NOTICE) and [AUTHORS.md](AUTHORS.md).
