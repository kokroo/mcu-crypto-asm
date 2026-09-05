# `mcu-crypto-asm` Algorithm Optimization Roadmap & TODO Tracker

This document tracks candidate cryptographic algorithms, target microarchitectures (based on the [Teleprobe test farm](https://teleprobe.embassy.dev/) and Espressif ecosystems), prior art / reference assembly implementations, and prioritized implementation tasks.

---

## 1. Hardware Architecture Tiers (Teleprobe + Espressif)

All 42 microcontroller boards in the Teleprobe test farm plus modern IoT chips (ESP32-S3, ESP32-C6) map into five distinct execution tiers:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ Tier 1: ARMv7E-M & ARMv8-M Mainline with DSP                                    │
│ Hardware: Single-cycle UMAAL (32x32 + 32 + 32 -> 64), SIMD packed arithmetic    │
│ Chips: nRF52840, nRF52832, nRF5340, nRF9160, nRF54L15, STM32F4, G4, L4, WB,    │
│        WL, H7 (M7 dual-issue), STM32H5 (M33), U5, L5, WBA, RP2350 (M33), MCXA   │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Tier 2: ARMv7-M                                                                 │
│ Hardware: Full Thumb-2, 32x32->64 UMULL/UMLAL (3-5 cycles). NO UMAAL.           │
│ Chips: STM32F103 (Blue Pill), STM32F207, STM32L152                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Tier 3: ARMv6-M                                                                 │
│ Hardware: 16-bit Thumb-1 only, 32x32->32 MULS only. NO 64-bit mul. High spills. │
│ Chips: RP2040 (Raspberry Pi Pico), nRF51, STM32C0, G0, L0, F0, U0               │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Tier 4: Cadence Xtensa (LX6 / LX7)                                              │
│ Hardware: 32-bit windowed registers (a0-a15), MULUH, zero-overhead LOOP.        │
│           ESP32-S3 adds PIE 128-bit SIMD / vector extensions.                   │
│ Chips: ESP32, ESP32-S2, ESP32-S3                                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Tier 5: RISC-V (RV32IMAC / Zk)                                                  │
│ Hardware: 32 orthogonal registers, MUL/MULHU. ESP32-C6/P4 add Zk crypto ext.   │
│ Chips: RP2350 (Hazard3 core), ESP32-C3, ESP32-C6, ESP32-P4, nRF54L coprocessor │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Algorithm Optimization Matrix

| Algorithm | Standard / Protocols | Core Bottleneck | Tier 1 (M4/M7/M33) | Tier 2 (M3) | Tier 3 (M0/M0+) | Tier 4 (Xtensa S3) | Tier 5 (RISC-V) | Priority |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **NIST P-256** | TLS 1.3, BLE, Matter | 256-bit Comba $\mathbb{F}_p$, windowed scalarmul, mod $n$ inv | **DONE** (406c mul, 61k inv) | 1.8x–2.5x | **4.0x–7.0x** | 2.0x–3.0x | 2.2x–3.5x | Port to M0+/Xtensa |
| **NIST P-384** | CNSA Suite, TLS 1.3 | 384-bit field mul, comb scalarmul | **DONE** (1,366c mul, 3.3M comb) | 2.0x–3.0x | **5.0x–8.0x** | 2.5x–3.5x | 2.5x–4.0x | Port to Xtensa/RISC-V |
| **Curve25519 / X25519** | WireGuard, SSH, TLS 1.3 | $\mathbb{F}_{2^{255}-19}$ mul & sqr, Montgomery ladder | **3.5x–5.0x** (~650k cycles) | 2.2x–3.0x | **5.0x–9.0x** | 2.5x–3.5x | 2.5x–4.0x | **P0 (Highest)** |
| **Ed25519** | SSH, Signal, Matter | $\mathbb{F}_{2^{255}-19}$ point ops, scalar reduction mod $\ell$ | **3.0x–4.5x** | 2.0x–2.8x | **4.5x–8.0x** | 2.2x–3.2x | 2.2x–3.5x | **P0 (Highest)** |
| **Poly1305** | WireGuard, TLS 1.3 | Inner loop mod $2^{130}-5$ multiply-add | **4.0x–6.0x** (**~2.5 c/byte**) | 2.5x–3.5x | **5.0x–8.0x** | 3.0x–4.0x | 3.0x–4.5x | **P0 (Highest)** |
| **ChaCha20** | WireGuard, TLS 1.3 | 32-bit ARX quarter-rounds, 16 state words | **1.8x–2.5x** (Keep state in regs) | 1.5x–2.0x | **2.5x–4.0x** | 1.8x–2.5x | 1.8x–2.5x | **P1 (High)** |
| **RSA-2048 / 4096** | Secure Boot, PKI, TLS | Large-integer modular exp, Montgomery reduction | **3.0x–5.0x** (Emill bignum) | 2.0x–3.0x | 3.5x–6.0x | 2.5x–3.5x | 2.5x–3.5x | **P1 (High)** |
| **secp256k1** | Bitcoin, Ethereum, Hardware Wallets | $\mathbb{F}_{2^{256}-2^{32}-977}$ mul, GLV endomorphism | **3.0x–4.5x** (GLV halves doubles) | 2.0x–2.8x | **4.0x–7.0x** | 2.2x–3.0x | 2.2x–3.2x | **P1 (High)** |
| **ML-KEM (Kyber)** | Post-Quantum KEM (FIPS 203) | NTT mod 3329, Barrett reduction | **3.5x–6.0x** (Dual SIMD butterfly)| 1.8x–2.2x | 2.0x–3.0x | 2.0x–3.0x | 2.0x–3.5x | **P1 (PQC Top)** |
| **ML-DSA (Dilithium)** | Post-Quantum Sig (FIPS 204) | NTT mod $2^{23}-2^{13}+1$, matrix-vector mul | **3.0x–5.0x** (SIMD butterfly) | 1.6x–2.0x | 2.0x–2.8x | 2.0x–3.0x | 2.0x–3.5x | **P2 (Medium)** |
| **SHA-512 / SHA-384** | Ed25519, P-384, Hashes | 64-bit ARX on 32-bit registers, high register pressure | **2.2x–3.5x** (LDRD/STRD + rotates) | 1.8x–2.5x | **3.5x–5.5x** | 2.0x–3.0x | 2.0x–3.0x | **P1 (High)** |
| **Keccak / SHAKE** | ML-KEM, ML-DSA, Ethereum | 1600-bit state (25x 64-bit lanes) | **2.5x–4.0x** (32-bit interleaved) | 1.8x–2.5x | **3.0x–5.0x** | 2.0x–3.2x | 2.0x–3.5x | **P1 (PQC Core)** |
| **Bitsliced AES** | Constant-Time AES | Non-linear S-box via Boolean expressions over $GF(2^8)$ | **2.5x–4.5x** (No cache side-channels) | 2.0x–3.5x | **3.0x–5.0x** | 2.0x–3.5x | 1.5x *(10x Zk)* | **P2 (Medium)** |
| **GHASH (GCM)** | AES-GCM Authentication | 128-bit carryless polynomial multiplication in $\mathbb{F}_{2^{128}}$ | **2.5x–4.0x** (Karatsuba / 4-bit table) | 1.8x–2.5x | **3.0x–5.0x** | 2.0x–3.0x | 1.8x *(8x Zbkc)*| **P2 (Medium)** |

---

## 3. Reference Implementations & Prior Art Survey

### 3.1. Emill Repositories
- **[`Emill/P256-Cortex-M4`](https://github.com/Emill/P256-Cortex-M4)** (BSD-2-Clause / MIT)
  - *Status*: Partially vendored in `third_party/emill`.
  - *Highlights*: Hand-written Cortex-M4 assembly using `UMAAL` for P-256 field multiplication (`P256_mulmod` @ 406 cycles), squarings (`P256_sqrmod` @ 358 cycles), modular addition/subtraction, affine table lookups, and complete Jacobian point arithmetic.
- **[`Emill/P256-cortex-ecdh`](https://github.com/Emill/P256-cortex-ecdh)** (BSD-2-Clause)
  - *Status*: Reference for Cortex-M0/M0+ support.
  - *Highlights*: Contains `P256-cortex-m0-ecdh-gcc.s`. Achieves P-256 ECDH in **4,457k to 5,764k cycles on pure Cortex-M0** (translates to ~33–43 ms on RP2040 @ 133 MHz!). Also provides size-optimized and speed-optimized Cortex-M4 variants.
- **[`Emill/rsa-armv7`](https://github.com/Emill/rsa-armv7)** (BSD-2-Clause)
  - *Status*: High-priority candidate for RSA integration.
  - *Highlights*: Highly optimized ARMv7E-M / Cortex-M33 bignum engine (`bignum_asm.S`). Implements RSAES-PKCS1-v1_5, RSASSA-PKCS1-v1_5, and RSASSA-PSS (TLS 1.3 compatible) with CRT optimization. RSA-2048 public verify takes ~1.03M cycles; private sign is ~46M cycles with constant memory access patterns.

### 3.2. Curve25519 & Ed25519
- **`fe25519` by Dideriksen et al. / Schwabe** (Public Domain / CC0):
  - *Architectures*: Cortex-M4 / Cortex-M33.
  - *Technique*: 10 unsaturated 25.5-bit limbs with `UMAAL`. Computes X25519 in **~620,000–650,000 cycles** (~10 ms @ 64 MHz on nRF52840).
- **"Curve25519 on Cortex-M0" by Haase & Labrique (CHES 2014)**:
  - *Architectures*: Cortex-M0 / Cortex-M0+ (RP2040).
  - *Technique*: Multi-precision Karatsuba and Comba designed to avoid register spills on `r0`–`r7`. Computes X25519 in **~3.5M cycles** (~26 ms on RP2040).
- **`lib25519` / SUPERCOP / Stoffelen (2019)**:
  - *Architectures*: RISC-V RV32IM.
  - *Technique*: Branchless Montgomery ladder in ~1.8M cycles on 32-bit RISC-V cores.

### 3.3. Poly1305 & ChaCha20
- **`poly1305-donna` / `poly1305-armv6` by Andrew Moon (Floodyberry)** (MIT / Public Domain):
  - *Architectures*: ARMv6, ARMv7, Cortex-M4.
  - *Technique*: Uses `UMAAL` to accumulate into 44-bit limbs. Evaluates Poly1305 in **~2.2–2.5 cycles/byte** on Cortex-M4.
- **OpenSSL `chacha-armv4.S`**:
  - *Architectures*: Thumb-2 / ARMv7-M / Cortex-M4.
  - *Technique*: Unrolls two quarter-rounds and holds all 16 state words in registers without stack spills (~16 cycles/byte).

### 3.4. secp256k1
- **`micro-ecc` by Kenneth MacKay** (BSD-2-Clause):
  - *Architectures*: Cortex-M0 (`uECC_arm_m0.inc`) and Cortex-M4 (`uECC_arm.c`).
  - *Technique*: Compact assembly routines for P-192, P-224, P-256, and secp256k1.
- **`libsecp256k1` (Bitcoin Core)**:
  - *Technique*: Endomorphism-based scalar decomposition (GLV method), replacing a 256-bit scalar multiplication with two parallel 128-bit multi-scalar multiplications, halving point doublings.

### 3.5. Post-Quantum Cryptography (ML-KEM / Kyber & ML-DSA / Dilithium)
- **`PQM4` (Post-Quantum Cryptography for ARM Cortex-M4)** (`https://github.com/mupq/pqm4`) (CC0 / Apache-2.0 / MIT):
  - *Architectures*: Cortex-M4, Cortex-M7, Cortex-M33.
  - *Authors*: Kannwischer, Rijneveld, Schwabe, Stoffelen.
  - *Technique*: Hand-written assembly for Number Theoretic Transform (NTT) using DSP SIMD instructions (`SMLABB`, `SMULBB`, `PKHTB`) to process two 16-bit coefficients simultaneously. Speeds up Kyber and Dilithium by **3.5x–6.0x** over compiled C/Rust.
- **`pqriscv`** (`https://github.com/mupq/pqriscv`):
  - *Architectures*: RISC-V RV32IMAC.

### 3.6. Hashes (SHA-256, SHA-512, Keccak)
- **XKCP (eXtended Keccak Code Package)**:
  - *Technique*: `KeccakP-1600-armv7m-le-gcc.s` with 32-bit interleaved bit-slice representation.
- **OpenSSL `sha512-armv4.S`**:
  - *Technique*: Uses `LDRD`/`STRD` paired register loads and combined rotations to solve 64-bit register pressure on 32-bit ARM cores.

### 3.7. AES (128, 192, 256) & Wide-Key/Wide-Block Ciphers
- **Standard AES (FIPS 197)**: Defines AES-128 (10 rounds), AES-192 (12 rounds), and AES-256 (14 rounds) on a 128-bit block.
- **"AES-512" and Wide Constructs**: FIPS 197 specifies a maximum 256-bit key. In practice, "AES-512" refers to:
  - **AES-XTS-512** (IEEE 1619 / FIPS): Standard for disk/flash encryption, using two 256-bit keys (512-bit total key material: $K_1$ for AES-256 block cipher, $K_2$ for tweak encryption).
  - **Rijndael-256 / Rijndael-512**: The original Rijndael submission supported 256-bit block and key sizes (used in wide-block hashing and MACs).
  - **Kalyna-512 / Threefish-512**: National standard / Skein 512-bit wide block ciphers.
- **Reference Implementations & Prior Art**:
  - **[`Rvch7/Fixslicing-AES`](https://github.com/Rvch7/Fixslicing-AES)** (Alexandre Adomnicăi & Thomas Peyrin, TCHES 2021) (MIT / Public Domain):
    - *Architectures*: ARM Cortex-M (Thumb-2) and RISC-V.
    - *Technique*: Fixslicing eliminates the ShiftRows overhead in classical bitslicing by adjusting the representation each round. Achieves speed records on Cortex-M4: **~63 cycles/byte for AES-128-CTR** in 2-block parallel constant-time assembly.
  - **[`Ko-/aes-armcortexm`](https://github.com/Ko-/aes-armcortexm)** ("All the AES You Need on Cortex-M3 and M4", Peter Schwabe & Ko Stoffelen, SAC 2016) (Public Domain):
    - *Architectures*: Cortex-M3, Cortex-M4.
    - *Technique*: Fast T-table, constant-time bitsliced (2, 4, and 8-block), and **first-order masked bitsliced AES** (provides provable side-channel resistance against DPA/CPA power analysis attacks on microcontrollers!).
  - **[`BearSSL aes_ct.c`](https://bearssl.org/)** (Thomas Pornin) (MIT):
    - *Technique*: 32-bit constant-time bitsliced S-box using Boyar-Peralta logic minimization (only 113–115 boolean gates per S-box). Compact, zero RAM tables, immune to cache attacks.
  - **RISC-V Scalar Cryptography (`Zkne`, `Zknd`)**:
    - *Architectures*: ESP32-C6, ESP32-P4, modern RV32 cores.
    - *Technique*: Hardware round instructions (`aes32esi`, `aes32esmi`, `aes32dsi`, `aes32dsmi`) reduce each AES round to just **4 instructions** (~10–15 cycles/block).
  - **Why Software ASM Matters Even with Hardware Crypto Accelerators**:
    1. *Cache Timing Immunity*: Hardware engines or T-table software leak cache lines on MCUs with data caches (Cortex-M7, ESP32). Bitslicing has zero data-dependent memory lookups.
    2. *Hardware Limitations*: Nordic nRF52/nRF53 hardware ECB only supports AES-128 (no AES-192 or AES-256).
    3. *Zero Peripheral Contention / Re-entrancy*: Hardware engines require RTOS mutexes, peripheral power clocks, and DMA setup; software assembly is purely re-entrant and faster for payloads under 64–128 bytes.

---

## 4. Actionable TODO Tracker

### Phase 1: Port Current NIST P-256 & P-384 to Additional ISAs
- [x] **Cortex-M4 / Cortex-M33 P-256**: Hand-written UMAAL assembly, batch affine table, Bernstein-Yang `mod_n_inv`.
- [x] **Cortex-M4 / Cortex-M33 P-384**: Hand-written 12-limb unrolled UMAAL multiplication, comb scalar mul.
- [x] **Embassy `P256Ops` Driver**: Fully integrated and tested on hardware with zero secret branches.
- [ ] **Cortex-M0 / Cortex-M0+ (RP2040, STM32G0/L0/C0, nRF51) P-256 Backend**:
  - [ ] Vendor or adapt `P256-cortex-m0-ecdh-gcc.s` from `Emill/P256-cortex-ecdh`.
  - [ ] Implement constant-time 16-bit Thumb-1 field arithmetic (`mul`, `sqr`, `add`, `sub`).
  - [ ] Hook into `mcu-crypto-asm` build system with `cfg(target_arch = "arm")` + `cfg(not(target_feature = "dsp"))`.
  - [ ] Benchmark on RP2040 silicon via `probe-rs`.
- [ ] **Xtensa (ESP32 / ESP32-S3) P-256 & P-384 Backend**:
  - [ ] Implement assembly field multiplier exploiting 32-register sliding window (`a0`–`a15`) and `LOOP`.
  - [ ] Benchmark against ESP32-S3 hardware ECC coprocessor.
- [ ] **RISC-V (RP2350 Hazard3, ESP32-C3/C6) P-256 Backend**:
  - [ ] Implement 8-limb Comba multiplication utilizing 32 orthogonal registers.
  - [ ] Add `Zbkc` carryless multiplier path for targets supporting RISC-V Scalar Crypto.

---

### Phase 2: Modern Elliptic Curves (Curve25519 / X25519 & Ed25519)
- [ ] **Curve25519 Field $\mathbb{F}_{2^{255}-19}$ Arithmetic (Cortex-M4 / M33)**:
  - [ ] Implement 10-limb radix-$2^{25.5}$ multiplication and squaring with `UMAAL`.
  - [ ] Implement fast reduction modulo $2^{255}-19$ ($19 \times \text{carry}$).
  - [ ] Constant-time conditional swap (`CSWAP`) using bitwise multiplexing.
- [ ] **X25519 ECDH Protocol (RFC 7748)**:
  - [ ] Constant-time Montgomery ladder (255 steps).
  - [ ] Inversion modulo $2^{255}-19$ via addition chain ($2^{255}-21$).
  - [ ] Target cycle goal: **< 650,000 cycles on Cortex-M4** (< 10.2 ms @ 64 MHz).
- [ ] **Ed25519 Signature Verification & Signing (RFC 8032)**:
  - [ ] Twisted Edwards point addition and doubling in extended projective coordinates $(X:Y:Z:T)$.
  - [ ] Fixed-base comb multiplication for base point $B$.
  - [ ] Scalar reduction modulo $\ell = 2^{252} + 27742317777372353535851937790883648493$.

---

### Phase 3: High-Speed Symmetric AEAD (Poly1305 & ChaCha20)
- [ ] **Poly1305 One-Time Authenticator (RFC 8439)**:
  - [ ] Implement ARMv7E-M / Cortex-M33 assembly inner loop using `UMAAL`.
  - [ ] Target throughput goal: **~2.5 cycles/byte** on nRF52840 / STM32H5.
  - [ ] Implement constant-time clamping and final reduction modulo $2^{130}-5$.
  - [ ] Host and target KAT test vectors from RFC 8439.
- [ ] **ChaCha20 Stream Cipher**:
  - [ ] Implement ARM assembly block function holding all 16 state words in registers without stack spills.
  - [ ] Add 32-bit interleaved parallel blocks for cores with extra registers or dual-issue (M7).

---

### Phase 4: Big-Integer Modular Exponentiation & RSA
- [ ] **Integrate `Emill/rsa-armv7` Bignum Engine**:
  - [ ] Vendor `bignum_asm.S` and review Montgomery multiplication routines.
  - [ ] Create Rust `no_std` wrapper for generic big-integer modular exponentiation ($a^b \pmod n$).
  - [ ] Support RSA-2048 and RSA-4096 public operations (verification) and CRT private operations (signing).
  - [ ] Implement constant memory access pattern mode for cached architectures.
  - [ ] Implement RSASSA-PSS signature verification compatible with TLS 1.3.

---

### Phase 5: Post-Quantum Cryptography (NIST FIPS 203 & 204)
- [ ] **ML-KEM (Kyber-512 / 768 / 1024) Cortex-M4 / M33 NTT Acceleration**:
  - [ ] Vendor / adapt PQM4's hand-written SIMD NTT butterflies (`SMLABB`/`PKHTB`).
  - [ ] Fast Barrett and Montgomery reduction modulo $q = 3329$.
  - [ ] Target cycle goal: **< 600,000 cycles for Kyber-768 decapsulation**.
- [ ] **ML-DSA (Dilithium-2 / 3 / 5) NTT Acceleration**:
  - [ ] Adapt PQM4's SIMD NTT for modulus $q = 8380417$.
  - [ ] Fast polynomial matrix-vector multiplication.

---

### Phase 6: Hashes & Symmetric Primitives
- [ ] **SHA-512 / SHA-384 Assembly**:
  - [ ] ARMv7E-M assembly implementation pairing 32-bit registers for 64-bit words via `LDRD`/`STRD`.
  - [ ] Eliminates compiler register spills, speeding up Ed25519 and P-384 certificate parsing.
- [ ] **Keccak-f[1600] / SHAKE-128 / SHAKE-256**:
  - [ ] Integrate 32-bit interleaved bit-sliced ARM assembly (from XKCP).
  - [ ] Critical performance driver for ML-KEM and ML-DSA hash operations.
- [ ] **Constant-Time Bitsliced & Fixsliced AES-128, AES-192, AES-256**:
  - [ ] Implement Adomnicăi-Peyrin 2-block parallel **Fixsliced AES** on ARM Cortex-M4/M33 (target **~63 cycles/byte** in CTR mode).
  - [ ] Implement constant-time Boyar-Peralta S-box (113–115 gates) for memory-constrained MCUs (RP2040 Cortex-M0+).
  - [ ] Implement **first-order masked bitsliced AES** (Schwabe-Stoffelen) for power-analysis / DPA resistance on secure embedded tokens.
  - [ ] Support AES-XTS (256-bit and 512-bit key material) for encrypted firmware partitions and external flash.
  - [ ] Add RISC-V `Zkne`/`Zknd` scalar crypto instructions backend for ESP32-C6 / ESP32-P4.
