# `mcu-crypto-asm` Target vs. Algorithm Optimization Matrix & Roadmap

This document defines the architectural target tiers for embedded microcontroller cryptography, establishes the comprehensive **Target vs. Algorithm Matrix**, and tracks active implementation progress.

---

## 1. Architectural Target Tiers

All microcontroller hardware platforms cluster into five distinct architectural execution targets based on instruction set architecture (ISA), register file structure, and hardware arithmetic primitives:

| Target | Architecture / ISA | Processor Cores | Key Arithmetic & Microarchitectural Hardware Primitives |
| :--- | :--- | :--- | :--- |
| **Target 1** | **ARMv7E-M / ARMv8-M Mainline** | Cortex-M4, Cortex-M7, Cortex-M33 | Single-cycle **`UMAAL`** ($R_{lo}, R_{hi} \leftarrow a \times b + R_{lo} + R_{hi}$), DSP SIMD (`SMLABB`, `PKHTB`). Full Thumb-2 carry chains (`ADCS`). |
| **Target 2** | **ARMv6-M** | Cortex-M0, Cortex-M0+ | 16-bit Thumb-1 only. **No 64-bit multiplier** (32×32$\to$32 `MULS` only). High register pressure restricted to low registers `r0`–`r7`. |
| **Target 3** | **ARMv7-M** | Cortex-M3 | Full Thumb-2 instruction set with 32×32$\to$64 `UMULL`/`UMLAL` (3–5 cycles) and `ADCS` carry chains. **No `UMAAL`**. |
| **Target 4** | **RISC-V 32-bit (RV32IMAC / Zk)** | RV32IMAC cores | 32 orthogonal registers (`x0`–`x31`), hardware 32×32$\to$64 multiply (`MUL`/`MULH`/`MULHU`). Optional Scalar Cryptography (`Zk`/`Zbkc`). |
| **Target 5** | **Cadence Xtensa (LX6 / LX7)** | Xtensa LX6, Xtensa LX7 | 32-bit windowed registers (`a0`–`a15`), `MULUH`, zero-overhead `LOOP`. LX7 adds branchless `SALTU` carry emulation; optional MAC16 40-bit accumulator. |

---

## 2. Target vs. Algorithm Matrix

| Algorithm | Standard / Category | Target 1<br>(ARMv7E-M / ARMv8-M) | Target 2<br>(ARMv6-M) | Target 3<br>(ARMv7-M) | Target 4<br>(RISC-V RV32) | Target 5<br>(Xtensa LX6 / LX7) | Implementation Status / Priority |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **NIST P-256** | TLS 1.3, BLE, Matter | ✅ **DONE**<br>(406c mul, 61k inv) | ✅ **DONE**<br>(400ms ECDH @ 12MHz) | [Emill P256-M3](https://github.com/Emill/P256-cortex-ecdh)<br>*(1.8×–2.5×)* | [micro-ecc RV32](https://github.com/kmackay/micro-ecc)<br>*(2.2×–3.5×)* | ✅ **DONE**<br>(1,274c mul, 2.19×) | ✅ **Production** (T1, T2, T5 Done) |
| **NIST P-384** | CNSA Suite, TLS 1.3 | ✅ **DONE**<br>(1,366c mul, 3.3M comb) | *No ASM prior art*<br>*(C fallback, 5–8×)* | [fiat-crypto](https://github.com/mit-plv/fiat-crypto)<br>*(2.0×–3.0×)* | [fiat-crypto](https://github.com/mit-plv/fiat-crypto)<br>*(2.5×–4.0×)* | ✅ **DONE**<br>(2,886c mul, 2.96×) | ✅ **Production** (T1, T5 Done; T4 next) |
| **Curve25519 / X25519** | WireGuard, SSH, TLS 1.3 | ✅ **DONE**<br>(~550k cycles, 8.6ms) | ✅ **DONE**<br>(269ms @ 12MHz, 3.2M cyc) | [cortex25519](https://github.com/embassy-rs/cortex25519)<br>*(2.2×–3.0×)* | [Ko-/lib25519](https://github.com/Ko-/lib25519)<br>*(1.8M cyc, 2.5–4×)* | [aCinal/esp-x25519](https://github.com/aCinal/esp-x25519)<br>*(MAC16, 2.5–3.5×)* | ✅ **Production** (T1, T2 Done) |
| **Ed25519** | SSH, Signal, Matter | ✅ **DONE**<br>(Point Ops / Scalarmul) | [μNaCl / CHES 2014](https://munacl.cryptojedi.org/)<br>*(4.5×–8.0×)* | [cortex25519](https://github.com/embassy-rs/cortex25519)<br>*(2.0×–2.8×)* | [lib25519](https://lib25519.cr.yp.to/)<br>*(2.2×–3.5×)* | [esp-x25519](https://github.com/aCinal/esp-x25519)<br>*(2.2×–3.2×)* | ✅ **Production** (T1 Done) |
| **Poly1305** | WireGuard, TLS 1.3 | ✅ **DONE**<br>(~17 c/byte total) | [poly1305-donna](https://github.com/floodyberry/poly1305-donna)<br>*(armv6, 5–8×)* | [poly1305-donna](https://github.com/floodyberry/poly1305-donna)<br>*(2.5×–3.5×)* | [riscv-crypto](https://github.com/riscv/riscv-crypto)<br>*(3.0×–4.5×)* | [poly1305-donna](https://github.com/floodyberry/poly1305-donna)<br>*(3.0×–4.0×)* | ✅ **Production** (T1 Done) |
| **ChaCha20** | WireGuard, TLS 1.3 | ✅ **DONE**<br>(~30 c/byte bare-metal) | [chacha-opt](https://github.com/floodyberry/chacha-opt)<br>*(armv6, 2.5–4×)* | [OpenSSL chacha](https://github.com/openssl/openssl/blob/master/crypto/chacha/asm/chacha-armv4.pl)<br>*(1.5×–2.0×)* | [riscv-crypto](https://github.com/riscv/riscv-crypto)<br>*(1.8×–2.5×)* | [chacha-opt](https://github.com/floodyberry/chacha-opt)<br>*(1.8×–2.5×)* | ✅ **Production** (T1 Done) |
| **RSA-2048 / 4096** | Secure Boot, PKI, TLS | ✅ **DONE**<br>(345k cycles RSA-2048) | [BearSSL rsa_i15](https://bearssl.org/)<br>*(3.5×–6.0×)* | [Emill/rsa-armv7](https://github.com/Emill/rsa-armv7)<br>*(2.0×–3.0×)* | [riscv-crypto](https://github.com/kostoffelen/riscv-crypto)<br>*(2.5×–3.5×)* | [BearSSL rsa_i31](https://bearssl.org/)<br>*(2.5×–3.5×)* | ✅ **Production** (T1 Done) |
| **secp256k1** | Bitcoin, Wallets | ✅ **DONE**<br>(~11.7k dbl, 101ms scalarmult) | [micro-ecc m0](https://github.com/kmackay/micro-ecc)<br>*(4.0×–7.0×)* | [micro-ecc arm](https://github.com/kmackay/micro-ecc)<br>*(2.0×–2.8×)* | [libsecp256k1](https://github.com/bitcoin-core/secp256k1)<br>*(2.2×–3.2×)* | [libsecp256k1](https://github.com/bitcoin-core/secp256k1)<br>*(2.2×–3.0×)* | ✅ **Production** (T1 Done) |
| **ML-KEM (Kyber)** | Post-Quantum (FIPS 203) | ✅ **DONE**<br>(5.8kc NTT/InvNTT/Basemul) | *No ASM prior art*<br>*(No SIMD, 2–3×)* | [mupq/pqm4 C](https://github.com/mupq/pqm4)<br>*(1.8×–2.2×)* | [mupq/pqriscv](https://github.com/mupq/pqriscv)<br>*(2.0×–3.5×)* | [esp-dsp](https://github.com/espressif/esp-dsp)<br>*(2.0×–3.0×)* | ✅ **Production** (T1 Done) |
| **ML-DSA (Dilithium)** | Post-Quantum (FIPS 204) | ✅ **DONE**<br>(11.7kc NTT/InvNTT, 3.9kc PW) | *No ASM prior art*<br>*(No SIMD, 2–2.8×)* | [mupq/pqm4 C](https://github.com/mupq/pqm4)<br>*(1.6×–2.0×)* | [mupq/pqriscv](https://github.com/mupq/pqriscv)<br>*(2.0×–3.5×)* | [esp-dsp](https://github.com/espressif/esp-dsp)<br>*(2.0×–3.0×)* | ✅ **Production** (T1 Done) |
| **SHA-512 / SHA-384** | Ed25519, P-384, Hashes | ✅ **DONE**<br>(11.7kc/blk, ~97 cpb)| [BearSSL sha512](https://bearssl.org/)<br>*(3.5×–5.5×)* | [OpenSSL sha512](https://github.com/openssl/openssl/blob/master/crypto/sha/asm/sha512-armv4.pl)<br>*(1.8×–2.5×)* | [riscv-crypto](https://github.com/riscv/riscv-crypto)<br>*(2.0×–3.0×)* | [OpenSSL sha512](https://github.com/openssl/openssl/blob/master/crypto/sha/asm/sha512-armv4.pl)<br>*(2.0×–3.0×)* | ✅ **Production** (T1 Done) |
| **Keccak / SHAKE** | ML-KEM, ML-DSA, Hashes | ✅ **DONE**<br>(15.6k cycles / 24-rnd) | [XKCP armv6m](https://github.com/XKCP/XKCP)<br>*(3.0×–5.0×)* | [XKCP armv7m](https://github.com/XKCP/XKCP)<br>*(1.8×–2.5×)* | [pqriscv keccak](https://github.com/mupq/pqriscv)<br>*(2.0×–3.5×)* | [XKCP generic](https://github.com/XKCP/XKCP)<br>*(2.0×–3.2×)* | ✅ **Production** (T1 Done) |
| **Bitsliced AES** | Constant-Time AES | ✅ **DONE**<br>(Fixsliced AES-128/256) | ✅ **DONE**<br>(~281 c/byte @ 12MHz, 4.4k c/blk) | [Fixslicing-AES](https://github.com/Rvch7/Fixslicing-AES)<br>*(2.0×–3.5×)* | [Fixslicing-AES](https://github.com/Rvch7/Fixslicing-AES)<br>*(10× with [Zk](https://github.com/riscv/riscv-crypto))* | [BearSSL aes_ct](https://bearssl.org/)<br>*(2.0×–3.5×)* | ✅ **Production** (T1, T2 Done) |
| **GHASH (GCM)** | AES-GCM Authentication | ✅ **DONE**<br>(820c/blk, ~51 cpb) | [BearSSL ghash](https://bearssl.org/)<br>*(3.0×–5.0×)* | [OpenSSL ghash](https://github.com/openssl/openssl/blob/master/crypto/modes/asm/ghash-armv4.pl)<br>*(1.8×–2.5×)* | [riscv-crypto](https://github.com/riscv/riscv-crypto)<br>*(8× with [Zbkc](https://github.com/riscv/riscv-crypto))* | [BearSSL ghash](https://bearssl.org/)<br>*(2.0×–3.0×)* | ✅ **Production** (T1 Done) |

---

## 3. Reference Implementations & Prior Art Survey

### 3.1. Emill Repositories
- **[`Emill/P256-Cortex-M4`](https://github.com/Emill/P256-Cortex-M4)** (BSD-2-Clause / MIT)
  - *Status*: Partially vendored in `third_party/emill`.
  - *Highlights*: Hand-written Target 1 assembly using `UMAAL` for P-256 field multiplication (`P256_mulmod` @ 406 cycles), squarings (`P256_sqrmod` @ 358 cycles), modular addition/subtraction, affine table lookups, and complete Jacobian point arithmetic.
- **[`Emill/P256-cortex-ecdh`](https://github.com/Emill/P256-cortex-ecdh)** (BSD-2-Clause)
  - *Status*: Reference for Target 2 (ARMv6-M) support.
  - *Highlights*: Contains `P256-cortex-m0-ecdh-gcc.s`. Achieves P-256 ECDH in **4,457k to 5,764k cycles on pure Target 2** (~33–43 ms @ 133 MHz). Also provides size-optimized and speed-optimized Target 1 variants.
- **[`Emill/rsa-armv7`](https://github.com/Emill/rsa-armv7)** (BSD-2-Clause)
  - *Status*: High-priority candidate for RSA integration.
  - *Highlights*: Highly optimized Target 1 bignum engine (`bignum_asm.S`). Implements RSAES-PKCS1-v1_5, RSASSA-PKCS1-v1_5, and RSASSA-PSS (TLS 1.3 compatible) with CRT optimization. RSA-2048 public verify takes ~1.03M cycles; private sign is ~46M cycles with constant memory access patterns.

### 3.2. Curve25519 & Ed25519
- **[`embassy-rs/cortex25519`](https://github.com/embassy-rs/cortex25519)** (Dario Nieuwenhuis / Dirbaio & Emil Lenngren) (BSD-2-Clause):
  - *Targets*: Target 1 (ARMv7E-M / ARMv8-M Mainline).
  - *Upstream Origin*: Emil Lenngren's [`Emill/X25519-Cortex-M4`](https://github.com/Emill/X25519-Cortex-M4), extended by Embassy to support Ed25519 signature verification.
  - *Highlights*: Contains pure assembly kernels `cortex_m_fe25519.s`, `cortex_m_curve25519.s`, and `cortex_m_ed25519.s`. Tested with Wycheproof vectors in QEMU. Direct drop-in candidate for Target 1 backend.
- **[`aCinal/esp-x25519`](https://github.com/aCinal/esp-x25519)** (Alper Cinal) (MIT):
  - *Targets*: Target 5 (Xtensa LX6 and LX7).
  - *Technique*: Constant-time X25519 optimized for the **Xtensa MAC16** execution unit. Uses 17 15-bit limbs ($17 \times 15 = 255$) to fit into the 40-bit accumulator (`xsr.acclo`, `xsr.acchi`) without intermediate overflows, combined with zero-overhead hardware `loop` instructions.
- **`fe25519` by Dideriksen et al. / Schwabe** (Public Domain / CC0):
  - *Targets*: Target 1.
  - *Technique*: 10 unsaturated 25.5-bit limbs with `UMAAL`. Computes X25519 in **~620,000–650,000 cycles** (~10 ms @ 64 MHz).
- **"Curve25519 on Cortex-M0" by Haase & Labrique (CHES 2014)**:
  - *Targets*: Target 2 (ARMv6-M).
  - *Technique*: Multi-precision Karatsuba and Comba designed to avoid register spills on `r0`–`r7`. Computes X25519 in **~3.5M cycles** (~26 ms @ 133 MHz).
- **[`pornin/x25519-cm0`](https://github.com/pornin/x25519-cm0)** (Thomas Pornin) (MIT):
  - *Targets*: Target 2 (ARMv6-M / Cortex-M0 / Cortex-M0+).
  - *Technique*: Pure 16-bit Thumb-1 assembly for X25519 scalar multiplication, constant-time, achieving **~3.23M cycles**.
- **`lib25519` / SUPERCOP / Stoffelen (2019)**:
  - *Targets*: Target 4 (RISC-V RV32IM).
  - *Technique*: Branchless Montgomery ladder in ~1.8M cycles on 32-bit RISC-V cores.

### 3.3. Poly1305 & ChaCha20
- **`poly1305-donna` / `poly1305-armv6` by Andrew Moon (Floodyberry)** (MIT / Public Domain):
  - *Targets*: Target 1, Target 2, Target 3.
  - *Technique*: Uses `UMAAL` on Target 1 to accumulate into 44-bit limbs. Evaluates Poly1305 in **~2.2–2.5 cycles/byte** on Target 1.
- **OpenSSL `chacha-armv4.S`**:
  - *Targets*: Target 1, Target 3.
  - *Technique*: Unrolls two quarter-rounds and holds all 16 state words in registers without stack spills (~16 cycles/byte).

### 3.4. secp256k1
- **`micro-ecc` by Kenneth MacKay** (BSD-2-Clause):
  - *Targets*: Target 1 (`uECC_arm.c`) and Target 2 (`uECC_arm_m0.inc`).
  - *Technique*: Compact assembly routines for P-192, P-224, P-256, and secp256k1.
- **`libsecp256k1` (Bitcoin Core)**:
  - *Technique*: Endomorphism-based scalar decomposition (GLV method), replacing a 256-bit scalar multiplication with two parallel 128-bit multi-scalar multiplications, halving point doublings.

### 3.5. Post-Quantum Cryptography (ML-KEM / Kyber & ML-DSA / Dilithium)
- **`PQM4` (Post-Quantum Cryptography for ARM Cortex-M4)** (`https://github.com/mupq/pqm4`) (CC0 / Apache-2.0 / MIT):
  - *Targets*: Target 1 (ARMv7E-M / ARMv8-M Mainline).
  - *Authors*: Kannwischer, Rijneveld, Schwabe, Stoffelen.
  - *Technique*: Hand-written assembly for Number Theoretic Transform (NTT) using DSP SIMD instructions (`SMLABB`, `SMULBB`, `PKHTB`) to process two 16-bit coefficients simultaneously. Speeds up Kyber and Dilithium by **3.5x–6.0x** over compiled C/Rust.
- **`pqriscv`** (`https://github.com/mupq/pqriscv`):
  - *Targets*: Target 4 (RISC-V RV32IMAC).

### 3.6. Hashes (SHA-256, SHA-512, Keccak)
- **XKCP (eXtended Keccak Code Package)**:
  - *Technique*: `KeccakP-1600-armv7m-le-gcc.s` with 32-bit interleaved bit-slice representation.
- **OpenSSL `sha512-armv4.S`**:
  - *Technique*: Uses `LDRD`/`STRD` paired register loads and combined rotations to solve 64-bit register pressure on 32-bit ARM cores.

### 3.7. AES (128, 192, 256) & Wide-Key/Wide-Block Ciphers
- **Standard AES (FIPS 197)**: Defines AES-128 (10 rounds), AES-192 (12 rounds), and AES-256 (14 rounds) on a 128-bit block.
- **"AES-512" and Wide Constructs**:
  - **AES-XTS-512** (IEEE 1619 / FIPS): Standard for disk/flash encryption, using two 256-bit keys (512-bit total key material).
  - **Rijndael-256 / Rijndael-512**: Supported 256-bit block and key sizes (used in wide-block hashing and MACs).
- **Reference Implementations & Prior Art**:
  - **[`Rvch7/Fixslicing-AES`](https://github.com/Rvch7/Fixslicing-AES)** (Alexandre Adomnicăi & Thomas Peyrin, TCHES 2021) (MIT / Public Domain):
    - *Targets*: Target 1, Target 3, Target 4.
    - *Technique*: Fixslicing eliminates the ShiftRows overhead in classical bitslicing by adjusting the representation each round. Achieves speed records on Target 1: **~63 cycles/byte for AES-128-CTR** in 2-block parallel constant-time assembly.
  - **[`Ko-/aes-armcortexm`](https://github.com/Ko-/aes-armcortexm)** ("All the AES You Need on Cortex-M3 and M4", Peter Schwabe & Ko Stoffelen, SAC 2016) (Public Domain):
    - *Targets*: Target 1, Target 3.
    - *Technique*: Fast constant-time bitsliced (2, 4, and 8-block), and **first-order masked bitsliced AES** (provable side-channel resistance against DPA/CPA power analysis attacks on microcontrollers).
  - **[`BearSSL aes_ct.c`](https://bearssl.org/)** (Thomas Pornin) (MIT):
    - *Technique*: 32-bit constant-time bitsliced S-box using Boyar-Peralta logic minimization (only 113–115 boolean gates per S-box). Compact, zero RAM tables, immune to cache attacks.
  - **RISC-V Scalar Cryptography (`Zkne`, `Zknd`)**:
    - *Targets*: Target 4 with `Zk` extensions.
    - *Technique*: Hardware round instructions (`aes32esi`, `aes32esmi`, `aes32dsi`, `aes32dsmi`) reduce each AES round to just **4 instructions** (~10–15 cycles/block).
  - **Why Software ASM Matters Even with Hardware Crypto Accelerators**:
    1. *Cache Timing Immunity*: Hardware engines or T-table software leak cache lines on MCUs with data caches. Bitslicing has zero data-dependent memory lookups.
    2. *Hardware Limitations*: Many hardware ECB accelerators only support AES-128 (no AES-192 or AES-256).
    3. *Zero Peripheral Contention / Re-entrancy*: Hardware engines require RTOS mutexes, peripheral power clocks, and DMA setup; software assembly is purely re-entrant and faster for payloads under 64–128 bytes.

### 3.8. GHASH (GCM Authenticator)
- **OpenSSL / CRYPTOGAMS `ghash-armv4.pl`** (Andy Polyakov) (Apache-2.0 / Cryptogams):
  - *Targets*: Target 1 (ARMv7E-M / ARMv8-M Mainline), Target 3 (ARMv7-M).
  - *Technique*: 4-bit windowed polynomial multiplication in $\text{GF}(2^{128})$ with a 256-byte precomputed table per hash key $H$. Fuses 128-bit right shifts with XORs into a 32-instruction unrolled inner loop, processing 16-byte blocks in ~820 cycles (~51 cycles/byte) on Cortex-M33.

---

## 4. Actionable TODO Tracker

### Phase 1: Port Current NIST P-256 & P-384 to Additional ISAs
- [x] ✅ **Target 1: ARMv7E-M / ARMv8-M Mainline (Cortex-M4 / Cortex-M33) P-256**: Hand-written UMAAL assembly, batch affine table, Bernstein-Yang `mod_n_inv`.
- [x] ✅ **Target 1: ARMv7E-M / ARMv8-M Mainline (Cortex-M4 / Cortex-M33) P-384**: Hand-written 12-limb unrolled UMAAL multiplication, comb scalar mul.
- [x] ✅ **Embassy `P256Ops` Driver**: Fully integrated and tested on hardware with zero secret branches.
  - **Live Hardware Verification (Target 1: Cortex-M33 @ 64 MHz, RAM-only execution)**:
    | Benchmark Operation | `driver_mcu_crypto_asm` | `driver_p256_cm4` (Emil) | Speedup / Advantage |
    | :--- | :---: | :---: | :--- |
    | **Total Wall Time** | **1,782,470 µs (1.78 s)** | **2,302,917 µs (2.30 s)** | 🏆 **`mcu-crypto-asm` is 1.29× FASTER (22.6% less time)** |
    | **`base_mul`** (keygen/ECDSA) | **5,331 µs** | 6,526 µs | 🏆 **18.3% faster** (comb filter) |
    | **`point_add`** (projective) | **106 µs** | 1,678 µs | 🏆 **15.8× faster** (Renes-Costello-Batina complete) |
    | **`inv`** (`mod_n_inv`) | **677 µs** | 640 µs | 🎯 **Parity achieved** (down from 8,742 µs in PR #1) |
    | **`var_mul`** (peer public key) | 14,051 µs | 12,206 µs | Emil faster by ~1.8 ms (Emil disables CT cache check: `has_d_cache=0`) |
    | **`ecdh`** | 14,083 µs | 11,324 µs | Emil faster by ~2.7 ms |
    | **`lincomb`** (verify) | 19,385 µs | 16,375 µs | Emil faster by ~3.0 ms (joint sliding window) |
    | **`TLS 1.3 ECDHE`** | 19,382 µs | 18,732 µs | Essentially neck-and-neck |

- [x] ✅ **Target 2: ARMv6-M (Cortex-M0 / Cortex-M0+) P-256 Backend**:
  - [x] ✅ Adapt and vendor 16-bit Thumb-1 assembly from `Emill/P256-cortex-ecdh` (`asm/cortex_m0_p256.S`).
  - [x] ✅ Implement constant-time Thumb-1 field arithmetic (`emill_cm0_p256_mul_mont`, `sqr_mont`, `add_mod`, `sub_mod`).
  - [x] ✅ Hook into `mcu-crypto-asm` build system with `cfg(nistp_asm_cm0)` on `thumbv6m-none-eabi` / `thumbv8m.base`.
  - [x] ✅ Hardware verification on physical Target 2 (`nucleo-stm32c031c6` Cortex-M0+ @ 48 MHz) via Teleprobe (100% PASS on field arithmetic KATs + ECDH keygen & shared secret).
- [x] ✅ **Target 5: Xtensa LX7 P-256 & P-384 Backend**:
  - [x] ✅ Implement hand-written unrolled assembly multiplier (`nistp_mul_mont_8`, `nistp_mul_mont_12`) utilizing `SALTU` branchless carry propagation.
  - [x] ✅ Implement dedicated Solinas Montgomery squaring (`nistp_sqr_mont_8`, `nistp_sqr_mont_12`) eliminating off-diagonal products.
  - [x] ✅ Implement branchless constant-time modular addition and subtraction (`nistp_add_mod_*`, `nistp_sub_mod_*`).
  - [x] ✅ Support both Windowed ABI (`asm/xtensa_lx7.S`) and Call0 ABI (`asm/xtensa_lx7_call0.S`).
  - [x] ✅ Implement interleaved simultaneous double-scalar multiplication (`PointJacobian::lincomb` / Shamir's Trick) halving point doublings from 512 to 256 for P-256 and 768 to 384 for P-384.
  - [x] ✅ Fast Jacobian projective ECDSA verification ($r \cdot Z^2 \equiv X \pmod p$) eliminating modular field inversion $\pmod p$.
  - [x] ✅ Fully integrated into `mcu-crypto-asm` backend dispatch and Embassy `P256Ops` driver.
  - [x] ✅ Hardware verification on physical Target 5 (Xtensa LX7 @ 240 MHz) via J-Link JTAG / OpenOCD (100% bit-exact across all 128 KAT vectors, 0 failures):
    | Operation | Routine | Physical Target 5 @ 240 MHz | Fiat-Crypto (RustCrypto) | Speedup / Status |
    | :--- | :--- | :---: | :---: | :--- |
    | **P-256 Mul** | `nistp_mul_mont_8` | **1,274 cycles** (5.3 µs) | 2,795 cycles (11.6 µs) | 🏆 **2.19× faster** |
    | **P-256 Sqr** | `nistp_sqr_mont_8` | **1,344 cycles** (5.6 µs) | 2,795 cycles (11.6 µs) | 🏆 **2.08× faster** |
    | **P-256 Add / Sub** | `nistp_add/sub_mod_8` | **217 / 159 cycles** | ~450 cycles | 🏆 **2.1×–2.8× faster** |
    | **P-384 Mul** | `nistp_mul_mont_12` | **2,886 cycles** (12.0 µs) | 8,538 cycles (35.6 µs) | 🏆 **2.96× faster** |
    | **P-384 Sqr** | `nistp_sqr_mont_12` | **2,789 cycles** (11.6 µs) | 8,538 cycles (35.6 µs) | 🏆 **3.06× faster** |
    | **P-384 Add / Sub** | `nistp_add/sub_mod_12`| **324 / 235 cycles** | ~650 cycles | 🏆 **2.0×–2.8× faster** |
    | **P-256 ECDSA Verify** | `ecdsa::verify` | **~20.0 ms** | 890.0 ms (`opt-s`) | 🏆 **44.5× faster** (Shamir's Trick) |
    | **P-384 ECDSA Verify** | `ecdsa::verify` | **~62.1 ms** | 2,410.0 ms (`opt-s`) | 🏆 **38.8× faster** (Shamir's Trick) |
- [ ] **Target 4: RISC-V (RV32IMAC / Zk) P-256 Backend**:
  - [ ] Implement 8-limb Comba multiplication utilizing 32 orthogonal registers.
  - [ ] Add `Zbkc` carryless multiplier path for targets supporting RISC-V Scalar Crypto.

---

### Phase 2: Modern Elliptic Curves (Curve25519 / X25519 & Ed25519)
- [x] ✅ **Target 1: ARMv7E-M / ARMv8-M Mainline X25519 & Ed25519 Backend**:
  - [x] ✅ Integrate `cortex_m_fe25519.S`, `cortex_m_curve25519.S`, and `cortex_m_ed25519.S` from [`embassy-rs/cortex25519`](https://github.com/embassy-rs/cortex25519).
  - [x] ✅ Target cycle goal: **550,720 cycles on Target 1** (8.6 ms @ 64 MHz on Cortex-M33).
  - [x] ✅ Support X25519 ECDH key agreement (RFC 7748) and Ed25519 Edwards point arithmetic.
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on RFC 7748 and Wycheproof test vectors).
- [ ] **Target 5: Xtensa LX6 / LX7 X25519 Backend**:
  - [ ] Integrate MAC16-optimized assembly from [`aCinal/esp-x25519`](https://github.com/aCinal/esp-x25519) (17 15-bit limbs, 40-bit accumulator registers `acclo`/`acchi`, hardware `loop`).
  - [ ] Provide constant-time, zero-table X25519 in bare-metal Rust without external C dependencies.
- [x] ✅ **Target 2: ARMv6-M (Cortex-M0 / Cortex-M0+) Curve25519 / X25519**:
  - [x] ✅ Port Thomas Pornin's pure 16-bit Thumb-1 assembly (`pornin/x25519-cm0`) into `asm/cortex_m0_curve25519.S`.
  - [x] ✅ Inversion using optimized constant-time binary GCD algorithm in 54,793 cycles.
  - [x] ✅ Safe, zero-dependency `no_std` Rust API in `src/curve25519/cortex_m0.rs` and `src/curve25519/x25519.rs` with `cfg(nistp_asm_cm0)`.
  - [x] ✅ Hardware verification on physical Target 2 (`nucleo-stm32c031c6` Cortex-M0+ @ 12 MHz) via Teleprobe (100% PASS on RFC 7748 KAT 1 [269 ms, ~3.23M cycles], KAT 2 [269 ms], and Diffie-Hellman Alice-Bob key exchange).

---

### Phase 2.5: secp256k1 (Bitcoin / Koblitz Curve)
- [x] ✅ **Target 1: ARMv7E-M / ARMv8-M Mainline secp256k1 Backend**:
  - [x] ✅ Integrate UMAAL multi-precision multiplication and squaring via `asm/cortex_m_bignum.S`.
  - [x] ✅ Fast pseudo-Mersenne Solinas reduction modulo $p = 2^{256} - 2^{32} - 977$.
  - [x] ✅ Complete Renes–Costello–Batina addition formulas for $a = 0$ (Algorithm 1) with zero exception branches.
  - [x] ✅ Constant-time Montgomery ladder scalar multiplication over all 256 bits.
  - [x] ✅ SEC1 compressed (33B) and uncompressed (65B) point serialization/deserialization.
  - [x] ✅ ECDH key agreement and public key derivation.
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on point doubling @ 183 µs / 11,712 cycles, RFC 6979 Section A.2.5 keygen @ 101 ms, SEC1 33B/65B roundtrip, and ECDH shared secret agreement @ 101 ms).
- [ ] **Target 2: ARMv6-M (Cortex-M0 / Cortex-M0+) secp256k1**:
  - [ ] Adapt 16-bit Thumb-1 routines from `third_party/micro-ecc` (`asm_arm_m0.inc`).

---

### Phase 3: High-Speed Symmetric AEAD (Poly1305 & ChaCha20)
- [x] ✅ **Poly1305 One-Time Authenticator (RFC 8439)**:
  - [x] ✅ Implement Target 1 assembly inner loop using `UMLAL` (`asm/cortex_m_poly1305.S`).
  - [x] ✅ High-speed constant-time multi-precision evaluation (~17 cycles/byte total bare-metal throughput).
  - [x] ✅ Implement constant-time clamping and final reduction modulo $2^{130}-5$.
  - [x] ✅ Host and target KAT test vectors from RFC 8439.
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on RFC 8439 test vector and 1024-byte benchmark).
- [x] ✅ **ChaCha20 Stream Cipher**:
  - [x] ✅ Implement ARM assembly block function holding all 8 active round state words in registers without stack spills (`asm/cortex_m_chacha20.S`).
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on RFC 8439 Section 2.3.2 block function, Section 2.4.2 encryption, and 1024-byte benchmark @ ~30 c/byte).

---

### Phase 4: Big-Integer Modular Exponentiation & RSA
- [x] ✅ **Integrate `Emill/rsa-armv7` Bignum Engine**:
  - [x] ✅ Vendor `asm/cortex_m_bignum.S` Montgomery multiplication, squaring, reduction routines.
  - [x] ✅ Create Rust `no_std` wrapper (`src/rsa.rs`) for big-integer modular exponentiation ($a^b \pmod n$).
  - [x] ✅ Support RSA-1024, RSA-2048, and RSA-4096 public operations (verification) with arbitrary exponents.
  - [x] ✅ Constant-time Montgomery modular arithmetic.
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on RSA-1024 [1.7 ms] and RSA-2048 [5.4 ms] known-answer tests).

---

### Phase 5: Post-Quantum Cryptography (NIST FIPS 203 & 204)
- [x] ✅ **ML-KEM (Kyber-512 / 768 / 1024) Target 1 NTT Acceleration**:
  - [x] ✅ Adapt PQM4's hand-written SIMD NTT butterflies (`SMLABB`/`PKHTB`, Plantard arithmetic, `fastntt.S`, `fastinvntt.S`, `fastbasemul.S`, `reduce.S`, `fastaddsub.S`).
  - [x] ✅ Fast Barrett and Plantard reduction modulo $q = 3329$ (`asm_barrett_reduce`, `plant_red`).
  - [x] ✅ Implement safe `no_std` Rust API with `Polynomial` (`[i16; 256]`): `ntt()`, `invntt()`, `basemul()`, `basemul_acc()`, `mul_ring()`, `add()`, `sub()`, `reduce()`, and 12-bit serialization (`from_bytes`/`to_bytes`).
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on zero poly, vector addition [1,920c], vector subtraction [1,920c], Barrett reduction [1,920c], forward NTT [5,824c], inverse NTT [5,824c], NTT basemul [5,824c], full ring multiplication [25,344c] verified bit-exact against schoolbook math, basemul accumulation, and 12-bit serialization).
- [x] ✅ **ML-DSA (Dilithium-2 / 3 / 5) Target 1 NTT Acceleration**:
  - [x] ✅ Adapt PQM4's SIMD NTT for modulus $q = 8380417$ (`ntt.S`, `pointwise_mont.s`, `vector.s`, `macros.i`).
  - [x] ✅ Fast Montgomery reduction and conditional modular addition modulo $q = 8380417$ (`asm_reduce32`, `asm_caddq`).
  - [x] ✅ Implement safe `no_std` Rust API with `Polynomial` (`[i32; 256]`): `ntt()`, `invntt_tomont()`, `pointwise_mont()`, `pointwise_acc_mont()`, `mul_ring()`, `reduce32()`, `caddq()`, `add()`, `sub()`.
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on zero poly, vector addition [1,920c], vector subtraction [1,920c], reduce32 [1,920c], caddq [0, Q-1] range, forward NTT [11,712c], inverse NTT [11,712c], pointwise Montgomery multiplication [3,904c], full ring multiplication [46,848c] verified bit-exact against schoolbook math, and pointwise accumulation).

---

### Phase 6: Hashes & Symmetric Primitives
- [x] ✅ **SHA-512 / SHA-384 Assembly**:
  - [x] ✅ Target 1 assembly implementation pairing 32-bit registers for 64-bit words via Andy Polyakov / OpenSSL `sha512-armv4.pl` (`asm/cortex_m_sha512.S`).
  - [x] ✅ Eliminates compiler register spills, speeding up Ed25519, P-384 certificate parsing, and FIPS 180-4 hashing.
  - [x] ✅ Safe, zero-dependency `no_std` Rust API (`src/sha512.rs`) with `Sha512`, `Sha384`, `compress_blocks()`, and portable fallback.
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on raw 128-byte block compress [11,712 cycles, 91 cpb], NIST empty string, NIST 'abc', NIST 112-byte multi-block vectors, streaming incremental updates, and 1024-byte bulk throughput @ ~97 cycles/byte).
- [x] ✅ **Keccak-f[1600] / SHAKE-128 / SHAKE-256**:
  - [x] ✅ Integrate 32-bit interleaved bit-sliced ARM assembly (`asm/cortex_m_keccak.S`, `src/keccak.rs`).
  - [x] ✅ Full FIPS 202 sponge implementation (SHA3-256, SHA3-512, SHAKE128, SHAKE256).
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on 24-round permutation @ 15,616 cycles, SHA3-256/512, and SHAKE-128/256 KATs).
- [x] ✅ **Constant-Time Bitsliced & Fixsliced AES-128, AES-192, AES-256**:
  - [x] ✅ Implement Adomnicăi-Peyrin 2-block parallel **Fixsliced AES** on Target 1 (`asm/cortex_m_aes_encrypt.S`, `asm/cortex_m_aes_keyschedule.S`, ~1,950 cycles/block AES-128, ~2,910 cycles/block AES-256).
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on AES-128 and AES-256 NIST SP 800-38A KATs).
- [x] ✅ **GHASH (Galois/Counter Mode Authentication, NIST SP 800-38D)**:
  - [x] ✅ Target 1 assembly implementation using 4-bit windowed GF(2^128) polynomial multiplier with 256-byte precomputed table via Andy Polyakov / OpenSSL `ghash-armv4.pl` (`asm/cortex_m_ghash.S`).
  - [x] ✅ Implements streaming multi-block `gcm_ghash_4bit` and single-block `gcm_gmult_4bit` with native little-endian table layout.
  - [x] ✅ Safe, zero-dependency `no_std` Rust API (`src/ghash.rs`) with `Ghash`, `Htable`, `compress_blocks()`, `gmult()`, and bitwise portable fallback.
  - [x] ✅ Hardware verification on physical Target 1 (`nucleo-stm32h563zi` Cortex-M33 @ 64 MHz) via Teleprobe (100% PASS on Htable precomputation, single-block gmult [1,920 cycles], two-block streaming GHASH [1,920 cycles, 60 cpb], streaming unaligned chunks, and 1024-byte bulk throughput @ 823 µs / 52,672 cycles / ~51 cycles/byte).
- [x] ✅ **Target 2: ARMv6-M (Cortex-M0 / Cortex-M0+) Bitsliced AES Backend**: Constant-time Boyar-Peralta S-box (113–115 boolean gates, 0 RAM tables, fully cache-immune) ported from Thomas Pornin / BearSSL. Hardware verified on physical Target 2 (`nucleo-stm32c031c6` and `nucleo-stm32g071rb` Cortex-M0+ @ 12 MHz) via Teleprobe (100% PASS on NIST FIPS-197 AES-128 [366 µs/blk, 4.4k cyc], AES-256 [518 µs/blk, 6.2k cyc], and 200-block streaming throughput @ 281 c/byte).
- [ ] Implement **first-order masked bitsliced AES** (Schwabe-Stoffelen) for power-analysis / DPA resistance on secure embedded tokens.
- [ ] Support AES-XTS (256-bit and 512-bit key material) for encrypted firmware partitions and external flash.
- [ ] Add Target 4 (RISC-V `Zkne`/`Zknd` scalar crypto instructions) backend.
