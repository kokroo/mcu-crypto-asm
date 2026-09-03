# mcu-crypto-asm

**Hand-written assembly cryptography for 32-bit microcontrollers** —
constant-time, `no_std`, no allocator, no dependencies.

The `-asm` is the point: these are hand-rolled assembly kernels for the one
operation that dominates each primitive, not portable code hoping the compiler
does something clever. Where that wins, the README says by how much and shows
the measurement; where it loses, it says that too.

**Today that means P-256 and P-384**, with hand-written assembly for
**Cortex-M4/M7/M33** and **Xtensa LX7** (ESP32-S2/S3). The crate is named for
the scope it is meant to grow into — other primitives will be added as
separate, feature-gated modules under the same package, so a project that
wants one of them does not compile the rest.

Every performance and constant-time claim below is **measured on real silicon**
(nRF52840 and ESP32-S3 over J-Link), not estimated.

```toml
[dependencies]
mcu-crypto-asm = "0.1"
```

```rust
use mcu_crypto_asm::p256;

// Public key from a private scalar (SEC1 uncompressed: 0x04 || x || y)
let mut pk = [0u8; 65];
p256::derive_public_key(&secret /* 32 bytes, big-endian */, &mut pk)?;

// ECDH - rejects peer points that are not on the curve
let mut shared = [0u8; 32];
mcu_crypto_asm::ecdh::shared_secret::<{ p256::N }>(
    &p256::CURVE, &secret, &peer_pk, &mut shared,
)?;
```

On an embassy executor use the yielding form, so a 31 ms operation does not
stall every other task - see [Not blocking the executor](#not-blocking-the-executor).

---

## Scope

| primitive | status |
|---|---|
| P-256 field arithmetic, point ops, ECDH | ✅ done, hardware-validated |
| P-384 field arithmetic, point ops, ECDH | ✅ done, hardware-validated |
| ECDSA (both curves) | planned |
| further primitives (hashing, symmetric, X25519) | not started |

Each primitive lives in its own module and, once there is more than one, its
own cargo feature. The shared machinery — the assembly generators in `gen/`,
the QEMU and on-hardware harnesses, and the three-way constant-time
verification — is the reusable part, and is deliberately primitive-agnostic.

## Why this exists

Hand-optimised P-256 for Cortex-M4 already exists and is excellent
([Emill/P256-Cortex-M4](https://github.com/Emill/P256-Cortex-M4), MIT). Two
gaps remain, and this crate fills them:

- **P-384 on any MCU.** There is no permissively-licensed optimised
  implementation; everything falls back to portable C or Rust.
- **Xtensa LX7.** The ESP32-S2/S3 have **no ECC accelerator at all** - verified
  from ESP-IDF's own `soc_caps.h`, which defines `SOC_MPI_SUPPORTED` (the
  RSA/bignum peripheral) but no `SOC_ECC_SUPPORTED`. Only the ESP32-C6/H2 have
  an ECC block, and it does P-192/P-256 only, never P-384.

### Should you use this?

Read this table before adopting it:

| your target | use |
|---|---|
| **P-384, any MCU** | **this crate** - nothing else is optimised |
| **ESP32-S2/S3, either curve** | **this crate** - largest margins measured here |
| P-256 on Cortex-M4/M7 | **[Emill's library](https://github.com/Emill/P256-Cortex-M4)** - 2.4x faster than this crate |
| STM32 with a PKA peripheral | **the hardware** (L5, U5, WB/WBA, WL, H5); `embassy-stm32` already has a driver |
| ESP32-C6/H2, P-256 | **the on-chip ECC peripheral** |

This crate is also a reasonable default if you want *one* implementation across
several architectures, with a portable fallback everywhere else.

---

## Measured performance

Exact hardware cycle counts (DWT CYCCNT / Xtensa CCOUNT), running from RAM.
Reproduce with `harness/src/bin/bench.rs`.

### Modular multiplication

**nRF52840 (Cortex-M4) @ 64 MHz**

| operation | fiat-crypto | mcu-crypto-asm | Emill | verdict |
|---|---|---|---|---|
| P-256 | 2248 | **998** | **418** | Emill wins, 2.38x |
| P-384 | 3858 | **1951** | n/a | **we win, 1.97x** |

**ESP32-S3 (Xtensa LX7)**

| operation | fiat-crypto | mcu-crypto-asm | verdict |
|---|---|---|---|
| P-256 | 2795 | **1272** | **we win, 2.20x** |
| P-384 | 8538 | **2884** | **we win, 2.96x** |

`fiat-crypto` is the formally-verified generated arithmetic that the RustCrypto
`p256`/`p384` crates vendor internally, so this is the same operation, not a
comparison across abstraction levels. The benchmark **cross-checks** every
implementation's output before timing anything.

**P-384 on Xtensa is the widest margin here, and it is not an accident.**
fiat-crypto's P-384 costs 3858 cycles on Cortex-M4 but 8538 on Xtensa - 2.2x
worse - while this crate degrades only 1.35x. Portable code leans on the
compiler to synthesise carry chains, and Xtensa has **no carry flag**, so that
code falls apart. Explicit `SALTU` carry handling is what recovers it.

### Higher-level operations (nRF52840 @ 64 MHz)

| operation | cycles | time |
|---|---|---|
| `k*G` (fixed-base comb) P-256 | 1 675 431 | **26 ms** |
| `k*G` (fixed-base comb) P-384 | 4 690 419 | **73 ms** |
| `derive_public_key` P-256 | 1 986 800 | **31 ms** |
| `derive_public_key` P-384 | 5 642 494 | **88 ms** |
| `k*P` (variable base, ECDH) P-256 | 6 513 216 | 101 ms |
| `k*P` (variable base, ECDH) P-384 | 18 308 596 | 286 ms |

`k*G` started at 150 ms (P-256) / 433 ms (P-384). What got it here:

| change | effect |
|---|---|
| 4-bit window instead of double-and-add-always | -33% |
| fixed-base comb, 4 tables x 16 entries | -63% |
| windowed inversion (`p-2` is public, zero digits skippable) | -21% / -32% of the inversion |
| `u64` carry-chain idiom in `add_mod`/`sub_mod` | -24% on those |

The comb costs 4 KiB (P-256) + 6 KiB (P-384) of flash.

---

## Constant time

Every level measures **exactly flat** - zero cycles of operand-dependent
variation - on real hardware with a cycle counter:

| | evidence |
|---|---|
| `mul_mont` | 16 operand classes, spread 0; assembly has **zero branches** |
| `add_mod` / `sub_mod` | spread 0 |
| `Point::add` | 200 additions over 6 operand pairs incl. `identity+identity`, spread 0 |
| `mul_base` (`k*G`) | 6 scalars from sparse to dense, spread 0 |

Verified three ways, because no single method was sufficient:

1. **Static audit of the assembly** (`cargo test --test constant_time`) - the
   generated `.S` contains **zero branches**, every memory operand is
   `[reg, #imm]`, and every opcode is on a fixed-latency allow-list.
2. **Dynamic timing on hardware** (`harness/src/bin/ct.rs`) - many operand
   classes against an interleaved same-input control group establishing the
   noise floor.
3. **Instruction tracing** (`harness/src/bin/scantrace.rs`) - QEMU
   `-singlestep -d exec,nochain`, diffing executed PC sequences.

### Three real leaks were found here. Read this before modifying the code.

**A timing test is not sufficient.** The worst bug in this crate's history was
found only by tracing:

**LLVM compiled the constant-time table scan into an early-exit search.** The
comb scan ORs all 16 entries under a mask so exactly one contributes - but LLVM
*proved* that property and emitted `beq` to the matching entry and `bne` to
loop, so **the loop-trip count was the secret digit**. Timing showed this only
as a ~0.1% wobble, and five plausible fixes reasoned from timing all made it
*worse*. Diffing instruction traces found it immediately: digit 0 and digit 15
executed *disjoint address ranges*.

The other two:

- **`add_mod` branched on operand values.** `(a & m) | (b & !m)` compiles to a
  select; an N-word select is too long for a Thumb-2 IT block, so it became a
  real branch. Fixed by subtracting a *masked modulus* instead. Rewriting in
  XOR form was **not enough** - LLVM reconstructs the select.
- **Choosing an addition formula on a secret digit** with `if digit == 0`,
  where the two formulas cost different numbers of multiplications.

**Consequences for contributors:**

- The `core::hint::black_box` calls on masks and flags are **load bearing**.
  Removing them silently reintroduces the branch. They are commented as such.
- After touching the scan or the field arithmetic, re-run the trace check, not
  just the timing test:
  ```sh
  cd harness && cargo build --release --bin scantrace
  qemu-system-arm -machine mps2-an386 -cpu cortex-m4 -nographic \
    -semihosting-config enable=on,target=native -singlestep -d exec,nochain \
    -D /tmp/trace.log -kernel target/thumbv7em-none-eabihf/release/scantrace
  # then diff the two invocations' PC sequences - they must be identical
  ```
- `tools/audit_compiled.sh <elf> <symbol>` lists a function's conditional
  control flow. Loop back-edges against public constants and IT blocks are
  fine; anything conditioned on a secret is not.

### Threat model

Constant time **with respect to secret scalars and field element values**. Loop
trip counts depend only on the curve, which is public. Not hardened against
power/EM side channels, fault injection, or a variable-latency multiplier -
**Cortex-M3 is deliberately excluded** for that last reason (it has `UMAAL`, but
a variable-latency multiplier; `build.rs` warns and falls back to portable).

This crate has **not had an external security audit.**

---

## Not blocking the executor

A scalar multiplication is 26-88 ms. Run that as one blocking call inside an
embassy executor and every other task stalls for that whole period - long enough
to drop BLE connection events and miss packet deadlines.

`async` cannot move the work off the CPU - there is one core and no accelerator.
What it *can* do is stop holding the CPU for the whole computation:

```rust
// Blocking: holds the CPU for the entire operation.
let pk = point.mul_scalar(&p384::CURVE, &k);

// Yielding: same result, longest uninterrupted hold ~640 us.
let pk = mul_scalar_yielding(&p384::CURVE, &point, &k, 1).await;

// Or drive it manually from your own state machine:
let mut st = ScalarMul::new(&p384::CURVE, &point, &k);
while st.step(&p384::CURVE, 4).is_none() { /* do something else */ }
```

| | blocking | worst chunk (`budget = 1`) |
|---|---|---|
| P-256 `k*P` | 101 ms | **345 us** |
| P-384 `k*P` | 286 ms | **640 us** |

Total cost rises by only **~0.2%**. `ecdh::derive_public_key_yielding` and
`shared_secret_yielding` expose the same at the ECDH level, validating the peer
point *before* any yielding so hostile input is rejected without partial work.

The yield future is six lines of `core::future` - **no async runtime
dependency** - so it works under embassy or anything else.

**Chunking does not weaken the timing guarantee.** The total number of point
operations is fixed by the curve, never the scalar (`ScalarMul::total_ops`), so
every scalar takes the same number of steps and yields. A test asserts exactly
that across five very different scalars.

The state holds a 16-entry precomputed table: ~1.6 KiB (P-256) / ~2.6 KiB
(P-384). It lives in the future, so place it deliberately rather than deep on a
small task stack.

---

## Design

Performance of ECC on a 32-bit MCU is decided almost entirely by one operation,
so **the assembly surface is deliberately tiny**: `mul_mont` and nothing else.
Point arithmetic, the scalar ladder and ECDH are portable Rust shared by every
curve and target.

**Montgomery CIOS, and one lucky fact.** Both NIST primes satisfy
`p == -1 (mod 2^32)`, so `n0' = -p^-1 mod 2^32 == 1` and the per-word reduction
multiplier collapses to `m = t[0]` - no multiply at all. `gen/gen_params.py`
*asserts* this rather than trusting it.

**FIOS, not CIOS.** CIOS makes two passes over the accumulator per outer
iteration, so every limb is loaded and stored twice; FIOS fuses them into one
pass. The cost is a second carry chain, needing one more register than either
core has spare, so both backends fully unroll the outer loop to free the
counter. Worth ~24% on Cortex-M4 and ~15% on Xtensa. A side effect: with no loop
left, the assembly contains **zero branches**.

**The modulus is a constant, so treat it like one.** Each NIST prime has only
three distinct limb values. On Cortex-M4 they live in registers, removing one
`ldr` from every reduction step. On Xtensa, where a full step costs 11
instructions, limbs equal to 0 or 1 skip the product entirely.

**Cortex-M4** is built on `UMAAL` - `RdHi:RdLo = Rn*Rm + RdHi + RdLo`, one
cycle, cannot overflow - which is exactly the CIOS inner step. **Xtensa LX7** has
no `UMAAL` and no carry flag; the same step costs eight instructions using
`SALTU` as a branchless carry primitive. That 8:1 ratio is the honest ceiling on
how close Xtensa can get.

**Complete point formulas.** Renes-Costello-Batina complete addition for
`a = -3`: one formula, no exceptions, correct for `P+Q`, `P+P`, `P+(-P)` and the
identity. There is deliberately **no separate doubling routine** - `add(P, P)`
is simply correct. That is a security property: the classic way to leak a scalar
is a special case that fires only when the accumulator equals the input point.

**ECDH validates its inputs.** `shared_secret` rejects peer points not on the
curve - omitting that is the invalid-curve attack, which recovers a private key
from a handful of exchanges. Scalars must be in `[1, n)` and coordinates reduced
mod p.

The assembly is **generated** (`gen/gen_asm_*.py`), not hand-maintained: P-256
executes 128 `UMAAL` per multiply and P-384 288, and hand-editing carry chains
that long is how silent bugs happen.

### How correctness is established

Nothing is trusted because it looks right:

- The portable backend is checked against **`num-bigint`**, including carry edge
  cases.
- Every assembly backend is **differential-tested** against the portable one.
- Known-answer vectors come from **independent Python bignum**.
- The point layer is checked against a **deliberately different algorithm** -
  plain affine arithmetic with explicit special cases - so a transcription error
  in the projective formulas cannot be mirrored in both. Vectors include `k = n`
  (the identity) and `k = n-1` (`-G`).
- The SEC1 byte encoding is pinned separately, because two sides agreeing on a
  shared secret proves *consistency*, not correctness.
- **Every harness has been mutation-tested** - a deliberate bug injected and the
  harness confirmed to fail - so a green run means something.

---

## Supported targets

| target | backend | notes |
|---|---|---|
| `thumbv7em-none-eabi(hf)` | assembly | Cortex-M4 / M7 |
| `thumbv8m.main-none-eabi(hf)` | assembly | Cortex-M33 |
| `xtensa-esp32s3-none-elf` | assembly | needs the esp toolchain |
| `xtensa-esp32s2-none-elf` | assembly | needs the esp toolchain |
| everything else | portable Rust | host, RISC-V, Cortex-M0+, ... |
| `thumbv7m` (Cortex-M3) | portable, **deliberately** | has `UMAAL`, but a variable-latency multiplier, so assembly would not be constant time |
| `xtensa-esp32` (LX6) | portable, **deliberately** | no `SALTU` |

Backend selection happens in `build.rs` **from the target triple**, not from
`target_feature`: `dsp`/`v7` are not exposed as cfgs on bare-metal ARM targets,
so gating on them silently compiles the portable fallback and you benchmark the
wrong thing.

### Toolchain notes

- **Cortex-M builds on stable Rust.** The assembly goes through `global_asm!`
  with `options(raw)` - without `raw`, `push {r4-r11, lr}` is parsed as a format
  placeholder.
- **Xtensa needs the esp toolchain** (`espup install`). LLVM's Xtensa assembler
  does **not** implement `SALTU`, so that file cannot go through `global_asm!`;
  `build.rs` assembles it with the esp GNU toolchain and links it as a static
  library. This also keeps the `.S` a clean standalone file.

---

## Building and testing

```sh
# Host: portable reference vs num-bigint, point/ECDH oracles, CT audit
cargo test

# Everything: host + QEMU (Cortex-M4, M7, Xtensa) - non-zero exit on failure
./run-all.sh

# Cortex-M4 benchmark under QEMU
cd harness
qemu-system-arm -machine mps2-an386 -cpu cortex-m4 -icount shift=0 -nographic \
  -semihosting-config enable=on,target=native \
  -kernel target/thumbv7em-none-eabihf/release/bench

# On real hardware - runs entirely from RAM, writes no flash
NISTP_MEMORY_X=memory-nrf-ram.x cargo build --release
probe-rs run --chip nRF52840_xxAA target/thumbv7em-none-eabihf/release/bench

# Xtensa correctness (esp toolchain + Espressif's QEMU fork)
cd harness-xtensa && ./run.sh

# Regenerate constants and assembly
python3 gen/gen_params.py && python3 gen/gen_asm_cortex_m4.py \
  && python3 gen/gen_asm_xtensa.py && python3 gen/gen_asm_xtensa.py --call0 \
  && python3 gen/gen_kat.py && python3 gen/gen_comb.py \
  && python3 gen/gen_point_vectors.py
```

`-icount shift=0` is required under QEMU: it makes the virtual clock advance
deterministically with instructions retired, which is what makes SysTick a valid
*relative* measure. The benchmark runs a linearity self-check and refuses to
report numbers if the counter is not tracking work. On real hardware the same
binary uses DWT CYCCNT and reports exact cycles.

**Hardware measurements run from RAM**, so flash wait states are excluded and
instruction fetch contends with data on the same bus (~2.6 cycles/instruction
observed on the M4). Ratios against fiat-crypto hold since both run under
identical conditions; absolute cycles from flash will differ.

---

## Not done yet

- **ECDSA.** ECDH is complete; signing and verification are not implemented.
- **Dedicated squaring and doubling.** `sqr` routes through `mul_mont`; the comb
  uses the general addition for doubling. Together worth maybe 10-15%.
- **Assembly `add_mod`/`sub_mod`.** Still portable Rust at 208/176 cycles
  against 998 for a full multiply - the largest single remaining item, ~10%.
- **Closing the gap to Emill on P-256/Cortex-M4** is a rewrite, not a tweak: a
  full 256x256 Comba product held in registers plus FPU, with a P-256-specific
  Solinas reduction. P-256-only, and it would not help P-384.
- **Cortex-M0+ and RV32IM backends.** Both are genuinely empty niches (RP2040
  especially) and fully emulatable.

---

## Vendored code

`third_party/` contains upstream sources used **only for benchmarking and
cross-checking** - none of it is linked into the library. See
[`third_party/README.md`](third_party/README.md) for licences.

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

## Acknowledgements

- **[Emill](https://github.com/Emill/P256-Cortex-M4)** - the reference
  hand-optimised P-256 for Cortex-M4, and still the right choice on that curve
  and core. Benchmarked against here rather than competed with.
- **[fiat-crypto](https://github.com/mit-plv/fiat-crypto)** - formally-verified
  field arithmetic, the honest baseline for "what you get without assembly".
- **Renes, Costello and Batina**, *Complete addition formulas for prime order
  elliptic curves* (2016).
