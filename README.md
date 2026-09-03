# nistp-mcu

Fast, constant-time **P-256 and P-384** modular arithmetic for 32-bit MCUs, with
hand-written assembly for **Cortex-M4/M7/M33** and **Xtensa LX7** (ESP32-S2/S3).

## Why

Hand-optimised P-256 for Cortex-M4 already exists and is excellent
([Emill/P256-Cortex-M4](https://github.com/Emill/P256-Cortex-M4), MIT). Two gaps
remain:

- **P-384 on any MCU.** There is no permissively-licensed optimised
  implementation. Everything falls back to portable C/Rust.
- **Xtensa LX7.** The ESP32-S2/S3 have no ECC accelerator at all — verified from
  ESP-IDF's own `soc_caps.h`, which defines `SOC_MPI_SUPPORTED` (the RSA/bignum
  peripheral) but no `SOC_ECC_SUPPORTED`. Only the ESP32-C6/H2 have an ECC block,
  and it does P-192/P-256 only, never P-384.

## Results

### Speed — measured on real silicon

**nRF52840 (Cortex-M4) @ DWT CYCCNT — exact hardware cycles, 1000 ops each:**

| operation | fiat-crypto | nistp-mcu | Emill | verdict |
|---|---|---|---|---|
| P-256 modular multiply | 2246 | 1411 | **415** | **Emill wins, 3.39×** |
| P-384 modular multiply | 3857 | **2834** | n/a | **we win, 1.36×** |

**ESP32-S3 (Xtensa LX7) @ CCOUNT — exact hardware cycles:**

| operation | nistp-mcu | vs Cortex-M4 |
|---|---|---|
| P-256 modular multiply | 1703 | 1.21× more cycles |
| P-384 modular multiply | 3823 | 1.35× more cycles |

Two things worth reading off these numbers:

**QEMU overstated our advantage.** Instruction-count ratios predicted 1.88× /
1.62× over fiat-crypto; real cycles gave **1.59× / 1.36×**. Our implementation
is memory-heavy, and loads and stores cost more on real silicon than an
instruction count suggests. Emulation was right about the *ordering* and wrong
about the *margin* — which is exactly why the hardware run mattered.

**Xtensa does far better than the instruction ratio implies.** The CIOS inner
step costs 8 Xtensa instructions against 1 `UMAAL`, yet the measured gap is only
1.21×. The reason is that the Cortex-M4 version is memory-bound, so most of the
`UMAAL` advantage is spent waiting on `ldr`/`str` — the same bottleneck that
loses us the Emill comparison, showing up twice.

Measurements were taken running from RAM, so flash wait states are excluded;
absolute numbers running from flash will be higher, ratios roughly similar.

### Historical: emulated Cortex-M4

`fiat-crypto`'s `p256_32`/`p384_32` is the formally-verified generated Montgomery
arithmetic that the RustCrypto `p256`/`p384` crates vendor internally, so
`fiat_p256_mul` is *the same operation* as our `mul_mont` — a true head-to-head
rather than a comparison across abstraction levels.

| operation | fiat-crypto | nistp-mcu | Emill | verdict |
|---|---|---|---|---|
| P-256 modular multiply | 32926 | 17501 | **4750** | **Emill wins, 3.68× over us** |
| P-384 modular multiply | 57125 | **35100** | n/a | **we win, 1.62×** |

*Ticks per 1000 operations, QEMU `mps2-an386` with `-icount shift=0`.*
All three agree on the result — the benchmark cross-checks Emill's output
against ours before timing anything, so this compares identical work.

### Read this before using it

**On Cortex-M4, use Emill for P-256.** He is 3.4× faster (measured) and this crate does not
change that. The measured reason is memory traffic: our CIOS inner step is four
instructions (`ldr`, `ldr`, `umaal`, `str`) where his is essentially one,
because he keeps the accumulator in registers — using the **FPU registers as
scratch** (`vldm r1,{s8-s15}`) to escape Cortex-M4's register pressure — while
we spill `t[]` to the stack. Closing that gap is a restructuring job, not a
tweak, and it is the main open work item.

Where this crate is actually the best option available:

- **P-384 on any MCU** — 1.36× faster than fiat-crypto on real silicon, and no
  hand-optimised P-384 to compete with. This is the real gap it fills.
- **Xtensa LX7 (ESP32-S2/S3)** — the only optimised implementation, on a chip
  with no ECC accelerator at all.
- **Anywhere you want one implementation across arches**, with the portable
  backend as the fallback.

⚠️ **These are instruction-proportional, not hardware cycles.** QEMU's mps2
machines do not implement DWT CYCCNT, so the harness falls back to SysTick, which
under `-icount` advances deterministically with instructions retired. Absolute
values are meaningless; **ratios are exact**. The binary runs a linearity
self-check (250 vs 1000 ops must differ by ~4×; measured 4763 vs 19050) and
*aborts rather than report numbers* from a counter that is not tracking work.
Exact cycle counts on real hardware are pending — see [Status](#status).

### Constant time

Two independent lines of evidence:

**Static audit** (`cargo test --test constant_time`, 7 tests) parses the generated
`.S` files and proves:

- Exactly **2 conditional branches** in each backend — the two outer-loop
  back-edges, one per curve. Nothing branches on a value.
- Every memory operand is `[reg, #imm]` (ARM) / `l32i rd, rs, imm` (Xtensa).
  No register-offset addressing, so no address depends on a secret.
- Every opcode is on a fixed-latency allow-list. No `udiv`/`sdiv`, no IT blocks.

**Dynamic check** (`harness/src/bin/ct.rs`) runs the real assembly under
deterministic `-icount` across 16 operand classes — zero, one, `p-1`, `p/2`,
all-ones, and randoms, which take both paths through the final conditional
subtraction — and compares against an interleaved **control group** that measures
the *same* input repeatedly:

```
ok p256: operand spread 0 tick(s) ... noise floor 0  (1412023..1412023)
ok p384: operand spread 0 tick(s) ... noise floor 0  (2839017..2839017)
```

That is **real hardware with a true cycle counter**: 16 operand classes × 1000
repetitions produce byte-identical cycle totals, to the cycle. Under QEMU the
same test showed a 1-tick spread, which the interleaved control group proved was
SysTick quantisation (identical inputs varied by the same 1 tick) rather than
operand dependence. Hardware removes the ambiguity entirely.

## Beyond the field layer

Point arithmetic and ECDH are implemented, so this can actually be registered
as an `embassy-crypto-driver` once the ECC traits return upstream (they landed
2026-08-29 and were removed 2026-09-01, which currently blocks the STM32 PKA
hardware driver too — it has nothing to register against either).

- **Complete formulas.** Points use homogeneous projective coordinates with the
  Renes–Costello–Batina complete addition formulas for `a = -3`. One formula,
  no exceptions: correct for `P+Q`, `P+P`, `P+(-P)` and the identity. There is
  deliberately **no separate doubling routine** — the classic way to leak a
  scalar is a special case that only fires when the accumulator happens to
  equal the input point.
- **Scalar multiplication** is double-and-add-always with a branchless select,
  so every bit costs one doubling and one addition regardless of its value.
- **ECDH validates its inputs.** `shared_secret` rejects peer points that are
  not on the curve — skipping that check is the invalid-curve attack, which
  recovers a private key from a handful of exchanges. Scalars must be in
  `[1, n)`, and coordinates must be reduced mod p.

Validated against an independent oracle: `gen/gen_point_vectors.py` computes
`k*G` with plain **affine** arithmetic and explicit special cases — a different
algorithm from the projective formulas under test, so a transcription error
cannot be mirrored in both. Vectors include `k = n` (the identity) and
`k = n-1` (`-G`). The SEC1 byte encoding is pinned separately, because two
sides agreeing proves consistency, not correctness.

## Design

Performance on a 32-bit MCU is decided almost entirely by one operation, so the
assembly surface is deliberately tiny: `mul_mont` and nothing else. Everything
above the field layer stays portable Rust.

**The modulus is a constant, so treat it like one.** Each NIST prime has only
three distinct limb values. On Cortex-M4 they are held in registers (`mvn r12,#0`
etc.), removing one `ldr` from every reduction step — n² loads per multiply. On
Xtensa, where a full step costs 11 instructions, limbs equal to 0 or 1 skip the
product entirely (5 and 8 instructions respectively). Together this moved P-256
from 1.72× to 1.88× and P-384 from 1.47× to 1.62×.

**Montgomery CIOS, and one lucky fact.** Both NIST primes satisfy
`p ≡ -1 (mod 2^32)`, so `n0' = -p⁻¹ mod 2^32 == 1` and the per-word reduction
multiplier `m = t[0] * n0'` collapses to `m = t[0]` — no multiply at all.
`gen/gen_params.py` *asserts* this rather than trusting it.

**Cortex-M4** is built on `UMAAL`:

```
UMAAL RdLo, RdHi, Rn, Rm   ->   RdHi:RdLo = Rn*Rm + RdHi + RdLo
```

which is exactly the CIOS inner step `(C, t[j]) = t[j] + a[j]*b[i] + C`, in one
cycle, and cannot overflow. A P-256 multiply executes 128 of them, P-384 288.

**Xtensa LX7** has no `UMAAL` and, more consequentially, **no carry flag**. The
same step costs eight instructions, using `SALTU` (set-if-less-than-unsigned) as
a branchless carry primitive:

```
mull lo,aj,bi | muluh hi,aj,bi | add lo,lo,tj | saltu c,lo,tj
add hi,hi,c   | add lo,lo,C    | saltu c,lo,C | add hi,hi,c
```

That 8:1 ratio is the honest ceiling on how close Xtensa can get to Cortex-M4.

The assembly is **generated** (`gen/gen_asm_*.py`), not hand-maintained — the
alternative is hand-editing hundreds of carry-chained instructions, which is how
silent carry bugs happen.

## Status

| | correctness | speed |
|---|---|---|
| portable (host) | ✅ vs `num-bigint`, incl. carry edge cases | — |
| Cortex-M4 (QEMU `mps2-an386`) | ✅ 128 KAT + 500 differential / curve | ✅ |
| Cortex-M7 (QEMU `mps2-an500`) | ✅ same binary, all pass | — |
| Xtensa LX7 (QEMU `esp32s3`) | ✅ 128 vectors / curve | ✅ |
| **nRF52840, real silicon** | ✅ 128 KAT + 500 differential / curve | ✅ 1.59× / 1.36× vs fiat-crypto |
| **ESP32-S3, real silicon** | ✅ 128 vectors / curve | ✅ 1703 / 3823 cycles |
| constant time, real silicon | ✅ **0 cycles of spread**, both curves | — |

**Every test harness has been mutation-tested** — a deliberate bug was injected
and each harness confirmed to fail — so a green run means something.

### Not done yet

- **Register-resident accumulator (the big one).** Now measured: Emill is 3.68×
  faster on P-256 purely because his accumulator never touches memory. Getting
  close needs `t[]` held in registers, which on Cortex-M4 means using the FPU
  bank as scratch the way he does. Until then, P-256 users on Cortex-M4 should
  use his library.
- **ECDSA.** ECDH is done; signing/verification still to come.
- **Squaring** currently routes through `mul_mont`; a dedicated routine skips
  ~half the partial products.

## Building and running

```bash
# Host: portable reference vs num-bigint, plus the constant-time audit
cargo test

# Cortex-M4 correctness + benchmark + constant-time (QEMU)
cd harness && cargo run --release --bin nistp-harness
qemu-system-arm -machine mps2-an386 -cpu cortex-m4 -icount shift=0 -nographic \
  -semihosting-config enable=on,target=native \
  -kernel target/thumbv7em-none-eabihf/release/bench

# Xtensa LX7 correctness (needs the esp toolchain + Espressif's QEMU fork)
cd harness-xtensa && ./run.sh

# Regenerate constants and assembly
python3 gen/gen_params.py && python3 gen/gen_asm_cortex_m4.py \
  && python3 gen/gen_asm_xtensa.py && python3 gen/gen_kat.py
```

### Toolchain notes

- **Cortex-M** builds on **stable** Rust; the assembly goes through `global_asm!`
  with `options(raw)` (without `raw`, `push {r4-r11, lr}` is parsed as a format
  placeholder).
- **Xtensa** needs the `esp` toolchain (`espup install`). LLVM's Xtensa assembler
  does **not** implement `SALTU`, so that file cannot go through `global_asm!`;
  `build.rs` assembles it with the esp GNU toolchain and links it as a static
  library. This also keeps the `.S` a clean standalone file.
- Backend selection is done in `build.rs` **from the target triple**, not from
  `target_feature`: `dsp`/`v7` are not exposed as cfgs on bare-metal ARM targets,
  so gating on them silently compiles the portable fallback and you benchmark the
  wrong thing.
- **Cortex-M3 is deliberately excluded.** It has `UMAAL`, but its multiplier is
  variable-latency, so this code would not be constant time there. `build.rs`
  emits a warning and falls back to portable.
- **ESP32 (LX6) is deliberately excluded.** No `SALTU`; it uses the portable
  backend.

## Licence

MIT OR Apache-2.0.
