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

### Speed — vs `fiat-crypto`, emulated Cortex-M4

`fiat-crypto`'s `p256_32`/`p384_32` is the formally-verified generated Montgomery
arithmetic that the RustCrypto `p256`/`p384` crates vendor internally, so
`fiat_p256_mul` is *the same operation* as our `mul_mont` — a true head-to-head
rather than a comparison across abstraction levels.

| operation | fiat-crypto | nistp-mcu | speedup |
|---|---|---|---|
| P-256 modular multiply | 32925 | 19050 | **1.72×** |
| P-384 modular multiply | 57125 | 38650 | **1.47×** |

*Ticks per 1000 operations, QEMU `mps2-an386` with `-icount shift=0`.*

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
ok p256: operand spread 1 tick  ==  same-input noise floor 1 tick  (19050..19051)
ok p384: operand spread 1 tick  ==  same-input noise floor 1 tick  (38700..38701)
```

The control group is what makes this meaningful: it shows the 1-tick variation is
SysTick quantisation, present even for identical inputs, and not operand
dependence.

## Design

Performance on a 32-bit MCU is decided almost entirely by one operation, so the
assembly surface is deliberately tiny: `mul_mont` and nothing else. Everything
above the field layer stays portable Rust.

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
| Cortex-M4 (QEMU `mps2-an386`) | ✅ 16 KAT + 500 differential / curve | ✅ 1.72× / 1.47× vs fiat-crypto |
| Cortex-M7 (QEMU `mps2-an500`) | ✅ same binary, all pass | — |
| Xtensa LX7 (QEMU `esp32s3`) | ✅ 128 vectors / curve | ⏳ pending |
| real hardware | ⏳ pending | ⏳ pending |

**Every test harness has been mutation-tested** — a deliberate bug was injected
and each harness confirmed to fail — so a green run means something.

### Not done yet

- **Hardware cycle counts.** The bench boards (nRF52840 Cortex-M4 + ESP32-S3,
  both on J-Link) were in use; nothing has been flashed. The same benchmark
  binary reports exact DWT CYCCNT cycles when run there.
- **Emill head-to-head.** His `P256_mulmod` is a non-AAPCS internal symbol
  (inputs in r1/r2, result returned in r0–r7, clobbers everything) so it needs a
  hand-written shim. Worth doing, and **he is expected to win on P-256**: his
  code uses the FPU registers as extra scratch (`vldm r1,{s8-s15}`) to escape
  Cortex-M4's register pressure, where this generic CIOS spills `t[]` to the
  stack. That is the top optimisation lead here. P-384 has no equivalent to
  compare against.
- **Point arithmetic / ECDH / ECDSA.** This crate is the field layer only.
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
