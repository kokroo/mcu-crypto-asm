# Vendored third-party code

Used **only for benchmarking and cross-checking**. None of it is linked into
the `nistp-mcu` library itself — it lives in the benchmark harnesses.

| directory | upstream | licence | why |
|---|---|---|---|
| `emill/` | [Emill/P256-Cortex-M4](https://github.com/Emill/P256-Cortex-M4) | MIT (`emill/LICENSE.txt`) | The reference hand-optimised P-256 for Cortex-M4. Benchmark baseline, and the bar this crate does not clear on that curve. |
| `fiat-crypto/` | [mit-plv/fiat-crypto](https://github.com/mit-plv/fiat-crypto) | MIT OR Apache-2.0 OR BSD-1-Clause | Formally-verified generated field arithmetic; the same code RustCrypto's `p256`/`p384` vendor. Primary benchmark baseline. |

Both are unmodified upstream sources. `emill/shim.S` and
`fiat-crypto/shim.c` are ours — thin wrappers exposing internal or
`static inline` symbols so the harness can call them.
