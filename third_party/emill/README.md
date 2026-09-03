# Emill/P256-Cortex-M4 (vendored, MIT)

Upstream: https://github.com/Emill/P256-Cortex-M4 (commit in `COMMIT`).
Files are **unmodified**; only the assembly and its config header are vendored,
which is all that is needed for the field-multiply comparison.

`P256_mulmod` is the reference hand-optimised P-256 Montgomery multiply and is
the operation `mcu-crypto`'s `mul_mont` competes with. It is an *internal*
symbol with a non-AAPCS convention:

    inputs:  r1 -> in1, r2 -> in2   (both 8-word, Montgomery form)
    output:  r0-r7                  (returned in registers, not memory)
    clobbers: everything else

`shim.S` wraps it in a normal AAPCS function. Because `.global` must appear in
the same assembly unit as the definition, `harness/build.rs` concatenates
`shim.S` onto a copy of the upstream file rather than editing it in place.
