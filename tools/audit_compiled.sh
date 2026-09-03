#!/usr/bin/env bash
# Static constant-time audit of COMPILED RUST, not just the hand-written .S.
#
# tests/constant_time.rs audits the .S files, but the point and scalar layers
# are Rust -- and Rust that reads as branchless can still COMPILE to branches.
# This disassembles a symbol and lists its conditional control flow so it can
# be checked against what is expected:
#
#   OK    loop back-edges comparing against a public constant (limb counts,
#         table sizes), and IT blocks, which are constant time on Cortex-M
#   NOT   any branch whose condition derives from a secret
#
# Usage: tools/audit_compiled.sh <elf> <symbol-substring>
set -uo pipefail
ELF="${1:?usage: audit_compiled.sh <elf> <symbol-substring>}"
PAT="${2:?}"
SYM=$(arm-none-eabi-nm -S --size-sort "$ELF" | grep -i "$PAT" | tail -1)
[ -n "$SYM" ] || { echo "no symbol matching '$PAT'" >&2; exit 1; }
ADDR=$(echo "$SYM" | awk '{print $1}'); SIZE=$(echo "$SYM" | awk '{print $2}')
echo "symbol: $SYM"
echo "--- conditional control flow (with the compare that drives it) ---"
arm-none-eabi-objdump -d --start-address=0x$ADDR --stop-address=$((0x$ADDR + 0x$SIZE)) "$ELF" \
  | grep -B2 -E "\b(beq|bne|bcs|bcc|bmi|bpl|bhi|bls|bge|blt|bgt|ble|cbz|cbnz|it|ite|itt)\b" \
  | sed 's/^/  /'
