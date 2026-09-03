#!/usr/bin/env bash
# Build + run the Xtensa LX7 correctness harness under Espressif's QEMU fork.
#
# Needs: the esp GNU toolchain (`espup install`) and Espressif's qemu-system-xtensa,
# which is the only build with an `esp32s3` machine. Vanilla qemu-system-xtensa
# only has dc232b/de212 cores, which lack SALTU.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

TC="${XTENSA_ESP_ELF_ROOT:-}"
if [ -z "$TC" ]; then
    GCC="$(command -v xtensa-esp-elf-gcc 2>/dev/null || \
           find "$HOME/.rustup/toolchains" -name xtensa-esp-elf-gcc -type f 2>/dev/null | head -1)"
    [ -n "$GCC" ] || { echo "xtensa-esp-elf-gcc not found; run \`espup install\`" >&2; exit 1; }
    TC="$(dirname "$(dirname "$GCC")")"
fi
QEMU="${ESP_QEMU:-/tmp/espqemu/qemu/bin/qemu-system-xtensa}"
[ -x "$QEMU" ] || { echo "Espressif qemu-system-xtensa not found at $QEMU (set ESP_QEMU)" >&2; exit 1; }

export XTENSA_GNU_CONFIG="$TC/lib/xtensa_esp32s3.so"

"$TC/bin/xtensa-esp-elf-gcc" -nostdlib -nostartfiles -O2 -Wall -I "$HERE" \
    -T "$HERE/link.ld" "$HERE/start.S" "$HERE/main.c" "$HERE/../asm/xtensa_lx7.S" "$HERE/../third_party/fiat-crypto/shim.c" -I "$HERE/../third_party/fiat-crypto" \
    -o "$HERE/xtensa-harness.elf" || exit 1

# The bare-metal harness cannot ask QEMU to exit, so it spins after printing.
# `timeout` killing QEMU is EXPECTED; the verdict comes from the OUTPUT, not
# from QEMU's exit status.
out="$(timeout 25 "$QEMU" -machine esp32s3 -cpu esp32s3 -nographic \
        -kernel "$HERE/xtensa-harness.elf" 2>&1 || true)"

echo "$out" | grep -vE "SPI Flash|both -bios|terminating on signal"

if echo "$out" | grep -q "ALL PASS"; then
    exit 0
fi
echo "xtensa harness did not report ALL PASS" >&2
exit 1
