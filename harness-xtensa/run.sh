#!/usr/bin/env bash
# Build + run the Xtensa LX7 correctness harness under Espressif's QEMU fork.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TC="${XTENSA_ESP_ELF_ROOT:-$(dirname "$(dirname "$(command -v xtensa-esp-elf-gcc 2>/dev/null || \
   find "$HOME/.rustup/toolchains" -name xtensa-esp-elf-gcc -type f 2>/dev/null | head -1)")")}"
QEMU="${ESP_QEMU:-/tmp/espqemu/qemu/bin/qemu-system-xtensa}"
export XTENSA_GNU_CONFIG="$TC/lib/xtensa_esp32s3.so"

"$TC/bin/xtensa-esp-elf-gcc" -nostdlib -nostartfiles -O2 -Wall -I "$HERE" \
    -T "$HERE/link.ld" "$HERE/start.S" "$HERE/main.c" "$HERE/../asm/xtensa_lx7.S" \
    -o "$HERE/xtensa-harness.elf"

exec timeout 25 "$QEMU" -machine esp32s3 -cpu esp32s3 -nographic \
    -kernel "$HERE/xtensa-harness.elf"
