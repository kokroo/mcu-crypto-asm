#!/usr/bin/env bash
# Build the CALL0 harness and run it on a real ESP32-S3 over J-Link/OpenOCD.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TC="${XTENSA_ESP_ELF_ROOT:-$(dirname "$(dirname "$(find "$HOME/.rustup/toolchains" -name xtensa-esp-elf-gcc -type f 2>/dev/null | head -1)")")}"
OOCD="$HOME/.espressif/tools/openocd-esp32/openocd-esp32/bin/openocd"
SCR="$HOME/.espressif/tools/openocd-esp32/openocd-esp32/share/openocd/scripts"
export XTENSA_GNU_CONFIG="$TC/lib/xtensa_esp32s3.so"

"$TC/bin/xtensa-esp-elf-gcc" -mabi=call0 -DNO_UART -nostdlib -nostartfiles -O2 -Wall -I "$HERE" \
    -T "$HERE/link.ld" "$HERE/start-call0.S" "$HERE/main.c" \
    "$HERE/../asm/xtensa_lx7_call0.S" -o "$HERE/xtensa-hw.elf" || exit 1

# Take the entry point FROM THE ELF. The linker places the literal pool at the
# start of the section (Xtensa L32R only reaches backwards), so the section
# base is DATA, not code -- resuming there executes literals as instructions
# and vectors straight to ROM.
ENTRY=$("$TC/bin/xtensa-esp-elf-readelf" -h "$HERE/xtensa-hw.elf" | awk '/Entry point/ {print $4}')
echo "entry point: $ENTRY"

# RAM-only image: nothing is written to flash, so the board's firmware survives.
timeout 150 "$OOCD" -s "$SCR" -f interface/jlink.cfg -f target/esp32s3.cfg \
  -c "adapter serial 000069651147" -c "adapter speed 2000" \
  -c "init" -c "reset halt" -c "load_image $HERE/xtensa-hw.elf" \
  -c "reg pc $ENTRY" -c "resume" -c "sleep 6000" -c "halt" \
  -c "mdw 0x3FCA0000 8" -c "shutdown" 2>&1 | grep -E "0x3fca0000|halted, PC"
