#!/usr/bin/env bash
# Run every check: host tests, Cortex-M4/M7 correctness, benchmark,
# constant-time, and Xtensa LX7 correctness. Non-zero exit on any failure.
set -uo pipefail
cd "$(dirname "$0")"
# cargo lives here on a non-login shell; without this every cargo step
# silently "fails" with command not found while the QEMU steps still pass.
export PATH="$HOME/.cargo/bin:$PATH"
fail=0
run() { echo; echo "=== $1 ==="; shift; "$@" || { echo "FAILED"; fail=1; }; }

QEMU_ARM=(qemu-system-arm -machine mps2-an386 -cpu cortex-m4 -nographic
          -semihosting-config enable=on,target=native)

run "host: oracle + constant-time audit" cargo test
run "host: portable backend correctness" cargo test --features force-portable
( cd harness && cargo build --release ) || fail=1
run "Cortex-M4: correctness"  "${QEMU_ARM[@]}" -kernel harness/target/thumbv7em-none-eabihf/release/nistp-harness
run "Cortex-M7: correctness"  qemu-system-arm -machine mps2-an500 -cpu cortex-m7 -nographic \
      -semihosting-config enable=on,target=native \
      -kernel harness/target/thumbv7em-none-eabihf/release/nistp-harness
run "Cortex-M4: constant time" "${QEMU_ARM[@]}" -icount shift=0 -kernel harness/target/thumbv7em-none-eabihf/release/ct
run "Cortex-M4: benchmark"     "${QEMU_ARM[@]}" -icount shift=0 -kernel harness/target/thumbv7em-none-eabihf/release/bench
if [ -x "${ESP_QEMU:-/tmp/espqemu/qemu/bin/qemu-system-xtensa}" ]; then
  run "Xtensa LX7: correctness"  ./harness-xtensa/run.sh
else
  echo; echo "=== Xtensa LX7: correctness ==="
  echo "SKIP - Espressif's qemu-system-xtensa not installed (optional)."
  echo "      Only its fork has an esp32s3 machine; vanilla QEMU lacks SALTU."
  echo "      Get it from github.com/espressif/qemu and set ESP_QEMU."
fi

echo; [ $fail -eq 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $fail
