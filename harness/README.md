# Harness

## Correctness (emulated Cortex-M4 / M7)
    cargo run --release --bin nistp-harness
    # or pick the core:
    qemu-system-arm -machine mps2-an500 -cpu cortex-m7 -nographic \
        -semihosting-config enable=on,target=native \
        -kernel target/thumbv7em-none-eabihf/release/nistp-harness

## Benchmark
    cargo build --release --bin bench
    qemu-system-arm -machine mps2-an386 -cpu cortex-m4 -icount shift=0 -nographic \
        -semihosting-config enable=on,target=native \
        -kernel target/thumbv7em-none-eabihf/release/bench

`-icount shift=0` is required: it makes QEMU's virtual clock advance
deterministically with instructions executed, which is what makes SysTick a
valid *relative* measure. The binary runs a linearity self-check and refuses
to report numbers if the counter does not scale with work.

On real hardware the same binary uses DWT CYCCNT and reports exact cycles.

## Real Hardware (RAM execution)

### nRF52840 (Cortex-M4)
    NISTP_MEMORY_X=memory-nrf-ram.x cargo build --release --bin bench
    probe-rs run --chip nRF52840_xxAA target/thumbv7em-none-eabihf/release/bench

### STM32H563 (Cortex-M33)
    NISTP_MEMORY_X=memory-stm32h5-ram.x cargo build --release --target thumbv8m.main-none-eabihf --bin bench
    probe-rs run --chip STM32H563ZI target/thumbv8m.main-none-eabihf/release/bench

