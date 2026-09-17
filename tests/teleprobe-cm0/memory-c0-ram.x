/* STM32C031C6 (Cortex-M0+, e.g. NUCLEO-C031C6), RAM-ONLY execution.
 * Running completely from internal SRAM (12 KB at 0x20000000).
 *
 * FLASH is mapped to the lower 8 KB of SRAM for .vector_table, .text, .rodata.
 * RAM is mapped to the upper 4 KB of SRAM for .data, .bss, heap, and stack.
 *
 * Teleprobe / probe-rs loads the ELF directly into SRAM via SWD.
 * Writes ZERO bytes to hardware flash, ensuring zero flash wear and safety.
 */
MEMORY
{
  FLASH : ORIGIN = 0x20000000, LENGTH = 8K
  RAM   : ORIGIN = 0x20002000, LENGTH = 4K
}
