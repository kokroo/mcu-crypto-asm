/* ESP32-S3 bare-metal layout for the on-target harness.
 *
 * ⚠ IRAM and DRAM are TWO WINDOWS ONTO THE SAME PHYSICAL SRAM:
 *      IRAM 0x40378000  ==  DRAM 0x3FC88000
 * so an IRAM region and a DRAM region that look far apart can silently
 * overlap. That is exactly what happened when the fully-unrolled FIOS code
 * grew .text past 0x40390000: it wrote through onto .rodata and corrupted the
 * P-384 test vectors, which looked like an arithmetic bug for a while.
 *
 * Layout, chosen so the two windows cannot collide:
 *   IRAM 0x40378000 + 0x18000  aliases DRAM 0x3FC88000 .. 0x3FCA0000
 *   DRAM starts at 0x3FCA0000, immediately above that.
 */
MEMORY { iram (rwx) : ORIGIN = 0x40378000, LENGTH = 0x18000
         dram (rw)  : ORIGIN = 0x3FCA0000, LENGTH = 0x20000 }
ENTRY(_start)
SECTIONS {
  /* Xtensa L32R reaches only backwards, so literal pools precede their code. */
  .text : {
    *(.entry.literal) *(.entry)
    *(.literal .text .literal.* .text.*)
  } > iram

  /* .rodata must be in DRAM: a data load from the 0x403x_xxxx instruction
     window raises EXCCAUSE=3 (LoadStoreError) on the S3. */
  .rodata : { *(.rodata .rodata.*) } > dram

  /* Fixed address for the debugger to read results from; this board has no
     serial, only a J-Link. Placed well clear of .rodata. */
  .results 0x3FCB0000 : { KEEP(*(.results)) }
  .data : { *(.data .data.*) } > dram
  .bss  : { *(.bss .bss.*) *(COMMON) } > dram
  _stack_top = 0x3FCBFFF0;

  /* Fail the LINK rather than corrupt memory if .text ever reaches the alias
     of the DRAM origin. */
  ASSERT(ADDR(.text) + SIZEOF(.text) <= 0x40390000,
         ".text has grown into the DRAM alias (IRAM 0x40390000 == DRAM 0x3FCA0000)")
}
