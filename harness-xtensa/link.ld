/* Xtensa L32R reaches only backwards, so literal pools must precede their
   code -- otherwise the link fails with "dangerous relocation". */
MEMORY { iram (rwx) : ORIGIN = 0x40378000, LENGTH = 0x40000
         dram (rw)  : ORIGIN = 0x3FC90000, LENGTH = 0x40000 }
ENTRY(_start)
SECTIONS {
  .text : {
    *(.entry.literal) *(.entry)
    *(.literal .text .literal.* .text.*)
  } > iram

  /* .rodata MUST live in DRAM. On the ESP32-S3, 0x403x_xxxx is the
     instruction bus; a data load from there raises EXCCAUSE=3
     (LoadStoreError) -- which is exactly what the KAT tables did when they
     were linked into .text. */
  .rodata : { *(.rodata .rodata.*) } > dram
  /* Fixed address so a debugger can read the results without any serial. */
  .results 0x3FCA0000 : { KEEP(*(.results)) }
  .data : { *(.data .data.*) } > dram
  .bss  : { *(.bss .bss.*) *(COMMON) } > dram
  _stack_top = ORIGIN(dram) + LENGTH(dram) - 16;
}
