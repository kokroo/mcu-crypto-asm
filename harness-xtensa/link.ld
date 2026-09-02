/* Xtensa L32R reaches only backwards, so literal pools must precede their
   code -- otherwise the link fails with "dangerous relocation". */
MEMORY { iram (rwx) : ORIGIN = 0x40378000, LENGTH = 0x40000
         dram (rw)  : ORIGIN = 0x3FC90000, LENGTH = 0x40000 }
ENTRY(_start)
SECTIONS {
  .text : {
    *(.entry.literal) *(.entry)
    *(.literal .text .literal.* .text.*)
    *(.rodata .rodata.*)
  } > iram
  .data : { *(.data .data.*) } > dram
  .bss  : { *(.bss .bss.*) *(COMMON) } > dram
  _stack_top = ORIGIN(dram) + LENGTH(dram) - 16;
}
