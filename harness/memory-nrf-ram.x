/* nRF52840 (T-Echo), RAM-ONLY execution.
 *
 * The board carries a live embassy-boot bootloader at 0x0 and a Helius app at
 * 0x7000. Nothing here may touch flash, so the "FLASH" region -- which is only
 * a name cortex-m-rt uses for .vector_table/.text/.rodata -- is pointed at RAM.
 * A reset returns the board to its normal firmware, untouched.
 *
 * nRF52840 has 256K RAM at 0x20000000.
 */
MEMORY
{
  FLASH : ORIGIN = 0x20000000, LENGTH = 200K
  RAM   : ORIGIN = 0x20032000, LENGTH = 56K
}
