/* nRF52840 (Cortex-M4, e.g. NRF52840-DK / T-Echo), RAM-ONLY execution.
 * Running from SRAM (256 KB at 0x20000000).
 * Writes ZERO bytes to hardware flash.
 */
MEMORY
{
  FLASH : ORIGIN = 0x20000000, LENGTH = 200K
  RAM   : ORIGIN = 0x20032000, LENGTH = 56K
}
