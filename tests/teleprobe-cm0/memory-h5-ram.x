/* STM32H563 (Cortex-M33, e.g. NUCLEO-H563ZI), RAM-ONLY execution.
 * Running from SRAM1 (256 KB at 0x20000000).
 * Writes ZERO bytes to hardware flash.
 */
MEMORY
{
  FLASH : ORIGIN = 0x20000000, LENGTH = 200K
  RAM   : ORIGIN = 0x20032000, LENGTH = 56K
}
