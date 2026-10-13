// See LICENSE.Sifive for license details.
#include <platform.h>
#include <smp.h>
#include "common.h"

  .section .text.init
  .option norvc
  .globl _prog_start
_prog_start:
  li sp, (PAYLOAD_DEST + MEMORY_MEM_SIZE)
  call main
  csrr a0, mhartid // hartid for next level bootloader
  li s1, PAYLOAD_DEST
  // main() wrote the payload through the (write-back) D$; the I$ fetches it over
  // the bus. RISC-V requires fence.i between storing instructions and executing
  // them, otherwise the I$ can fetch stale data for lines still dirty in the D$.
  fence.i
  jr s1

  .section .dtb
  .align 3
dtb:
