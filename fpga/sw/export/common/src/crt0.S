// See LICENSE.Sifive for license details.
#include <platform.h>
#include <smp.h>
#include "common.h"

  .section .text.init
  .option norvc
  .globl _prog_start
_prog_start:
  // perform boot if hart_0, otherwise sleep
  csrr s0, mhartid
  bne s0, zero, _stop
  csrw mie, zero    // Disable all M-mode interrupt enables (s2 may be non-zero from prior run)
  la t0, _trap_handler
  csrw mtvec, t0    // Set trap vector to safe handler (catches any stale pending interrupt)
  la sp, _ram_end        // Load address of _ram_end from linker script
  
  // Clear .bss section (required for static variables to be zero-initialized)
  la t0, _fbss
  la t1, _ebss
_clear_bss:
  bge t0, t1, _bss_done
#if __riscv_xlen == 64
  sd zero, 0(t0)      // RV64: store doubleword
  addi t0, t0, 8
#else
  sw zero, 0(t0)      // RV32: use sw (store word) instead of sd
  addi t0, t0, 4      // RV32: increment by 4 bytes instead of 8
#endif
  j _clear_bss
_bss_done:

  // Paint all free RAM with a canary word so stack_highwater() can report
  // peak depth at runtime. The painted region is [_end, _ram_end): the heap
  // is a static .bss array, so everything above _end is stack.
  //
  // Painting the whole gap rather than just [_heap_end, _ram_end) is what
  // makes an overrun of the declared reservation visible: a stack that grows
  // past __stack_reserve lands in the incidental free RAM below it and works
  // by luck, which a reservation-sized canary cannot distinguish from a
  // stack that merely reached the bottom. crt0 uses no stack before
  // `call main`, so all of it can be painted.
  la t0, _end
  la t1, _ram_end
#if __riscv_xlen == 64
  li t2, 0x5A5A5A5A
  slli t3, t2, 32
  or t2, t2, t3
#else
  li t2, 0x5A5A5A5A
#endif
_paint_stack:
  bgeu t0, t1, _paint_done
#if __riscv_xlen == 64
  sd t2, 0(t0)
  addi t0, t0, 8
#else
  sw t2, 0(t0)
  addi t0, t0, 4
#endif
  j _paint_stack
_paint_done:

  //li sp, (PAYLOAD_DEST + 0xff0) // 0x80000ff0
  //li sp, (0x80000000 + 0xff0) // 0x80000ff0
  csrr a0, mhartid
  call main
  li s1, MEMORY_MEM_ADDR        // 0x80000000
  jr s1
_stop:
  wfi
_loopback:
  j _loopback

  .align 2
_trap_handler:
  // Minimal trap handler: clear mie + return (handles any stale pending interrupt on boot)
  csrw mie, zero
  csrw mstatus, zero
  mret
