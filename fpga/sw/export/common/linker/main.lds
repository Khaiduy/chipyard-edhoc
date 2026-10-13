OUTPUT_ARCH("riscv")
ENTRY(_prog_start)

INCLUDE memory.lds

PHDRS
{
  text PT_LOAD;
  data PT_LOAD;
  bss PT_LOAD;
}

SECTIONS
{
  PROVIDE(_ram = ORIGIN(memory_mem));
  PROVIDE(_ram_end = _ram + LENGTH(memory_mem));

  .text ALIGN((ORIGIN(memory_mem) + 0x0), 8) : AT(ALIGN((ORIGIN(memory_mem) + 0x0), 8)) {
    PROVIDE(_ftext = .);
    *(.text.init)
    *(.text.unlikely .text.unlikely.*)
    *(.text .text.* .gnu.linkonce.t.*)
    PROVIDE(_etext = .);
    . += 0x40;
  } >memory_mem  :text

  .eh_frame ALIGN((ADDR(.text) + SIZEOF(.text)), 8) : AT(ALIGN((LOADADDR(.text) + SIZEOF(.text)), 8)) {
    *(.eh_frame)
  } >memory_mem  :text

  .srodata ALIGN((ADDR(.eh_frame) + SIZEOF(.eh_frame)), 8) : AT(ALIGN((LOADADDR(.eh_frame) + SIZEOF(.eh_frame)), 8)) ALIGN_WITH_INPUT {
    *(.srodata.*)
  } >memory_mem  :data

  .data ALIGN((ADDR(.srodata) + SIZEOF(.srodata)), 8) : AT(ALIGN((LOADADDR(.srodata) + SIZEOF(.srodata)), 8)) ALIGN_WITH_INPUT {
    *(.data .data.* .gnu.linkonce.d.*)
    *(.tohost)
  } >memory_mem  :data

  .sdata ALIGN((ADDR(.data) + SIZEOF(.data)), 8) : AT(ALIGN((LOADADDR(.data) + SIZEOF(.data)), 8)) ALIGN_WITH_INPUT {
    *(.sdata .sdata.* .gnu.linkonce.s.*)
  } >memory_mem  :data

  .rodata ALIGN((ADDR(.sdata) + SIZEOF(.sdata)), 8) : AT(ALIGN((LOADADDR(.sdata) + SIZEOF(.sdata)), 8)) ALIGN_WITH_INPUT {
    *(.rodata .rodata.* .gnu.linkonce.r.*)
    *(.dtb)
  } >memory_mem  :data

  PROVIDE(_data = ADDR(.rodata));
  PROVIDE(_data_lma = LOADADDR(.rodata));
  PROVIDE(_edata = .);

  .bss ALIGN((ADDR(.rodata) + SIZEOF(.rodata)), 8) : AT(ALIGN((LOADADDR(.rodata) + SIZEOF(.rodata)), 8)) ALIGN(8) {
    PROVIDE(_fbss = .);
    PROVIDE(__global_pointer$ = . + 0x7C0);
    *(.sbss .sbss.* .gnu.linkonce.sb.*)
    *(.bss .bss.* .gnu.linkonce.b.*)
    . = ALIGN(8);
    PROVIDE(_ebss = .);
  } >memory_mem  :bss

  PROVIDE(_end = .);

  /* Heap grows up from _end */
  PROVIDE(_heap_start = _end);
  /* Stack reservation, overridden by the Makefile via
   * -Wl,--defsym=__stack_size=N (STACK_SIZE in mk/config.mk). */
  __stack_reserve = DEFINED(__stack_size) ? __stack_size : 8192;
  PROVIDE(_heap_end = _ram_end - __stack_reserve);

  /* Stack grows down from _ram_end */
  /* No explicit .stack section - just symbols */
  PROVIDE(_sp = _ram_end);  /* Stack starts at top of RAM */

  /* Verify the image plus its stack reservation fits the scratchpad. */
  ASSERT((_end <= (_ram_end - __stack_reserve)),
         "ERROR: Program + stack exceeds RAM. Reduce the image or lower STACK_SIZE.")

  /* Calculate sizes for information */
  _program_size = _end - _ram;
  _available_heap = _heap_end - _heap_start;
  _stack_size = __stack_reserve;
}