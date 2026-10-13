MEMORY
{
  bootrom_mem (rx) : ORIGIN = 0x10000, LENGTH = 0x2000   /* BootROMLocated size in Configs.scala */
  memory_mem (rwx) : ORIGIN = 0x80000000, LENGTH = 0x10000
}
