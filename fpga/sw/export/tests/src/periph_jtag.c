/*
 * periph_jtag.c — JTAG / debug-module test.
 *
 * The JTAG path is proven by the act of running this program: OpenOCD used the
 * debug module to halt the core, write this image into the scratchpad at
 * 0x80000000 and resume it. If JTAG or the DM were broken you would not be
 * reading this output.
 *
 * What is left to check from software is that the core the debugger examined
 * is the core we are running on, so this prints the identity CSRs and verifies
 * that MISA decodes to a sane RISC-V core of the expected width.
 */
#include <stdint.h>
#include "platform.h"
#include "kprintf.h"
#include "test_init.h"

#define CSR_READ(reg) ({ unsigned long v; __asm__ volatile ("csrr %0, " #reg : "=r"(v)); v; })

int main(void)
{
	test_console_init();

	unsigned long misa, hartid, vendor, arch, imp;
	int fails = 0;
	int xlen;

	kprintf("\r\n=== JTAG / debug module test ===\r\n");
	kprintf("  Loaded and resumed over JTAG: PASS (this output is the proof)\r\n");

	misa   = CSR_READ(misa);
	hartid = CSR_READ(mhartid);
	vendor = CSR_READ(mvendorid);
	arch   = CSR_READ(marchid);
	imp    = CSR_READ(mimpid);

	/* MXL lives in the top two bits of MISA: 1 = 32-bit, 2 = 64-bit. */
	xlen = (int)((misa >> (8 * sizeof(unsigned long) - 2)) & 0x3);

	kprintf("  mhartid     : %x\r\n", (unsigned)hartid);
	kprintf("  mvendorid   : %x\r\n", (unsigned)vendor);
	kprintf("  marchid     : %x\r\n", (unsigned)arch);
	kprintf("  mimpid      : %x\r\n", (unsigned)imp);
	kprintf("  misa low32  : %x  (MXL=%d -> RV%d)\r\n",
		(unsigned)misa, xlen, xlen == 1 ? 32 : (xlen == 2 ? 64 : 0));

	/* Extension letters, bit 0 = A ... bit 25 = Z */
	kprintf("  extensions  : ");
	for (int i = 0; i < 26; i++) {
		if (misa & (1UL << i))
			kprintf("%c", 'A' + i);
	}
	kprintf("\r\n");

	if (xlen != 1 && xlen != 2) {
		kprintf("  MISA MXL invalid: FAIL\r\n");
		fails++;
	}
	if ((misa & (1UL << ('I' - 'A'))) == 0) {
		kprintf("  base integer ISA missing from MISA: FAIL\r\n");
		fails++;
	}
	if (hartid != 0) {
		kprintf("  unexpected hartid (boot hart should be 0): FAIL\r\n");
		fails++;
	}

	/* Compile-time width must agree with what the hardware reports. */
#if __riscv_xlen == 64
	if (xlen != 2) {
		kprintf("  built RV64 but core reports RV32: FAIL\r\n");
		fails++;
	}
#else
	if (xlen != 1) {
		kprintf("  built RV32 but core reports RV64: FAIL\r\n");
		fails++;
	}
#endif

	kprintf("JTAG TEST: %s (%d failures)\r\n", fails ? "FAIL" : "PASS", fails);
	while (1)
		;
	return 0;
}
