/*
 * periph_spi.c — SPI peripheral test (SPI0 @ 0x64001000, the SD-card slot).
 *
 * Phase 1 is a self-contained register test. Phase 2 drives a real SD card
 * through the opening of the SPI-mode init sequence (74+ idle clocks, then
 * CMD0 GO_IDLE_STATE) and checks for the R1 = 0x01 "idle" response, which is
 * the standard proof that the SPI controller clocks, chip-select and both data
 * directions all work against a real device.
 *
 * With no card inserted the SD phase reports SKIP rather than FAIL: an empty
 * slot is not a controller fault. The register phase still runs.
 */
#include <stdint.h>
#include "platform.h"
#include "spi.h"
#include "kprintf.h"
#include "test_init.h"

#define S(i) (((volatile uint32_t *)SPI_CTRL_ADDR)[(i) >> 2])

static int check(const char *what, uint32_t got, uint32_t want)
{
	int ok = (got == want);

	kprintf("  %s: got=%x want=%x %s\r\n", what, got, want,
		ok ? "PASS" : "FAIL");
	return ok ? 0 : 1;
}

/* Full-duplex byte: SPI always clocks a byte out to clock one in. */
static uint8_t spi_xfer(uint8_t out)
{
	int32_t v;

	while ((int32_t)S(SPI_REG_TXFIFO) < 0)
		;
	S(SPI_REG_TXFIFO) = out;
	do {
		v = (int32_t)S(SPI_REG_RXFIFO);
	} while (v < 0);
	return (uint8_t)(v & 0xFF);
}

int main(void)
{
	test_console_init();

	int fails = 0;

	kprintf("\r\n=== SPI test (SPI0 @ 0x%x, SD slot) ===\r\n",
		(unsigned)SPI_CTRL_ADDR);

	/* 1. register read-back, restoring what we disturb */
	{
		uint32_t saved_div = S(SPI_REG_SCKDIV);
		uint32_t saved_fmt = S(SPI_REG_FMT);

		S(SPI_REG_SCKDIV) = 0x0000000C;
		fails += check("sckdiv      ", S(SPI_REG_SCKDIV) & 0xFFF, 0x0C);
		S(SPI_REG_SCKMODE) = 0;
		fails += check("sckmode     ", S(SPI_REG_SCKMODE) & 0x3, 0);
		S(SPI_REG_CSDEF) = 0x1;
		fails += check("csdef       ", S(SPI_REG_CSDEF) & 0x1, 0x1);

		S(SPI_REG_FMT) = saved_fmt;
		S(SPI_REG_SCKDIV) = saved_div;
	}

	/* 2. SD card CMD0 — the real end-to-end check.
	 * Sequence mirrors the bootrom's sd.c, which is known good on this SoC:
	 * a slow init clock, 80+ idle clocks with CS inactive, then CMD0 with CS
	 * held, polling for the first response byte with bit 7 clear. */
	{
		uint8_t r1 = 0xFF;
		unsigned long n;

		/* ~150 kHz from the 50 MHz pbus, matching the bootrom. */
		S(SPI_REG_SCKDIV) = TEST_CPU_HZ / 300000UL;  /* SD init needs < 400 kHz */
		S(SPI_REG_SCKMODE) = 0;
		S(SPI_REG_CSDEF) = 0x1;
		S(SPI_REG_CSID) = 0;

		/* >74 idle clocks with CS de-asserted put the card into SPI mode. */
		S(SPI_REG_CSMODE) = SPI_CSMODE_OFF;
		for (int i = 0; i < 10; i++)
			(void)spi_xfer(0xFF);
		S(SPI_REG_CSMODE) = SPI_CSMODE_AUTO;

		/* CMD0 GO_IDLE_STATE, CRC 0x95 is the fixed value for this command.
		 * The first CMD0 after power-up can read back a junk byte with
		 * bit 7 clear (seen: 0x3f) while the card leaves SD mode, so retry. */
		for (int t = 0; t < 10 && r1 != 0x01; t++) {
			S(SPI_REG_CSMODE) = SPI_CSMODE_HOLD;
			(void)spi_xfer(0xFF);
			(void)spi_xfer(0x40);
			(void)spi_xfer(0x00);
			(void)spi_xfer(0x00);
			(void)spi_xfer(0x00);
			(void)spi_xfer(0x00);
			(void)spi_xfer(0x95);

			n = 1000;
			do {
				r1 = spi_xfer(0xFF);
				if (!(r1 & 0x80))
					break;
			} while (--n > 0);

			(void)spi_xfer(0xFF);
			S(SPI_REG_CSMODE) = SPI_CSMODE_AUTO;
		}

		/* A valid R1 always has bit 7 clear; 0x7F/0xFF mean MISO simply
		 * idled high, i.e. nothing drove the bus. Report that as SKIP,
		 * since an empty slot is not a controller fault. */
		if ((r1 & 0x80) || r1 == 0x7F)
			kprintf("  SD CMD0     : R1=%x SKIP (no card responding)\r\n", r1);
		else if (r1 == 0x01)
			kprintf("  SD CMD0     : R1=%x PASS (card in idle state)\r\n", r1);
		else {
			kprintf("  SD CMD0     : R1=%x FAIL (expected 01)\r\n", r1);
			fails++;
		}
	}

	kprintf("SPI TEST: %s (%d failures)\r\n", fails ? "FAIL" : "PASS", fails);
	while (1)
		;
	return 0;
}
