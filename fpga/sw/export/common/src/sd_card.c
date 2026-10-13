/*
 * sd_card.c — microSD block access over SPI0, see sd_card.h.
 *
 * The SPI-mode command sequence, the R1 polling and the per-sector CRC-16 are
 * adapted from fpga/src/main/resources/arty35t/sdboot/sd.c, which is the code
 * that boots this board; keeping the same sequence avoids re-deriving card
 * quirks. Single-block CMD17/CMD24 only: the radio link, not the card, sets
 * the transfer rate.
 */
#include <stdint.h>

#include "platform.h"
#include "spi.h"
#include "sd_card.h"

#define REG_SPI(off) (((volatile uint32_t *)SPI_CTRL_ADDR)[(off) >> 2])

/* Card init must happen below 400 kHz; the data phase runs faster. 5 MHz is
 * what the bootloader uses and is known good on this board. */
#define SD_INIT_HZ 300000u
#define SD_DATA_HZ 5000000u

static uint32_t addr_shift;   /* 0: SDHC/SDXC block address, 9: SDSC byte address */

static uint8_t spi_xfer(uint8_t d)
{
	int32_t r;

	REG_SPI(SPI_REG_TXFIFO) = d;
	do {
		r = (int32_t)REG_SPI(SPI_REG_RXFIFO);
	} while (r < 0);
	return (uint8_t)r;
}

static inline uint8_t sd_dummy(void)
{
	return spi_xfer(0xFF);
}

static uint8_t sd_cmd(uint8_t cmd, uint32_t arg, uint8_t crc)
{
	unsigned long n;
	uint8_t r;

	REG_SPI(SPI_REG_CSMODE) = SPI_CSMODE_HOLD;
	sd_dummy();
	spi_xfer(cmd);
	spi_xfer((uint8_t)(arg >> 24));
	spi_xfer((uint8_t)(arg >> 16));
	spi_xfer((uint8_t)(arg >> 8));
	spi_xfer((uint8_t)arg);
	spi_xfer(crc);

	n = 1000;
	do {
		r = sd_dummy();
		if (!(r & 0x80))
			return r;
	} while (--n > 0);
	return 0xFF; /* timeout */
}

static inline void sd_cmd_end(void)
{
	sd_dummy();
	REG_SPI(SPI_REG_CSMODE) = SPI_CSMODE_AUTO;
}

static uint16_t crc16_round(uint16_t crc, uint8_t data)
{
	crc = (uint16_t)((uint8_t)(crc >> 8) | (crc << 8));
	crc ^= data;
	crc ^= (uint16_t)((uint8_t)(crc >> 4) & 0xf);
	crc ^= (uint16_t)(crc << 12);
	crc ^= (uint16_t)((crc & 0xff) << 5);
	return crc;
}

int sd_init(uint32_t pbus_hz)
{
	long i;
	uint8_t r = 0xFF;

	/* SiFive SPI: sck = pbus / (2 * (sckdiv + 1)); the bootloader's
	 * pbus/target idiom lands in the right range and is kept for parity. */
	REG_SPI(SPI_REG_SCKDIV) = pbus_hz / SD_INIT_HZ;
	REG_SPI(SPI_REG_CSMODE) = SPI_CSMODE_OFF;
	for (i = 10; i > 0; i--)   /* >= 74 idle clocks with CS deasserted */
		sd_dummy();
	REG_SPI(SPI_REG_CSMODE) = SPI_CSMODE_AUTO;

	/* CMD0: go idle. The first CMD0 after power-up can read back a junk byte
	 * with bit 7 clear (seen: 0x3f) while the card leaves SD mode, so retry. */
	for (i = 10; i > 0; i--) {
		r = sd_cmd(0x40, 0, 0x95);
		sd_cmd_end();
		if (r == 0x01)
			break;
	}
	if (r != 0x01)
		return -1;

	/* CMD8: interface condition, 2.7-3.6 V, pattern 0xAA */
	if (sd_cmd(0x48, 0x000001AA, 0x87) != 0x01) { sd_cmd_end(); return -1; }
	sd_dummy();
	sd_dummy();
	if ((sd_dummy() & 0xF) != 0x1) { sd_cmd_end(); return -1; }
	if (sd_dummy() != 0xAA)        { sd_cmd_end(); return -1; }
	sd_cmd_end();

	/* ACMD41 with HCS=1, until the card leaves idle */
	i = 100000;
	do {
		sd_cmd(0x77, 0, 0x65);          /* CMD55 */
		sd_cmd_end();
		r = sd_cmd(0x69, 0x40000000, 0x77);
		sd_cmd_end();
	} while (r == 0x01 && --i > 0);
	if (r != 0x00)
		return -1;

	/* CMD58: read OCR; bit 31 power-up done, bit 30 CCS (block addressing) */
	if (sd_cmd(0x7A, 0, 0xFD) != 0x00) { sd_cmd_end(); return -1; }
	r = sd_dummy();
	sd_dummy();
	sd_dummy();
	sd_dummy();
	sd_cmd_end();
	if (!(r & 0x80))
		return -1;
	addr_shift = (r & 0x40) ? 0 : 9;

	/* CMD16: 512-byte blocks */
	if (sd_cmd(0x50, SD_SECTOR_SIZE, 0x15) != 0x00) { sd_cmd_end(); return -1; }
	sd_cmd_end();

	REG_SPI(SPI_REG_SCKDIV) = pbus_hz / SD_DATA_HZ;
	return 0;
}

uint32_t sd_sectors(void)
{
	uint8_t csd[16];
	long guard = 1000000;
	uint32_t n = 0;

	if (sd_cmd(0x49, 0, 0x01) != 0x00)   /* CMD9: SEND_CSD */
		goto out;
	while (sd_dummy() != 0xFE)
		if (--guard <= 0)
			goto out;
	for (int i = 0; i < 16; i++)
		csd[i] = sd_dummy();
	sd_dummy();                          /* CRC-16 */
	sd_dummy();
	if ((csd[0] >> 6) == 1)              /* CSD v2 (SDHC/SDXC) only */
		n = ((((uint32_t)csd[7] & 0x3F) << 16 | csd[8] << 8 | csd[9]) + 1) * 1024;
out:
	sd_cmd_end();
	return n;
}

int sd_read(uint32_t lba, uint8_t *buf)
{
	uint16_t crc = 0, crc_exp;
	long guard = 1000000;
	int rc = -1;

	if (sd_cmd(0x51, lba << addr_shift, 0x01) != 0x00)   /* CMD17 */
		goto out;
	while (sd_dummy() != 0xFE)      /* data token */
		if (--guard <= 0)
			goto out;

	for (uint32_t n = 0; n < SD_SECTOR_SIZE; n++) {
		buf[n] = sd_dummy();
		crc = crc16_round(crc, buf[n]);
	}
	crc_exp  = (uint16_t)((uint16_t)sd_dummy() << 8);
	crc_exp |= sd_dummy();
	rc = (crc == crc_exp) ? 0 : -1;
out:
	sd_cmd_end();
	return rc;
}

int sd_write(uint32_t lba, const uint8_t *buf)
{
	uint16_t crc = 0;
	long guard = 10000000;
	int rc = -1;

	if (sd_cmd(0x58, lba << addr_shift, 0x01) != 0x00)   /* CMD24 */
		goto out;
	sd_dummy();
	spi_xfer(0xFE);                 /* start block token */
	for (uint32_t n = 0; n < SD_SECTOR_SIZE; n++) {
		spi_xfer(buf[n]);
		crc = crc16_round(crc, buf[n]);
	}
	spi_xfer((uint8_t)(crc >> 8));
	spi_xfer((uint8_t)crc);
	if ((sd_dummy() & 0x1F) != 0x05) /* data response: accepted */
		goto out;
	while (sd_dummy() != 0xFF)       /* busy while programming; the line
					  * releases mid-byte, so wait for 0xFF */
		if (--guard <= 0)
			goto out;
	rc = 0;
out:
	sd_cmd_end();
	return rc;
}
