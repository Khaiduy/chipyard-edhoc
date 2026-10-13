/*
 * sd_prep.c — prepare or check a board's SD card over JTAG, no card reader:
 *
 *   make sd_prep EXTRA_CFLAGS="-DSD_PREP_FORMAT -DSD_PREP_SEND=1048576"
 *       format the card (tools/mksd.sh layout), then write SEND.BIN
 *   make sd_prep EXTRA_CFLAGS=-DSD_PREP_SEND=1048576
 *       (re)write SEND.BIN only
 *   make sd_prep EXTRA_CFLAGS=-DSD_PREP_VERIFY
 *       check RECV.BIN against the same generator
 *
 * SEND.BIN holds a fixed pseudo-random sequence, so the receiving board can
 * verify RECV.BIN without the original. Prints the CRC-32 the file transfer
 * reports, for cross-checking.
 */
#include <stdint.h>

#include "kprintf.h"
#include "test_init.h"
#include "sd_card.h"
#include "fat32.h"
#include "sd_format.h"

#define CHUNK 512u

#if defined(SD_PREP_SEND) || defined(SD_PREP_VERIFY)
static uint8_t chunk[CHUNK];
static uint32_t seed;

static void gen(uint8_t *p, uint32_t n)
{
	while (n--) {
		seed = seed * 1664525u + 1013904223u;
		*p++ = (uint8_t)(seed >> 24);
	}
}

static uint32_t crc32(uint32_t crc, const uint8_t *p, uint32_t n)
{
	crc = ~crc;
	while (n--) {
		crc ^= *p++;
		for (int k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)((int32_t)(crc << 31) >> 31));
	}
	return ~crc;
}
#endif

static int run(void)
{
	struct fat32_file f;
	uint32_t total, crc = 0;
	int rc;

	if (sd_init(TEST_CPU_HZ))
		return kprintf("sd_init FAIL\r\n"), 1;
	total = sd_sectors();
	kprintf("card: %u sectors (%u MiB)\r\n", (unsigned)total, (unsigned)(total / 2048));
#ifdef SD_PREP_FORMAT
	kprintf("formatting...\r\n");
	if ((rc = sd_format(total)) != SD_FMT_OK)
		return kprintf("format FAIL %d\r\n", rc), 1;
	kprintf("format OK\r\n");
#endif
	if ((rc = fat32_mount()) != FAT_OK)
		return kprintf("mount FAIL %d\r\n", rc), 1;
#ifdef SD_PREP_SEND
	seed = 0x5EED0001u;
	if ((rc = fat32_create(&f, SD_PREP_SEND)) != FAT_OK)
		return kprintf("create FAIL %d\r\n", rc), 1;
	while (f.pos < f.size) {
		uint32_t n = f.size - f.pos < CHUNK ? f.size - f.pos : CHUNK;

		gen(chunk, n);
		crc = crc32(crc, chunk, n);
		if ((rc = fat32_write(&f, chunk, n)) != FAT_OK)
			return kprintf("write FAIL %d at %u\r\n", rc, (unsigned)f.pos), 1;
	}
	if ((rc = fat32_commit(&f, "SEND    BIN")) != FAT_OK)
		return kprintf("commit FAIL %d\r\n", rc), 1;
	kprintf("SEND.BIN: %u bytes, CRC %x\r\n", (unsigned)f.size, (unsigned)crc);
#endif
#ifdef SD_PREP_VERIFY
	{
		uint32_t bad = 0;

		seed = 0x5EED0001u;
		if ((rc = fat32_open(&f, "RECV    BIN")) != FAT_OK)
			return kprintf("no RECV.BIN (%d)\r\n", rc), 1;
		while (f.pos < f.size) {
			uint32_t n = f.size - f.pos < CHUNK ? f.size - f.pos : CHUNK;
			uint8_t want[CHUNK];

			if ((rc = fat32_read(&f, chunk, n)) != FAT_OK)
				return kprintf("read FAIL %d at %u\r\n", rc, (unsigned)f.pos), 1;
			gen(want, n);
			crc = crc32(crc, chunk, n);
			for (uint32_t i = 0; i < n; i++)
				bad += chunk[i] != want[i];
		}
		kprintf("RECV.BIN: %u bytes, CRC %x, %u bytes differ\r\n",
			(unsigned)f.size, (unsigned)crc, (unsigned)bad);
		if (bad)
			return 1;
	}
#endif
	(void)f;
	(void)crc;
	return 0;
}

int main(void)
{
	test_console_init();
	kprintf("\r\n== sd_prep ==\r\n");
	kprintf(run() ? "SD PREP FAIL\r\n" : "SD PREP OK\r\n");
	while (1)
		;
	return 0;
}
