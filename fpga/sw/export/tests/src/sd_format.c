/*
 * sd_format.c — lay down the card layout of tools/mksd.sh from the board
 * itself, so a card can be prepared over JTAG without a PC card reader:
 *
 *   LBA 0             MBR
 *   LBA 2048 + 64 Ki  partition 1, raw boot image (sd_boot.sh); not touched
 *   LBA 67584 ..      partition 2, FAT32, label EDHOC
 *
 * Also clears a GPT the card may carry (primary at LBA 1..33, backup header
 * in the last sector), so no tool mistakes the card for GPT afterwards.
 */
#include <stdint.h>

#include "sd_card.h"
#include "sd_format.h"

#define P1      2048u
#define P1_LEN  65536u
#define P2      (P1 + P1_LEN)
#define RSVD    32u
#define NFATS   2u
#define VOL_ID  0x20261008u

static uint8_t sec[SD_SECTOR_SIZE];

static void put16(uint32_t off, uint32_t x)
{
	sec[off] = (uint8_t)x;
	sec[off + 1] = (uint8_t)(x >> 8);
}

static void put32(uint32_t off, uint32_t x)
{
	put16(off, x);
	put16(off + 2, x >> 16);
}

static void put_str(uint32_t off, const char *s, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++)
		sec[off + i] = (uint8_t)s[i];
}

static void clear(void)
{
	for (uint32_t i = 0; i < SD_SECTOR_SIZE; i++)
		sec[i] = 0;
}

static int zero_run(uint32_t lba, uint32_t n)
{
	clear();
	for (uint32_t i = 0; i < n; i++)
		if (sd_write(lba + i, sec))
			return -1;
	return 0;
}

/* Cluster size as Windows picks it for FAT32. */
static uint32_t pick_spc(uint32_t sectors)
{
	if (sectors < 532480u)      /* < 260 MiB */
		return 1;
	if (sectors <= 16777216u)   /* <= 8 GiB */
		return 8;
	if (sectors <= 33554432u)   /* <= 16 GiB */
		return 16;
	if (sectors <= 67108864u)   /* <= 32 GiB */
		return 32;
	return 64;
}

static void boot_sector(uint32_t len, uint32_t spc, uint32_t fatsz)
{
	clear();
	put_str(0, "\xEB\x58\x90" "MSWIN4.1", 11);
	put16(11, SD_SECTOR_SIZE);
	sec[13] = (uint8_t)spc;
	put16(14, RSVD);
	sec[16] = NFATS;
	sec[21] = 0xF8;             /* fixed disk */
	put16(24, 63);              /* sectors per track */
	put16(26, 255);             /* heads */
	put32(28, P2);              /* hidden sectors */
	put32(32, len);
	put32(36, fatsz);
	put32(44, 2);               /* root directory cluster */
	put16(48, 1);               /* FSInfo sector */
	put16(50, 6);               /* backup boot sector */
	sec[64] = 0x80;
	sec[66] = 0x29;
	put32(67, VOL_ID);
	put_str(71, "EDHOC      FAT32   ", 19);
	sec[510] = 0x55;
	sec[511] = 0xAA;
}

static void fsinfo(uint32_t free_clusters)
{
	clear();
	put32(0, 0x41615252);
	put32(484, 0x61417272);
	put32(488, free_clusters);
	put32(492, 3);              /* next free cluster hint */
	put32(508, 0xAA550000);
}

static void mbr_entry(uint32_t i, uint8_t type, uint32_t start, uint32_t n)
{
	uint32_t o = 446 + 16 * i;

	sec[o + 1] = 0xFE;          /* CHS unused: LBA only */
	sec[o + 2] = 0xFF;
	sec[o + 3] = 0xFF;
	sec[o + 4] = type;
	sec[o + 5] = 0xFE;
	sec[o + 6] = 0xFF;
	sec[o + 7] = 0xFF;
	put32(o + 8, start);
	put32(o + 12, n);
}

int sd_format(uint32_t total)
{
	uint32_t len, spc, fatsz, clusters;

	if (total <= P2 + 65536u)
		return SD_FMT_SMALL;
	len   = total - P2;
	spc   = pick_spc(len);
	fatsz = (len - RSVD + (128 * spc + 1) - 1) / (128 * spc + 1);
	clusters = (len - RSVD - NFATS * fatsz) / spc;
	if (clusters < 65525u)
		return SD_FMT_SMALL;

	/* Old GPT: primary header + entries, backup header. */
	if (zero_run(1, 33) || zero_run(total - 1, 1))
		return SD_FMT_EIO;

	/* Reserved area, both FATs, root directory cluster. */
	if (zero_run(P2, RSVD) || zero_run(P2 + RSVD, NFATS * fatsz) ||
	    zero_run(P2 + RSVD + NFATS * fatsz, spc))
		return SD_FMT_EIO;
	clear();
	put_str(0, "EDHOC      ", 11);      /* volume label entry */
	sec[11] = 0x08;
	if (sd_write(P2 + RSVD + NFATS * fatsz, sec))
		return SD_FMT_EIO;
	for (uint32_t k = 0; k < NFATS; k++) {
		clear();
		put32(0, 0x0FFFFFF8);   /* media */
		put32(4, 0x0FFFFFFF);
		put32(8, 0x0FFFFFFF);   /* root directory: one cluster */
		if (sd_write(P2 + RSVD + k * fatsz, sec))
			return SD_FMT_EIO;
	}
	boot_sector(len, spc, fatsz);
	if (sd_write(P2, sec) || sd_write(P2 + 6, sec))
		return SD_FMT_EIO;
	fsinfo(clusters - 1);
	if (sd_write(P2 + 1, sec) || sd_write(P2 + 7, sec))
		return SD_FMT_EIO;

	/* MBR last: until here the card still shows its old layout. */
	clear();
	put32(440, VOL_ID);         /* disk signature */
	mbr_entry(0, 0xDA, P1, P1_LEN);
	mbr_entry(1, 0x0C, P2, len);
	sec[510] = 0x55;
	sec[511] = 0xAA;
	return sd_write(0, sec) ? SD_FMT_EIO : SD_FMT_OK;
}
