/*
 * fat32_host.c — host test driver for ../common/src/fat32.c.
 *
 * sd_read()/sd_write() are backed by a disk image, so the same FAT code that
 * runs on the board copies SEND.BIN to RECV.BIN inside the image, in
 * APP_PT_MAX-sized chunks as the radio transfer does. tests/fat32_test.py
 * builds the image and checks the result with an independent FAT reader and
 * fsck.fat.
 *
 *   fat32_host <image> copy       SEND.BIN -> RECV.BIN, committed
 *   fat32_host <image> nocommit   same, but never commits
 *   fat32_host <image> missing    open NOPE.BIN, expect FAT_ENOENT
 *   fat32_host <image> format     sd_format() the whole image
 */
#include <stdio.h>
#include <string.h>

#include "fat32.h"
#include "sd_card.h"
#include "sd_format.h"

#define CHUNK 206   /* APP_PT_MAX */

static FILE *img;

int sd_read(uint32_t lba, uint8_t *buf)
{
	return fseek(img, (long)lba * SD_SECTOR_SIZE, SEEK_SET) ||
	       fread(buf, SD_SECTOR_SIZE, 1, img) != 1 ? -1 : 0;
}

uint32_t sd_sectors(void)
{
	return fseek(img, 0, SEEK_END) ? 0 : (uint32_t)(ftell(img) / SD_SECTOR_SIZE);
}

int sd_write(uint32_t lba, const uint8_t *buf)
{
	return fseek(img, (long)lba * SD_SECTOR_SIZE, SEEK_SET) ||
	       fwrite(buf, SD_SECTOR_SIZE, 1, img) != 1 ? -1 : 0;
}

int main(int argc, char **argv)
{
	struct fat32_file in, out;
	uint8_t chunk[CHUNK];
	int rc;

	if (argc != 3 || !(img = fopen(argv[1], "r+b"))) {
		fprintf(stderr, "usage: %s <image> copy|nocommit|missing|format\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[2], "format")) {
		rc = sd_format(sd_sectors());
		printf("format: %d\n", rc);
		return rc || fclose(img) ? 1 : 0;
	}
	if ((rc = fat32_mount()) != FAT_OK) {
		printf("mount: %d\n", rc);
		return 1;
	}
	if (!strcmp(argv[2], "missing")) {
		rc = fat32_open(&in, "NOPE    BIN");
		printf("open NOPE.BIN: %d\n", rc);
		return rc == FAT_ENOENT ? 0 : 1;
	}
	if ((rc = fat32_open(&in, "SEND    BIN")) != FAT_OK ||
	    (rc = fat32_create(&out, in.size)) != FAT_OK) {
		printf("open/create: %d\n", rc);
		return 1;
	}
	while (in.pos < in.size) {
		uint32_t n = in.size - in.pos < CHUNK ? in.size - in.pos : CHUNK;

		if ((rc = fat32_read(&in, chunk, n)) != FAT_OK ||
		    (rc = fat32_write(&out, chunk, n)) != FAT_OK) {
			printf("copy at %u: %d\n", (unsigned)in.pos, rc);
			return 1;
		}
	}
	if (fat32_read(&in, chunk, 1) != FAT_EEOF ||
	    fat32_write(&out, chunk, 1) != FAT_EEOF) {
		printf("no EOF past the end\n");
		return 1;
	}
	if (!strcmp(argv[2], "copy") && (rc = fat32_commit(&out, "RECV    BIN")) != FAT_OK) {
		printf("commit: %d\n", rc);
		return 1;
	}
	printf("%s %u bytes, first cluster %u\n", argv[2], (unsigned)in.size,
	       (unsigned)out.first);
	return fclose(img) ? 1 : 0;
}
