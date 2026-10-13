/*
 * fat32.h — minimal FAT32 on the SD card: read one file, write one file.
 *
 * The card holds an MBR; the first FAT32 partition (type 0x0B/0x0C) is used,
 * so the SD boot image can keep its raw partition at LBA 2048 in front of it.
 * Files live in the root directory and are named in 8.3 form, padded to 11
 * characters ("SEND    BIN"). Long names are ignored, not written.
 *
 * One 512-byte sector buffer serves everything, so RAM use is flat in the
 * file size: the 64 KiB scratchpad cannot hold a FAT or a cluster cache.
 *
 * A written file becomes visible only at fat32_commit(): data goes to free
 * clusters first, then the FAT chain, the directory entry, and last the old
 * file's clusters are freed. A transfer that fails before commit leaves the
 * file system as it was: only clusters that are still free were written.
 */
#ifndef EDHOC_FAT32_H
#define EDHOC_FAT32_H

#include <stdint.h>

enum fat32_err {
	FAT_OK     =  0,
	FAT_EIO    = -1,   /* card read/write failed                        */
	FAT_ENOFS  = -2,   /* no MBR / FAT32 partition, or a corrupt chain  */
	FAT_ENOENT = -3,   /* file not in the root directory                */
	FAT_ENOSPC = -4,   /* no free run that large, or root directory full */
	FAT_EEOF   = -5,   /* read or write past the file size              */
};

struct fat32_file {
	uint32_t first;    /* first cluster, 0 for an empty file            */
	uint32_t clus;     /* cluster holding pos (reads)                   */
	uint32_t size;     /* bytes                                         */
	uint32_t pos;      /* bytes read or written so far                  */
};

/** @brief Finds the FAT32 partition. Call after sd_init(). */
int fat32_mount(void);

/** @brief Opens @p name83 in the root directory for reading. */
int fat32_open(struct fat32_file *f, const char *name83);

/** @brief Reads the next @p n bytes; FAT_EEOF past the end. */
int fat32_read(struct fat32_file *f, uint8_t *dst, uint32_t n);

/** @brief Reserves space for a new file of exactly @p size bytes. */
int fat32_create(struct fat32_file *f, uint32_t size);

/** @brief Appends @p n bytes; the total must not exceed the reserved size. */
int fat32_write(struct fat32_file *f, const uint8_t *src, uint32_t n);

/** @brief Publishes the written file as @p name83, replacing any old one. */
int fat32_commit(struct fat32_file *f, const char *name83);

#endif /* EDHOC_FAT32_H */
