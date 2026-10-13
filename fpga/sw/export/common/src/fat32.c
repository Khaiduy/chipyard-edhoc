/*
 * fat32.c — minimal FAT32, see fat32.h.
 */
#include <stdint.h>

#include "fat32.h"
#include "sd_card.h"

#define NO_LBA    0xFFFFFFFFu
#define DIR_END   0x00          /* first name byte: no entries after     */
#define DIR_FREE  0xE5          /* first name byte: deleted entry        */
#define FAT_DATE  0x5C21u       /* 2026-01-01: there is no RTC           */

static struct {
	uint32_t fat_lba;     /* first FAT                                 */
	uint32_t fat_sz;      /* sectors per FAT                           */
	uint32_t data_lba;    /* cluster 2                                 */
	uint32_t max_clus;    /* highest valid cluster number              */
	uint32_t root;        /* root directory first cluster              */
	uint32_t fsinfo_lba;
	uint32_t spc;         /* sectors per cluster                       */
	uint32_t nfats;
} v;

static uint8_t  buf[SD_SECTOR_SIZE];
static uint32_t buf_lba = NO_LBA;
static int      dirty;

static uint32_t le16(const uint8_t *b) { return b[0] | (uint32_t)b[1] << 8; }
static uint32_t le32(const uint8_t *b) { return le16(b) | le16(b + 2) << 16; }

static void put_le16(uint8_t *b, uint32_t x) { b[0] = (uint8_t)x; b[1] = (uint8_t)(x >> 8); }
static void put_le32(uint8_t *b, uint32_t x) { put_le16(b, x); put_le16(b + 2, x >> 16); }

/* Writes the buffer back; a FAT sector goes to every FAT copy. */
static int flush(void)
{
	uint32_t copies = 1;

	if (!dirty)
		return FAT_OK;
	if (buf_lba >= v.fat_lba && buf_lba < v.fat_lba + v.fat_sz)
		copies = v.nfats;
	for (uint32_t k = 0; k < copies; k++)
		if (sd_write(buf_lba + k * v.fat_sz, buf))
			return FAT_EIO;
	dirty = 0;
	return FAT_OK;
}

static int load(uint32_t lba)
{
	if (lba == buf_lba)
		return FAT_OK;
	if (flush())
		return FAT_EIO;
	buf_lba = NO_LBA;
	if (sd_read(lba, buf))
		return FAT_EIO;
	buf_lba = lba;
	return FAT_OK;
}

static int fat_get(uint32_t c, uint32_t *next)
{
	if (load(v.fat_lba + c / 128))
		return FAT_EIO;
	*next = le32(&buf[(c % 128) * 4]) & 0x0FFFFFFF;
	return FAT_OK;
}

static int fat_set(uint32_t c, uint32_t val)
{
	uint8_t *e;

	if (load(v.fat_lba + c / 128))
		return FAT_EIO;
	e = &buf[(c % 128) * 4];
	put_le32(e, (le32(e) & 0xF0000000) | val);   /* top 4 bits reserved */
	dirty = 1;
	return FAT_OK;
}

static int valid(uint32_t c)
{
	return c >= 2 && c <= v.max_clus;
}

static uint32_t clus_lba(uint32_t c)
{
	return v.data_lba + (c - 2) * v.spc;
}

int fat32_mount(void)
{
	uint32_t part = 0, rsvd, total;

	buf_lba = NO_LBA;
	dirty = 0;
	if (load(0))
		return FAT_EIO;
	if (buf[510] != 0x55 || buf[511] != 0xAA)
		return FAT_ENOFS;
	for (int i = 0; i < 4 && !part; i++) {
		const uint8_t *pe = &buf[446 + 16 * i];

		if (pe[4] == 0x0B || pe[4] == 0x0C)
			part = le32(&pe[8]);
	}
	if (!part)
		return FAT_ENOFS;
	if (load(part))
		return FAT_EIO;

	/* BPB: 512-byte sectors, FAT32 (16-bit FAT size field zero) */
	if (le16(&buf[11]) != SD_SECTOR_SIZE || buf[13] == 0 || buf[16] == 0 ||
	    le16(&buf[22]) != 0 || buf[510] != 0x55 || buf[511] != 0xAA)
		return FAT_ENOFS;
	v.spc        = buf[13];
	rsvd         = le16(&buf[14]);
	v.nfats      = buf[16];
	total        = le32(&buf[32]);
	v.fat_sz     = le32(&buf[36]);
	v.root       = le32(&buf[44]);
	v.fsinfo_lba = part + le16(&buf[48]);
	v.fat_lba    = part + rsvd;
	v.data_lba   = v.fat_lba + v.nfats * v.fat_sz;
	v.max_clus   = (total - rsvd - v.nfats * v.fat_sz) / v.spc + 1;
	if (v.max_clus >= v.fat_sz * 128)
		v.max_clus = v.fat_sz * 128 - 1;
	return valid(v.root) ? FAT_OK : FAT_ENOFS;
}

/* Walks the root directory for @p name83. On a hit lba/off locate its entry
 * (still in buf); on a miss they locate the first free slot, or lba is
 * NO_LBA if the directory is full. */
static int dir_find(const char *name83, uint32_t *lba, uint32_t *off)
{
	uint32_t c = v.root, hops = 0;

	*lba = NO_LBA;
	while (valid(c) && hops++ <= v.max_clus) {
		for (uint32_t s = 0; s < v.spc; s++) {
			if (load(clus_lba(c) + s))
				return FAT_EIO;
			for (uint32_t o = 0; o < SD_SECTOR_SIZE; o += 32) {
				const uint8_t *e = &buf[o];
				int same = 1;

				if (e[0] == DIR_END || e[0] == DIR_FREE) {
					if (*lba == NO_LBA) {
						*lba = clus_lba(c) + s;
						*off = o;
					}
					if (e[0] == DIR_END)
						return FAT_ENOENT;
					continue;
				}
				if (e[11] == 0x0F || (e[11] & 0x18))  /* LFN, label, dir */
					continue;
				for (int i = 0; i < 11; i++)
					same &= (e[i] == (uint8_t)name83[i]);
				if (same) {
					*lba = clus_lba(c) + s;
					*off = o;
					return FAT_OK;
				}
			}
		}
		if (fat_get(c, &c))
			return FAT_EIO;
	}
	return FAT_ENOENT;
}

int fat32_open(struct fat32_file *f, const char *name83)
{
	uint32_t lba, off;
	int rc = dir_find(name83, &lba, &off);

	if (rc)
		return rc;
	f->first = le16(&buf[off + 20]) << 16 | le16(&buf[off + 26]);
	f->size  = le32(&buf[off + 28]);
	f->clus  = f->first;
	f->pos   = 0;
	return (f->size && !valid(f->first)) ? FAT_ENOFS : FAT_OK;
}

int fat32_read(struct fat32_file *f, uint8_t *dst, uint32_t n)
{
	uint32_t cb = v.spc * SD_SECTOR_SIZE;

	if (n > f->size - f->pos)
		return FAT_EEOF;
	while (n) {
		uint32_t off = f->pos % SD_SECTOR_SIZE, take;

		if (f->pos && f->pos % cb == 0) {
			if (fat_get(f->clus, &f->clus))
				return FAT_EIO;
			if (!valid(f->clus))
				return FAT_ENOFS;
		}
		if (load(clus_lba(f->clus) + (f->pos % cb) / SD_SECTOR_SIZE))
			return FAT_EIO;
		take = SD_SECTOR_SIZE - off < n ? SD_SECTOR_SIZE - off : n;
		for (uint32_t i = 0; i < take; i++)
			dst[i] = buf[off + i];
		f->pos += take;
		dst    += take;
		n      -= take;
	}
	return FAT_OK;
}

/* ponytail: one contiguous run of free clusters, so writing needs no FAT
 * lookups and the chain is laid down at commit. Fails with FAT_ENOSPC on a
 * card whose free space is fragmented; chain allocation if that matters. */
int fat32_create(struct fat32_file *f, uint32_t size)
{
	uint32_t cb = v.spc * SD_SECTOR_SIZE;
	uint32_t need = size / cb + (size % cb != 0), run = 0, start = 0, e;

	for (uint32_t c = 2; c <= v.max_clus && run < need; c++) {
		if (fat_get(c, &e))
			return FAT_EIO;
		if (e)
			run = 0;
		else if (run++ == 0)
			start = c;
	}
	if (run < need)
		return FAT_ENOSPC;
	f->first = need ? start : 0;
	f->clus  = f->first;
	f->size  = size;
	f->pos   = 0;
	return FAT_OK;
}

int fat32_write(struct fat32_file *f, const uint8_t *src, uint32_t n)
{
	if (n > f->size - f->pos)
		return FAT_EEOF;
	while (n) {
		uint32_t off = f->pos % SD_SECTOR_SIZE, take;
		uint32_t lba = clus_lba(f->first) + f->pos / SD_SECTOR_SIZE;

		if (off == 0) {             /* claim the next sector, no read */
			if (flush())
				return FAT_EIO;
			buf_lba = lba;
			for (uint32_t i = 0; i < SD_SECTOR_SIZE; i++)
				buf[i] = 0;
		} else if (load(lba)) {     /* buffer was lent out meanwhile */
			return FAT_EIO;
		}
		take = SD_SECTOR_SIZE - off < n ? SD_SECTOR_SIZE - off : n;
		for (uint32_t i = 0; i < take; i++)
			buf[off + i] = src[i];
		dirty = 1;
		f->pos += take;
		src    += take;
		n      -= take;
	}
	return FAT_OK;
}

int fat32_commit(struct fat32_file *f, const char *name83)
{
	uint32_t cb = v.spc * SD_SECTOR_SIZE;
	uint32_t need = f->size / cb + (f->size % cb != 0);
	uint32_t lba, off, old = 0, c;
	uint8_t *e;
	int rc;

	if (f->pos != f->size)
		return FAT_EEOF;
	for (uint32_t i = 0; i < need; i++)
		if (fat_set(f->first + i, i + 1 < need ? f->first + i + 1 : 0x0FFFFFFF))
			return FAT_EIO;

	rc = dir_find(name83, &lba, &off);
	if (rc != FAT_OK && rc != FAT_ENOENT)
		return rc;
	if (lba == NO_LBA)
		return FAT_ENOSPC;   /* ponytail: the root directory is not grown */
	if (load(lba))
		return FAT_EIO;
	e = &buf[off];
	if (rc == FAT_OK) {
		old = le16(&e[20]) << 16 | le16(&e[26]);
	} else {
		for (int i = 0; i < 32; i++)
			e[i] = 0;
		for (int i = 0; i < 11; i++)
			e[i] = (uint8_t)name83[i];
		e[11] = 0x20;                    /* archive */
		put_le16(&e[16], FAT_DATE);      /* created */
	}
	put_le16(&e[18], FAT_DATE);              /* accessed */
	put_le16(&e[24], FAT_DATE);              /* written */
	put_le16(&e[20], f->first >> 16);
	put_le16(&e[26], f->first);
	put_le32(&e[28], f->size);
	dirty = 1;

	/* Free the replaced file's chain. */
	for (uint32_t hops = 0; valid(old) && hops <= v.max_clus; hops++) {
		if (fat_get(old, &c) || fat_set(old, 0))
			return FAT_EIO;
		old = c;
	}

	/* FSInfo free count and hint are now stale: mark them unknown. */
	if (load(v.fsinfo_lba))
		return FAT_EIO;
	if (le32(buf) == 0x41615252) {
		put_le32(&buf[488], 0xFFFFFFFF);
		put_le32(&buf[492], 0xFFFFFFFF);
		dirty = 1;
	}
	return flush();
}
