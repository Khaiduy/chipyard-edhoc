/* edhoc_file_xfer.c — see edhoc_file_xfer.h */
#include <stdint.h>

#include "edhoc_file_xfer.h"
#include "fat32.h"
#include "sd_card.h"
#include "kprintf.h"
#include "perf.h"

#define NO_FILE 0xFFFFFFFFu

static const char send_name[] = "SEND    BIN";
static const char recv_name[] = "RECV    BIN";

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

static void put_be32(uint8_t *b, uint32_t v)
{
	b[0] = (uint8_t)(v >> 24);
	b[1] = (uint8_t)(v >> 16);
	b[2] = (uint8_t)(v >> 8);
	b[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *b)
{
	return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
	       ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
}

/* Brings the card and its FAT32 partition up; prints why not. */
static int card_up(void)
{
	int rc = sd_init(PERF_CPU_HZ) ? FAT_EIO : fat32_mount();

	if (rc)
		kprintf("XFER: SD card not usable (%d)\r\n", rc);
	return rc;
}

static void report(const char *what, uint32_t bytes, uint64_t cyc, uint64_t sd_cyc)
{
	perf_xfer(what, bytes, cyc);
	perf_step("xfer_sd_part     ", sd_cyc);
}

enum err file_xfer_send(struct app_chan *ch, app_tx_fn tx, void *sock)
{
	struct fat32_file f;
	uint8_t chunk[APP_PT_MAX];
	uint32_t crc = 0;
	uint64_t t0, t, sd_cyc = 0;
	enum err r;
	int rc = card_up();

	if (!rc && (rc = fat32_open(&f, send_name)) != FAT_OK)
		kprintf("XFER: no SEND.BIN on the card (%d)\r\n", rc);
	put_be32(chunk, rc ? NO_FILE : f.size);
	r = app_data_send(ch, chunk, 4, tx, sock);
	if (r != ok || rc)
		return r != ok ? r : unexpected_result_from_ext_lib;

	kprintf("XFER: sending SEND.BIN, %u bytes\r\n", (unsigned)f.size);
	t0 = read_cycles();
	while (f.pos < f.size) {
		uint32_t n = f.size - f.pos < APP_PT_MAX ? f.size - f.pos : APP_PT_MAX;

		t = read_cycles();
		rc = fat32_read(&f, chunk, n);
		sd_cyc += read_cycles() - t;
		if (rc) {
			kprintf("XFER: SD read failed at %u (%d)\r\n", (unsigned)f.pos, rc);
			return unexpected_result_from_ext_lib;
		}
		crc = crc32(crc, chunk, n);
		r = app_data_send(ch, chunk, n, tx, sock);
		if (r != ok) {
			kprintf("XFER: record at %u failed (%d)\r\n", (unsigned)(f.pos - n), r);
			return r;
		}
	}
	put_be32(chunk, crc);
	r = app_data_send(ch, chunk, 4, tx, sock);
	if (r != ok)
		return r;
	report("xfer_send   ", f.size, read_cycles() - t0, sd_cyc);
	kprintf("XFER SENT: %u bytes, CRC %x\r\n", (unsigned)f.size, (unsigned)crc);
	return ok;
}

enum err file_xfer_recv(struct app_chan *ch, app_rx_fn rx, void *sock)
{
	struct fat32_file f;
	uint8_t chunk[APP_PT_MAX];
	uint32_t got, size, done = 0, crc = 0;
	uint64_t t0, t, sd_cyc = 0;
	enum err r;
	int rc;

	r = app_data_recv(ch, chunk, sizeof(chunk), &got, rx, sock);
	if (r != ok)
		return r;
	if (got != 4)
		return unexpected_result_from_ext_lib;
	size = get_be32(chunk);
	if (size == NO_FILE) {
		kprintf("XFER: peer has no SEND.BIN\r\n");
		return unexpected_result_from_ext_lib;
	}

	kprintf("XFER: receiving %u bytes\r\n", (unsigned)size);
	rc = card_up();
	if (!rc && (rc = fat32_create(&f, size)) != FAT_OK)
		kprintf("XFER: no room for %u bytes (%d)\r\n", (unsigned)size, rc);

	t0 = read_cycles();
	while (done < size) {
		r = app_data_recv(ch, chunk, sizeof(chunk), &got, rx, sock);
		if (r != ok) {
			kprintf("XFER: record at %u failed (%d)\r\n", (unsigned)done, r);
			return r;
		}
		if (got > size - done)
			return unexpected_result_from_ext_lib;
		crc = crc32(crc, chunk, got);
		done += got;
		if (!rc) {
			t = read_cycles();
			rc = fat32_write(&f, chunk, got);
			sd_cyc += read_cycles() - t;
			if (rc)
				kprintf("XFER: SD write failed at %u (%d)\r\n", (unsigned)done, rc);
		}
	}
	r = app_data_recv(ch, chunk, sizeof(chunk), &got, rx, sock);
	if (r != ok)
		return r;
	if (got != 4 || get_be32(chunk) != crc) {
		kprintf("XFER: CRC mismatch, RECV.BIN not written\r\n");
		return unexpected_result_from_ext_lib;
	}
	if (!rc) {
		t = read_cycles();
		rc = fat32_commit(&f, recv_name);
		sd_cyc += read_cycles() - t;
	}
	report("xfer_recv   ", size, read_cycles() - t0, sd_cyc);
	if (rc) {
		kprintf("XFER: received %u bytes, CRC %x OK, not stored (%d)\r\n",
			(unsigned)size, (unsigned)crc, rc);
		return unexpected_result_from_ext_lib;
	}
	kprintf("XFER RECV: %u bytes -> RECV.BIN, CRC %x OK\r\n",
		(unsigned)size, (unsigned)crc);
	return ok;
}
