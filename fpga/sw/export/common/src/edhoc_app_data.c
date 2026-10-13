/*
 * edhoc_app_data.c - Suite-independent application data channel.
 *
 * Key schedule (RFC 9528 4.2.1, EDHOC_Exporter):
 *   PRK_exporter = EDHOC_KDF(PRK_out, "PRK_exporter", <>, hash_len)
 *   K_app        = EDHOC_Exporter(APP_KEY_LABEL, <>, aead_key_len)
 *   IV_app       = EDHOC_Exporter(APP_IV_LABEL,  <>, aead_iv_len)
 *
 * Record on the wire (payload of one transport frame): ciphertext || tag.
 *
 * Nonce = IV_app XOR (0..0 || dir || seq_be32), with dir = 0 for
 * initiator->responder and 1 for responder->initiator, so the two directions
 * never reuse a nonce under the shared key. The 5-byte (dir || seq_be32)
 * header is also the AAD but is never transmitted: both peers count their own
 * sequence numbers, and a desync shows up as a tag verification failure.
 *
 * Every suite-dependent quantity is a run-time query, so this file is
 * identical for the wolfCrypt and the ML-KEM package and needs no edit when
 * CRYPTO_SUITE changes.
 */
#include <string.h>

#include "edhoc_app_data.h"
#include "common/crypto_wrapper.h"
#include "kprintf.h"
#include "perf.h"
#include "edhoc_transport.h"
#include "secure_wipe.h"
#ifdef APP_SD_XFER
#include "edhoc_file_xfer.h"
#endif

#define APP_HDR_LEN 5

/* One record buffer, reused by send and receive: plaintext plus tag. */
static uint8_t rec_buf[APP_PT_MAX + APP_TAG_MAX];

static void mk_hdr(uint8_t *hdr, uint8_t dir, uint32_t seq)
{
	hdr[0] = dir;
	hdr[1] = (uint8_t)(seq >> 24);
	hdr[2] = (uint8_t)(seq >> 16);
	hdr[3] = (uint8_t)(seq >> 8);
	hdr[4] = (uint8_t)seq;
}

static void mk_nonce(const struct app_chan *ch, uint8_t *nonce,
		     const uint8_t *hdr)
{
	uint32_t off = ch->iv_len - APP_HDR_LEN;

	memcpy(nonce, ch->base_iv, ch->iv_len);
	for (uint32_t i = 0; i < APP_HDR_LEN; i++)
		nonce[off + i] ^= hdr[i];
}

/* The minimal kprintf has no precision modifier, so NUL-terminate a copy. */
static void print_msg(const char *label, const uint8_t *b, uint32_t n)
{
	char line[APP_PT_MAX + 1];

	if (n > APP_PT_MAX)
		n = APP_PT_MAX;
	memcpy(line, b, n);
	line[n] = '\0';
	kprintf("APP: %s '%s'\r\n", label, line);
}

enum err app_data_init(struct app_chan *ch, enum suite_label label,
		       struct byte_array *prk_out, int is_initiator)
{
	uint8_t prk_exp_buf[APP_HASH_MAX];
	struct byte_array prk_exp, key, iv;
	uint32_t hash_len;
	enum err r;

	r = get_suite(label, &ch->ste);
	if (r != ok)
		return r;

	ch->key_len = get_aead_key_len(ch->ste.app_aead);
	ch->iv_len = get_aead_iv_len(ch->ste.app_aead);
	ch->tag_len = get_aead_mac_len(ch->ste.app_aead);
	/* EDHOC_Exporter is EDHOC_KDF (RFC 9528 Section 4.2.1), so it runs on
	 * the EDHOC hash, not the application hash, and PRK_exporter is that
	 * hash's length. (For suites 0-6, 24 and 25 the two are the same.) */
	hash_len = get_hash_len(ch->ste.edhoc_hash);

	if (ch->key_len == 0 || ch->iv_len == 0 || ch->tag_len == 0 ||
	    hash_len == 0)
		return unsupported_cipher_suite;
	if (ch->key_len > APP_KEY_MAX || ch->iv_len > APP_IV_MAX ||
	    ch->tag_len > APP_TAG_MAX || hash_len > APP_HASH_MAX ||
	    ch->iv_len < APP_HDR_LEN)
		return buffer_to_small;

	prk_exp.ptr = prk_exp_buf;
	prk_exp.len = hash_len;
	r = prk_out2exporter(ch->ste.edhoc_hash, prk_out, &prk_exp);
	if (r != ok)
		return r;

	key.ptr = ch->key;
	key.len = ch->key_len;
	r = edhoc_exporter(ch->ste.edhoc_hash, APP_KEY_LABEL,
			   &prk_exp, &key);
	if (r != ok)
		return r;

	iv.ptr = ch->base_iv;
	iv.len = ch->iv_len;
	r = edhoc_exporter(ch->ste.edhoc_hash, APP_IV_LABEL,
			   &prk_exp, &iv);
	edhoc_wipe(prk_exp_buf, sizeof(prk_exp_buf));
	if (r != ok)
		return r;

	ch->is_initiator = is_initiator ? 1 : 0;
	ch->tx_seq = 0;
	ch->rx_seq = 0;
	ch->enc_cyc = ch->dec_cyc = 0;
	ch->enc_bytes = ch->dec_bytes = 0;
	return ok;
}

enum err app_data_send(struct app_chan *ch, const uint8_t *pt, uint32_t pt_len,
		       app_tx_fn tx, void *sock)
{
	uint8_t hdr[APP_HDR_LEN];
	uint8_t nonce_buf[APP_IV_MAX];
	uint8_t tag_buf[APP_TAG_MAX];
	struct byte_array in, key, nonce, aad, out, tag, rec;
	enum err r;

	if (pt_len > APP_PT_MAX)
		return buffer_to_small;

	mk_hdr(hdr, ch->is_initiator ? 0 : 1, ch->tx_seq);
	mk_nonce(ch, nonce_buf, hdr);

	in.ptr = (uint8_t *)pt;
	in.len = pt_len;
	key.ptr = ch->key;
	key.len = ch->key_len;
	nonce.ptr = nonce_buf;
	nonce.len = ch->iv_len;
	aad.ptr = hdr;
	aad.len = sizeof(hdr);
	/* out.len is the plaintext length; the buffer also holds the tag,
	 * which is what the TinyCrypt CCM backend writes in place. */
	out.ptr = rec_buf;
	out.len = pt_len;
	tag.ptr = tag_buf;
	tag.len = ch->tag_len;

	{
		uint64_t t0 = read_cycles();

		r = aead(ENCRYPT, &in, &key, &nonce, &aad, &out, &tag);
		ch->enc_cyc += read_cycles() - t0;
		ch->enc_bytes += pt_len;
	}
	if (r != ok)
		return r;

	memcpy(rec_buf + pt_len, tag_buf, ch->tag_len);

	rec.ptr = rec_buf;
	rec.len = pt_len + ch->tag_len;
	r = tx(sock, &rec);
	if (r != ok)
		return r;

	ch->tx_seq++;
	return ok;
}

enum err app_data_recv(struct app_chan *ch, uint8_t *pt, uint32_t pt_cap,
		       uint32_t *pt_len, app_rx_fn rx, void *sock)
{
	uint8_t hdr[APP_HDR_LEN];
	uint8_t nonce_buf[APP_IV_MAX];
	struct byte_array in, key, nonce, aad, out, tag, rec;
	uint32_t ct_len;
	enum err r;

	rec.ptr = rec_buf;
	rec.len = sizeof(rec_buf);
	r = rx(sock, &rec);
	if (r != ok)
		return r;
	if (rec.len < ch->tag_len)
		return buffer_to_small;

	ct_len = rec.len - ch->tag_len;
	if (ct_len > pt_cap)
		return buffer_to_small;

	/* The peer's direction byte is the opposite of ours. */
	mk_hdr(hdr, ch->is_initiator ? 1 : 0, ch->rx_seq);
	mk_nonce(ch, nonce_buf, hdr);

	in.ptr = rec_buf;
	in.len = rec.len; /* ciphertext || tag */
	key.ptr = ch->key;
	key.len = ch->key_len;
	nonce.ptr = nonce_buf;
	nonce.len = ch->iv_len;
	aad.ptr = hdr;
	aad.len = sizeof(hdr);
	out.ptr = pt;
	out.len = ct_len;
	tag.ptr = rec_buf + ct_len;
	tag.len = ch->tag_len;

	{
		uint64_t t0 = read_cycles();

		r = aead(DECRYPT, &in, &key, &nonce, &aad, &out, &tag);
		ch->dec_cyc += read_cycles() - t0;
		ch->dec_bytes += ct_len;
	}
	if (r != ok)
		return r;

	*pt_len = ct_len;
	ch->rx_seq++;
	return ok;
}

/* ---- Bulk transfer -------------------------------------------------- */

/* Deterministic payload generator: a 32-bit LCG. The receiver runs the same
 * sequence, so content is verified without buffering the stream. */
static uint32_t lcg_next(uint32_t *st)
{
	*st = (*st * 1664525u) + 1013904223u;
	return *st;
}

enum err app_file_send(struct app_chan *ch, uint32_t total, app_tx_fn tx,
		       void *sock, struct app_file_stats *st)
{
	uint8_t chunk[APP_PT_MAX];
	uint8_t hdr[4];
	uint32_t seed = APP_FILE_SEED;
	uint32_t sent = 0;
	uint64_t t0;
	enum err r;

	st->bytes = 0;
	st->chunks = 0;
	st->cycles = 0;
	st->bad_chunks = 0;

	hdr[0] = (uint8_t)(total >> 24);
	hdr[1] = (uint8_t)(total >> 16);
	hdr[2] = (uint8_t)(total >> 8);
	hdr[3] = (uint8_t)total;
	r = app_data_send(ch, hdr, sizeof(hdr), tx, sock);
	if (r != ok)
		return r;

	t0 = read_cycles();
	while (sent < total) {
		uint32_t n = total - sent;

		if (n > APP_PT_MAX)
			n = APP_PT_MAX;
		for (uint32_t i = 0; i < n; i++)
			chunk[i] = (uint8_t)(lcg_next(&seed) >> 24);

		r = app_data_send(ch, chunk, n, tx, sock);
		if (r != ok)
			return r;

		sent += n;
		st->chunks++;
	}
	st->cycles = read_cycles() - t0;
	st->bytes = sent;
	return ok;
}

enum err app_file_recv(struct app_chan *ch, app_rx_fn rx, void *sock,
		       struct app_file_stats *st)
{
	uint8_t chunk[APP_PT_MAX];
	uint32_t seed = APP_FILE_SEED;
	uint32_t total, got = 0, n;
	uint64_t t0;
	enum err r;

	st->bytes = 0;
	st->chunks = 0;
	st->cycles = 0;
	st->bad_chunks = 0;

	r = app_data_recv(ch, chunk, sizeof(chunk), &n, rx, sock);
	if (r != ok)
		return r;
	if (n != 4)
		return buffer_to_small;
	total = ((uint32_t)chunk[0] << 24) | ((uint32_t)chunk[1] << 16) |
		((uint32_t)chunk[2] << 8) | (uint32_t)chunk[3];

	t0 = read_cycles();
	while (got < total) {
		r = app_data_recv(ch, chunk, sizeof(chunk), &n, rx, sock);
		if (r != ok)
			return r;

		/* Regenerate what this chunk should hold and compare. */
		for (uint32_t i = 0; i < n; i++) {
			if (chunk[i] != (uint8_t)(lcg_next(&seed) >> 24)) {
				st->bad_chunks++;
				break;
			}
		}

		got += n;
		st->chunks++;
	}
	st->cycles = read_cycles() - t0;
	st->bytes = got;
	return ok;
}

enum err app_data_run_initiator(struct app_chan *ch, app_tx_fn tx, app_rx_fn rx,
				void *sock)
{
	uint8_t pt[APP_PT_MAX];
	uint32_t pt_len;
	enum err r;

	kprintf("APP: channel up (aead=%d key=%u iv=%u tag=%u)\r\n",
		(int)ch->ste.app_aead, (unsigned)ch->key_len,
		(unsigned)ch->iv_len, (unsigned)ch->tag_len);
	uint64_t t_app0 = read_cycles();

	/* Wait for the responder to say it is listening. In Method 3 the
	 * initiator sends message_3 last, so it leaves the handshake first and
	 * would otherwise transmit while the responder is still processing
	 * message_3 and deriving its keys. UART1 has no receive FIFO, so those
	 * bytes are lost outright. Gating on this record removes the race. */
	r = app_data_recv(ch, pt, sizeof(pt), &pt_len, rx, sock);
	if (r != ok) {
		kprintf("APP: ready-wait FAIL %d\r\n", r);
		return r;
	}

	for (uint32_t i = 0; i < APP_DEMO_ROUNDS; i++) {
		char req[32];
		uint32_t req_len = 0;

		/* "REQ n FROM INITIATOR" without depending on snprintf */
		const char *p = "REQ ";
		while (*p)
			req[req_len++] = *p++;
		req[req_len++] = (char)('0' + i);
		p = " FROM INITIATOR";
		while (*p)
			req[req_len++] = *p++;

		r = app_data_send(ch, (const uint8_t *)req, req_len, tx, sock);
		if (r != ok) {
			kprintf("APP: send %u FAIL %d\r\n", (unsigned)i, r);
			return r;
		}
		print_msg("sent   ", (const uint8_t *)req, req_len);

		r = app_data_recv(ch, pt, sizeof(pt), &pt_len, rx, sock);
		if (r != ok) {
			kprintf("APP: recv %u FAIL %d\r\n", (unsigned)i, r);
			return r;
		}
		print_msg("got    ", pt, pt_len);
	}

	perf_step("appdata_echo     ", read_cycles() - t_app0);

#ifdef APP_FILE_BYTES
	{
		struct app_file_stats st;

		kprintf("APP: sending %u bytes\r\n", (unsigned)APP_FILE_BYTES);
		r = app_file_send(ch, (uint32_t)APP_FILE_BYTES, tx, sock, &st);
		if (r != ok) {
			kprintf("APP: file send FAIL %d\r\n", r);
			return r;
		}
		perf_xfer("file_tx     ", st.bytes, st.cycles);
		kprintf("APP FILE TX: bytes=%u chunks=%u\r\n",
			(unsigned)st.bytes, (unsigned)st.chunks);
	}
#endif

#ifdef APP_SD_XFER
	/* SEND.BIN from this board's SD card to the responder's RECV.BIN. */
	r = file_xfer_send(ch, tx, sock);
	if (r != ok) {
		kprintf("XFER FAIL %d\r\n", r);
		return r;
	}
#endif

	perf_xfer("encrypt     ", ch->enc_bytes, ch->enc_cyc);
	perf_xfer("decrypt     ", ch->dec_bytes, ch->dec_cyc);
	kprintf("APP DATA OK\r\n");
	return ok;
}

enum err app_data_run_responder(struct app_chan *ch, app_tx_fn tx, app_rx_fn rx,
				void *sock)
{
	uint8_t pt[APP_PT_MAX];
	uint8_t reply[APP_PT_MAX];
	uint32_t pt_len;
	enum err r;

	kprintf("APP: channel up (aead=%d key=%u iv=%u tag=%u)\r\n",
		(int)ch->ste.app_aead, (unsigned)ch->key_len,
		(unsigned)ch->iv_len, (unsigned)ch->tag_len);
	uint64_t t_app0 = read_cycles();

	/* Tell the initiator we are about to listen (see the matching comment in
	 * app_data_run_initiator). Sending this last means the very next thing we
	 * do is enter the receive loop. Both transports deliver it only once the
	 * initiator is receiving: the radio repeats each frame until it is
	 * acknowledged, UART1 waits for the receiver's FRAME_READY. */
	{
		static const uint8_t ready = 'R';

		r = app_data_send(ch, &ready, 1, tx, sock);
		if (r != ok) {
			kprintf("APP: ready-send FAIL %d\r\n", r);
			return r;
		}
	}

	for (uint32_t i = 0; i < APP_DEMO_ROUNDS; i++) {
		uint32_t reply_len = 0;
		const char *p = "ECHO[";

		r = app_data_recv(ch, pt, sizeof(pt), &pt_len, rx, sock);
		if (r != ok) {
			kprintf("APP: recv %u FAIL %d\r\n", (unsigned)i, r);
			return r;
		}
		print_msg("got    ", pt, pt_len);

		while (*p)
			reply[reply_len++] = (uint8_t)*p++;
		if (pt_len > APP_PT_MAX - 6) /* room for "ECHO[" and "]" */
			pt_len = APP_PT_MAX - 6;
		memcpy(reply + reply_len, pt, pt_len);
		reply_len += pt_len;
		reply[reply_len++] = ']';

		r = app_data_send(ch, reply, reply_len, tx, sock);
		if (r != ok) {
			kprintf("APP: send %u FAIL %d\r\n", (unsigned)i, r);
			return r;
		}
		print_msg("sent   ", reply, reply_len);
	}

	perf_step("appdata_echo     ", read_cycles() - t_app0);

#ifdef APP_FILE_BYTES
	{
		struct app_file_stats st;

		r = app_file_recv(ch, rx, sock, &st);
		if (r != ok) {
			kprintf("APP: file recv FAIL %d\r\n", r);
			return r;
		}
		perf_xfer("file_rx     ", st.bytes, st.cycles);
		kprintf("APP FILE RX: bytes=%u chunks=%u bad=%u\r\n",
			(unsigned)st.bytes, (unsigned)st.chunks,
			(unsigned)st.bad_chunks);
		kprintf(st.bad_chunks == 0 ? "APP FILE OK\r\n"
					   : "APP FILE CORRUPT\r\n");
	}
#endif

#ifdef APP_SD_XFER
	r = file_xfer_recv(ch, rx, sock);
	if (r != ok) {
		kprintf("XFER FAIL %d\r\n", r);
		return r;
	}
#endif

	perf_xfer("encrypt     ", ch->enc_bytes, ch->enc_cyc);
	perf_xfer("decrypt     ", ch->dec_bytes, ch->dec_cyc);
	kprintf("APP DATA OK\r\n");
	return ok;
}
