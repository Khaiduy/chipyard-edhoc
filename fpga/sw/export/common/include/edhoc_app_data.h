/*
 * edhoc_app_data.h - Suite-independent application data channel.
 *
 * After a successful EDHOC handshake both peers hold the same PRK_out. This
 * module turns PRK_out into an AEAD-protected, bidirectional data channel that
 * runs over the same transport callbacks the handshake used.
 *
 * Nothing here is compiled per suite: the AEAD algorithm, key length, IV
 * length, tag length and hash are all read at run time from get_suite() and
 * the get_aead_*_len() helpers. The identical source therefore works for every
 * wolfCrypt suite (0-7, 24, 25) and for the ML-KEM build (suite 8).
 */
#ifndef EDHOC_APP_DATA_H
#define EDHOC_APP_DATA_H

#include <stdint.h>
#include "edhoc.h"
#include "perf.h"
#include "edhoc/suites.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/* Upper bounds over all supported suites (checked at run time in
 * app_data_init(), so adding a larger algorithm fails loudly, not silently). */
#define APP_KEY_MAX  32 /* ChaCha20/Poly1305, AES-256-GCM        */
#define APP_IV_MAX   16 /* Ascon-AEAD-128                        */
#define APP_TAG_MAX  16 /* everything except AES-CCM-16-64-128   */
#define APP_HASH_MAX 64 /* SHAKE256 (suite 25)                   */

/* Largest plaintext one record can carry. 206 + a 16-byte tag fills exactly
 * two radio fragments (2 x 111 bytes, see edhoc_rf_link.c). */
#define APP_PT_MAX   206

/* EDHOC_Exporter labels for this application (RFC 9528 4.2.1 uses an uint
 * label; 0/1 are the OSCORE ones, these are private to this demo). */
#define APP_KEY_LABEL 32768u
#define APP_IV_LABEL  32769u

/* Number of request/response exchanges app_data_run_*() performs. */
#define APP_DEMO_ROUNDS 3

typedef enum err (*app_tx_fn)(void *sock, struct byte_array *data);
typedef enum err (*app_rx_fn)(void *sock, struct byte_array *data);

struct app_chan {
	struct suite ste;
	uint8_t key[APP_KEY_MAX];
	uint8_t base_iv[APP_IV_MAX];
	uint32_t key_len;
	uint32_t iv_len;
	uint32_t tag_len;
	uint8_t is_initiator;
	uint32_t tx_seq;
	uint32_t rx_seq;
	uint64_t enc_cyc, dec_cyc;   /* AEAD time, reported by the run functions */
	uint32_t enc_bytes, dec_bytes;
};

/**
 * @brief			Derives the application key and IV from PRK_out.
 *
 * @param[out] ch		Channel state.
 * @param label			Cipher suite negotiated by the handshake.
 * @param[in] prk_out		PRK_out produced by edhoc_*_run().
 * @param is_initiator		Non-zero on the initiator, zero on the responder.
 * @return			ok or error code.
 */
enum err app_data_init(struct app_chan *ch, enum suite_label label,
		       struct byte_array *prk_out, int is_initiator);

/**
 * @brief			Encrypts one message and sends it as one frame.
 */
enum err app_data_send(struct app_chan *ch, const uint8_t *pt, uint32_t pt_len,
		       app_tx_fn tx, void *sock);

/**
 * @brief			Receives one frame and decrypts it.
 *
 * @param[out] pt		Plaintext output buffer.
 * @param pt_cap		Capacity of @p pt.
 * @param[out] pt_len		Number of plaintext bytes written.
 */
enum err app_data_recv(struct app_chan *ch, uint8_t *pt, uint32_t pt_cap,
		       uint32_t *pt_len, app_rx_fn rx, void *sock);

/* ---- Bulk transfer ------------------------------------------------------
 * Streams an arbitrary byte count over the same AEAD channel in APP_PT_MAX
 * chunks, each chunk one independent record. Memory use is constant: nothing
 * scales with the payload, so the transfer size is bounded by the link rate
 * and patience, not by RAM. Each record keeps its own sequence number, so a
 * lost or reordered chunk fails tag verification rather than corrupting data.
 *
 * The payload is generated from a 32-bit LCG seeded with APP_FILE_SEED, which
 * lets the receiver regenerate the expected bytes and verify them without
 * storing the stream. Replace app_file_send()'s generator with reads from
 * your own source (SD card, sensor, buffer) to send real content.
 *
 * Wire format: one 4-byte big-endian length record, then the payload chunks.
 */
#define APP_FILE_SEED 0x12345678u

struct app_file_stats {
	uint32_t bytes;      /* payload bytes transferred (excludes the header) */
	uint32_t chunks;     /* number of AEAD records used                     */
	uint64_t cycles;     /* cycles spent in the payload loop                */
	uint32_t bad_chunks; /* receiver only: chunks whose content mismatched  */
};

/**
 * @brief	Sends @p total bytes as a length record followed by chunks.
 */
enum err app_file_send(struct app_chan *ch, uint32_t total, app_tx_fn tx,
		       void *sock, struct app_file_stats *st);

/**
 * @brief	Receives a stream sent by app_file_send() and verifies it.
 *		The length is read from the stream, so the receiver does not
 *		need to know the size in advance.
 */
enum err app_file_recv(struct app_chan *ch, app_rx_fn rx, void *sock,
		       struct app_file_stats *st);

/* Demo exchange: the initiator sends APP_DEMO_ROUNDS requests and prints each
 * reply; the responder echoes every request back. */
enum err app_data_run_initiator(struct app_chan *ch, app_tx_fn tx, app_rx_fn rx,
				void *sock);
enum err app_data_run_responder(struct app_chan *ch, app_tx_fn tx, app_rx_fn rx,
				void *sock);

#endif /* EDHOC_APP_DATA_H */
