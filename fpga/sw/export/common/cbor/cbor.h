/*
 * cbor.h - the CBOR subset EDHOC needs (RFC 8949): unsigned and negative
 * integers, byte and text strings, array and map heads, all definite-length,
 * shortest-form on output. Replaces the zcbor-generated codecs.
 *
 * Writer errors latch in w->err (any later put is a no-op), so a caller
 * emits a whole structure and checks once. Reader calls return 0 on
 * success, -1 on malformed or truncated input.
 */
#ifndef CBOR_H
#define CBOR_H

#include <stdint.h>

enum { CBOR_UINT = 0, CBOR_NINT = 1, CBOR_BSTR = 2, CBOR_TSTR = 3,
       CBOR_ARRAY = 4, CBOR_MAP = 5 };

struct cbor_w {
	uint8_t *p;
	uint32_t len, cap;
	int err;
};

/* Encode a head (major type + argument) into h; returns its length. */
uint32_t cbor_head(uint8_t h[9], uint8_t major, uint64_t v);

void cbor_w_init(struct cbor_w *w, uint8_t *buf, uint32_t cap);
void cbor_put_head(struct cbor_w *w, uint8_t major, uint64_t v);
void cbor_put_int(struct cbor_w *w, int64_t v);
void cbor_put_bstr(struct cbor_w *w, const uint8_t *b, uint32_t n);
void cbor_put_tstr(struct cbor_w *w, const uint8_t *s, uint32_t n);
void cbor_put_raw(struct cbor_w *w, const uint8_t *b, uint32_t n);

struct cbor_r {
	const uint8_t *p, *end;
};

void cbor_r_init(struct cbor_r *r, const uint8_t *buf, uint32_t len);
/* Major type of the next item, or -1 at the end of the input. */
int cbor_peek(const struct cbor_r *r);
int cbor_get_head(struct cbor_r *r, uint8_t *major, uint64_t *v);
int cbor_get_int(struct cbor_r *r, int64_t *v);
int cbor_get_bstr(struct cbor_r *r, const uint8_t **b, uint32_t *n);
/* Skip one complete item, nested arrays and maps included (at most
 * CBOR_MAX_DEPTH levels deep), returning the encoded item's span. */
int cbor_get_item(struct cbor_r *r, const uint8_t **b, uint32_t *n);

#endif /* CBOR_H */
