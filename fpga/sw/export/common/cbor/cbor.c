/* cbor.c - see cbor.h. */
#include <string.h>
#include "cbor.h"

void cbor_w_init(struct cbor_w *w, uint8_t *buf, uint32_t cap)
{
	w->p = buf;
	w->len = 0;
	w->cap = cap;
	w->err = 0;
}

void cbor_put_raw(struct cbor_w *w, const uint8_t *b, uint32_t n)
{
	if (w->err || n > w->cap - w->len) {
		w->err = 1;
		return;
	}
	if (n)
		memcpy(w->p + w->len, b, n);
	w->len += n;
}

uint32_t cbor_head(uint8_t h[9], uint8_t major, uint64_t v)
{
	uint32_t n = v < 24 ? 0 : v <= 0xff ? 1 : v <= 0xffff ? 2 :
		     v <= 0xffffffffu ? 4 : 8;

	h[0] = (uint8_t)(major << 5 | (n == 0 ? v : n == 1 ? 24 : n == 2 ? 25 :
				       n == 4 ? 26 : 27));
	for (uint32_t i = 0; i < n; i++)
		h[1 + i] = (uint8_t)(v >> (8 * (n - 1 - i)));
	return 1 + n;
}

void cbor_put_head(struct cbor_w *w, uint8_t major, uint64_t v)
{
	uint8_t h[9];

	cbor_put_raw(w, h, cbor_head(h, major, v));
}

void cbor_put_int(struct cbor_w *w, int64_t v)
{
	if (v >= 0)
		cbor_put_head(w, CBOR_UINT, (uint64_t)v);
	else
		cbor_put_head(w, CBOR_NINT, (uint64_t)(-1 - v));
}

void cbor_put_bstr(struct cbor_w *w, const uint8_t *b, uint32_t n)
{
	cbor_put_head(w, CBOR_BSTR, n);
	cbor_put_raw(w, b, n);
}

void cbor_put_tstr(struct cbor_w *w, const uint8_t *s, uint32_t n)
{
	cbor_put_head(w, CBOR_TSTR, n);
	cbor_put_raw(w, s, n);
}

void cbor_r_init(struct cbor_r *r, const uint8_t *buf, uint32_t len)
{
	r->p = buf;
	r->end = buf + len;
}

int cbor_peek(const struct cbor_r *r)
{
	return r->p < r->end ? *r->p >> 5 : -1;
}

int cbor_get_head(struct cbor_r *r, uint8_t *major, uint64_t *v)
{
	uint8_t ai;
	uint32_t n;

	if (r->p >= r->end)
		return -1;
	*major = *r->p >> 5;
	ai = *r->p++ & 31;
	if (ai < 24) {
		*v = ai;
		return 0;
	}
	if (ai > 27)                  /* reserved, or indefinite length */
		return -1;
	n = 1u << (ai - 24);
	if ((uint32_t)(r->end - r->p) < n)
		return -1;
	*v = 0;
	while (n--)
		*v = *v << 8 | *r->p++;
	/* Deterministic encoding (RFC 8949 4.2.1, required by RFC 9528 1.2):
	 * an argument must use the shortest head, e.g. 19 00 03 is not 3. */
	if (*v < (ai == 24 ? 24u : 1ull << (8u << (ai - 25))))
		return -1;
	return 0;
}

int cbor_get_int(struct cbor_r *r, int64_t *v)
{
	uint8_t major;
	uint64_t u;

	if (cbor_get_head(r, &major, &u) || major > CBOR_NINT ||
	    u > (uint64_t)INT64_MAX)
		return -1;
	*v = major == CBOR_UINT ? (int64_t)u : -1 - (int64_t)u;
	return 0;
}

int cbor_get_bstr(struct cbor_r *r, const uint8_t **b, uint32_t *n)
{
	uint8_t major;
	uint64_t len;

	if (cbor_get_head(r, &major, &len) || major != CBOR_BSTR ||
	    len > (uint64_t)(r->end - r->p))
		return -1;
	*b = r->p;
	*n = (uint32_t)len;
	r->p += len;
	return 0;
}

/* Nesting is bounded so hostile input (e.g. 81 81 81 ...) cannot exhaust
 * the stack; EDHOC items nest at most two deep (ID_CRED map values). */
#define CBOR_MAX_DEPTH 4

static int skip(struct cbor_r *r, int depth)
{
	uint8_t major;
	uint64_t v;

	if (depth > CBOR_MAX_DEPTH || cbor_get_head(r, &major, &v))
		return -1;
	switch (major) {
	case CBOR_BSTR:
	case CBOR_TSTR:
		if (v > (uint64_t)(r->end - r->p))
			return -1;
		r->p += v;
		return 0;
	case CBOR_ARRAY:
	case CBOR_MAP:
		if (v > (uint64_t)(r->end - r->p))   /* every item is >= 1 byte */
			return -1;
		for (uint64_t i = 0; i < (major == CBOR_MAP ? 2 * v : v); i++)
			if (skip(r, depth + 1))
				return -1;
		return 0;
	case 6:                                       /* tag + tagged item */
		return skip(r, depth + 1);
	default:                                      /* ints, simple values */
		return 0;
	}
}

int cbor_get_item(struct cbor_r *r, const uint8_t **b, uint32_t *n)
{
	const uint8_t *start = r->p;

	if (skip(r, 0))
		return -1;
	*b = start;
	*n = (uint32_t)(r->p - start);
	return 0;
}
