/*
 * authkem_plaintext.c — plaintexts and MACs for authkem-01.
 * draft-ietf-lake-authkem-edhoc-01 sections 5.2 - 5.5.
 *
 * Every field is a self-delimiting CBOR item; EAD_x is the trailing CBOR
 * sequence (RFC 9528 section 3.8), never a bstr-wrapped blob, and is opaque
 * to EDHOC: it is checked for well-formedness and passed through verbatim.
 */
#include <string.h>

#include "cbor.h"

#include "edhoc/authkem_plaintext.h"
#include "edhoc/plaintext.h"
#include "edhoc/okm.h"
#include "edhoc/ead.h"

#include "common/memcpy_s.h"
#include "common/print_util.h"

/* Append one CBOR item, which must be exactly that. */
static void put_item(struct cbor_w *w, const struct byte_array *item)
{
	struct cbor_r r;
	const uint8_t *b;
	uint32_t n;

	cbor_r_init(&r, item->ptr, item->len);
	if (item->len == 0 || cbor_get_item(&r, &b, &n) || r.p != r.end)
		w->err = 1;
	cbor_put_raw(w, item->ptr, item->len);
}

/* Read C_x, kept as its CBOR item: bstr / -24..23 (RFC 9528 3.3.2). */
static enum err c_x_read(struct cbor_r *r, struct byte_array *dst)
{
	const uint8_t *b;
	uint32_t n;

	if (cbor_get_item(r, &b, &n) || !c_x_item_valid(b, n))
		return cbor_decoding_error;
	if (dst->len < n)
		return buffer_to_small;
	memcpy(dst->ptr, b, n);
	dst->len = n;
	return ok;
}

static enum err finish(struct cbor_w *w, const struct byte_array *ead,
		       struct byte_array *out)
{
	if (ead) {
		TRY(ead_validate(ead));
		cbor_put_raw(w, ead->ptr, ead->len);
	}
	if (w->err)
		return buffer_to_small;
	out->len = w->len;
	return ok;
}

static enum err take_ead(const struct cbor_r *r, struct byte_array *ead)
{
	uint32_t n = (uint32_t)(r->end - r->p);

	TRY(_memcpy_s(ead->ptr, ead->len, r->p, n));
	ead->len = n;
	return ead_validate(ead);
}

/* ---- PLAINTEXT_2 = (C_R, ID_CRED_R, ?EAD_2)
 * ---- PLAINTEXT_3 = (C_I, ID_CRED_I, ?EAD_3) ---------------------------- */
static enum err plaintext23_encode(const struct byte_array *c_x,
				   const struct byte_array *id_cred_x,
				   const struct byte_array *ead,
				   struct byte_array *out)
{
	struct cbor_w w;

	BYTE_ARRAY_NEW(kid, id_cred_x->len, id_cred_x->len);
	TRY(id_cred2kid(id_cred_x, &kid));
	cbor_w_init(&w, out->ptr, out->len);
	put_item(&w, c_x);
	put_item(&w, kid.len ? &kid : id_cred_x);
	return finish(&w, ead, out);
}

static enum err plaintext23_decode(const struct byte_array *in,
				   struct byte_array *c_x,
				   struct byte_array *id_cred_x,
				   struct byte_array *ead)
{
	struct cbor_r r;

	cbor_r_init(&r, in->ptr, in->len);
	TRY(c_x_read(&r, c_x));
	TRY(id_cred_read(&r, id_cred_x));
	return take_ead(&r, ead);
}

enum err authkem_plaintext2_encode(const struct byte_array *c_r,
				   const struct byte_array *id_cred_r,
				   const struct byte_array *ead,
				   struct byte_array *out)
{
	return plaintext23_encode(c_r, id_cred_r, ead, out);
}

enum err authkem_plaintext2_decode(const struct byte_array *in,
				   struct byte_array *c_r,
				   struct byte_array *id_cred_r,
				   struct byte_array *ead)
{
	return plaintext23_decode(in, c_r, id_cred_r, ead);
}

enum err authkem_plaintext3_encode(const struct byte_array *c_i,
				   const struct byte_array *id_cred_i,
				   const struct byte_array *ead,
				   struct byte_array *out)
{
	return plaintext23_encode(c_i, id_cred_i, ead, out);
}

enum err authkem_plaintext3_decode(const struct byte_array *in,
				   struct byte_array *c_i,
				   struct byte_array *id_cred_i,
				   struct byte_array *ead)
{
	return plaintext23_decode(in, c_i, id_cred_i, ead);
}

/* ---- PLAINTEXT_4 / PLAINTEXT_5 = (MAC, ?EAD) --------------------------- */
enum err authkem_plaintext45_encode(const struct byte_array *mac,
				    const struct byte_array *ead,
				    struct byte_array *out)
{
	struct cbor_w w;

	cbor_w_init(&w, out->ptr, out->len);
	cbor_put_bstr(&w, mac->ptr, mac->len);
	return finish(&w, ead, out);
}

enum err authkem_plaintext45_decode(const struct byte_array *in,
				    struct byte_array *mac,
				    struct byte_array *ead)
{
	struct cbor_r r;
	const uint8_t *b;
	uint32_t n;

	cbor_r_init(&r, in->ptr, in->len);
	if (cbor_get_bstr(&r, &b, &n))
		return cbor_decoding_error;
	TRY(_memcpy_s(mac->ptr, mac->len, b, n));
	mac->len = n;
	return take_ead(&r, ead);
}

/* ---- MAC_2 / MAC_3 ------------------------------------------------------ */
enum err authkem_mac(enum hash_alg alg, const struct byte_array *prk,
		     uint32_t label, const struct byte_array *c_x,
		     const struct byte_array *id_cred_x,
		     const struct byte_array *th,
		     const struct byte_array *cred_x,
		     const struct byte_array *ead, struct byte_array *mac)
{
	struct hash_part ctx[5] = {
		{ .ptr = c_x->ptr, .len = c_x->len },
		{ .ptr = id_cred_x->ptr, .len = id_cred_x->len },
		{ .ptr = th->ptr, .len = th->len, .as_bstr = true },
		{ .ptr = cred_x->ptr, .len = cred_x->len },
		{ .ptr = ead ? ead->ptr : NULL, .len = ead ? ead->len : 0 },
	};
	return edhoc_kdf_parts(alg, prk, label, ctx, 5, mac);
}
