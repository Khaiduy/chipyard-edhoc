/*
 * authkem_messages.c — CBOR encode/decode for the five authkem-01 messages.
 * draft-ietf-lake-authkem-edhoc-01 section 5.
 *
 * Every message is a CBOR Sequence. Each item is self-delimiting and the
 * cursor advances by exactly the bytes consumed -- a fixed-offset scheme
 * cannot parse these, because ID_CRED and EAD are variable length.
 */
#include "edhoc/plaintext.h"
#include <string.h>

#include "cbor.h"

#include "edhoc/authkem_messages.h"
#include "edhoc/buffer_sizes.h"
#include "edhoc/ead.h"

#include "common/memcpy_s.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

/* ---- message_1 --------------------------------------------------------- */
/* A suite byte holds its label as a signed 8-bit value, so the RFC 9528
 * private-use labels -24..-21 (where pqsuites TBD2 sits until it is
 * assigned) travel as negative CBOR integers. EAD_1 is a CBOR sequence
 * spliced straight into message_1, not a bstr. */
enum err authkem_msg1_encode(int32_t method, const struct byte_array *suites,
			     const struct byte_array *pk_eph,
			     const struct byte_array *c_i,
			     const struct byte_array *ead,
			     struct byte_array *out)
{
	struct cbor_w w;
	struct cbor_r r;
	const uint8_t *b;
	uint32_t n;

	if (!suites || suites->len == 0)
		return suites_i_list_empty;
	/* C_I must be exactly one CBOR item */
	cbor_r_init(&r, c_i->ptr, c_i->len);
	if (c_i->len == 0 || cbor_get_item(&r, &b, &n) || r.p != r.end)
		return cbor_decoding_error;
	if (ead)
		TRY(ead_validate(ead));

	cbor_w_init(&w, out->ptr, out->len);
	cbor_put_int(&w, method);
	if (suites->len == 1) {
		cbor_put_int(&w, (int8_t)suites->ptr[0]);
	} else {
		cbor_put_head(&w, CBOR_ARRAY, suites->len);
		for (uint32_t i = 0; i < suites->len; i++)
			cbor_put_int(&w, (int8_t)suites->ptr[i]);
	}
	cbor_put_bstr(&w, pk_eph->ptr, pk_eph->len);
	cbor_put_raw(&w, c_i->ptr, c_i->len);
	if (ead)
		cbor_put_raw(&w, ead->ptr, ead->len);
	if (w.err)
		return buffer_to_small;
	out->len = w.len;
	PRINT_ARRAY("authkem msg1", out->ptr, out->len);
	return ok;
}

enum err authkem_msg1_decode(const struct byte_array *msg, int32_t *method,
			     struct byte_array *suites, struct byte_array *pk_eph,
			     struct byte_array *c_i, struct byte_array *ead)
{
	struct cbor_r r;
	const uint8_t *b;
	uint32_t n;
	uint8_t major;
	uint64_t count;
	int64_t v;

	cbor_r_init(&r, msg->ptr, msg->len);
	if (cbor_get_int(&r, &v) || v < INT32_MIN || v > INT32_MAX)
		return cbor_decoding_error;
	*method = (int32_t)v;
	if (cbor_peek(&r) == CBOR_ARRAY) {
		if (cbor_get_head(&r, &major, &count) || count < 2)
			return cbor_decoding_error;
		if (count > suites->len)
			return suites_i_list_to_long;
	} else {
		count = 1;
	}
	for (uint32_t i = 0; i < count; i++) {
		if (cbor_get_int(&r, &v) || v < -128 || v > 127)
			return cbor_decoding_error;
		suites->ptr[i] = (uint8_t)v;
	}
	suites->len = (uint32_t)count;
	if (cbor_get_bstr(&r, &b, &n))
		return cbor_decoding_error;
	pk_eph->ptr = (uint8_t *)b;
	pk_eph->len = n;
	/* C_I = bstr / -24..23, an int-valued byte never as a bstr (RFC 9528
	 * 3.3.2) */
	if (cbor_get_item(&r, &b, &n) || !c_x_item_valid(b, n))
		return cbor_decoding_error;
	TRY(_memcpy_s(c_i->ptr, c_i->len, b, n));
	c_i->len = n;
	n = (uint32_t)(r.end - r.p);
	TRY(_memcpy_s(ead->ptr, ead->len, r.p, n));
	ead->len = n;
	TRY(ead_validate(ead));
	PRINT_ARRAY("authkem msg1 pk_eph", pk_eph->ptr, pk_eph->len);
	return ok;
}

/* ---- message_2, message_3, message_4_KEM, message_5_KEM ----------------- */
enum err authkem_msg_kem_open(struct byte_array *out, uint32_t ct_len,
			      uint32_t ciphertext_len, struct byte_array *ct,
			      struct byte_array *ciphertext)
{
	uint32_t total = ct_len + ciphertext_len;
	uint32_t hdr;

	if (out->len < 9)
		return buffer_to_small;
	hdr = cbor_head(out->ptr, CBOR_BSTR, total);
	if (out->len < hdr + total)
		return buffer_to_small;
	ct->ptr = out->ptr + hdr;
	ct->len = ct_len;
	ciphertext->ptr = ct->ptr + ct_len;
	ciphertext->len = ciphertext_len;
	out->len = hdr + total;
	return ok;
}

enum err authkem_msg_kem_split(const struct byte_array *msg, uint32_t ct_len,
			       struct byte_array *ct,
			       struct byte_array *ciphertext)
{
	struct cbor_r r;
	const uint8_t *b;
	uint32_t n;

	cbor_r_init(&r, msg->ptr, msg->len);
	if (cbor_get_bstr(&r, &b, &n) || r.p != r.end || n <= ct_len)
		return cbor_decoding_error;
	ct->ptr = (uint8_t *)b;
	ct->len = ct_len;
	ciphertext->ptr = (uint8_t *)b + ct_len;
	ciphertext->len = n - ct_len;
	return ok;
}
