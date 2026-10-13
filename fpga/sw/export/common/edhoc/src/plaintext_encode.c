/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>
#include <string.h>

#include "edhoc/plaintext.h"
#include "common/oscore_edhoc_error.h"

#include "cbor.h"

enum err id_cred2kid(const struct byte_array *id_cred, struct byte_array *kid)
{
	/* ID_CRED_x = { 4 : kid } is conveyed as kid alone (RFC 9528
	 * 3.5.3.2); any other map gives an empty kid. */
	struct cbor_r r;
	struct cbor_w w;
	uint8_t major;
	uint64_t n;
	int64_t label, v;
	const uint8_t *b;
	uint32_t blen;

	cbor_r_init(&r, id_cred->ptr, id_cred->len);
	if (cbor_get_head(&r, &major, &n) || major != CBOR_MAP)
		return cbor_decoding_error;
	if (n != 1 || cbor_get_int(&r, &label) || label != 4 /* kid */) {
		kid->len = 0;
		return ok;
	}
	cbor_w_init(&w, kid->ptr, kid->len);
	if (cbor_peek(&r) == CBOR_BSTR) {
		if (cbor_get_bstr(&r, &b, &blen))
			return cbor_decoding_error;
		/* A one-byte kid that is the CBOR encoding of an int in
		 * -24..23 is conveyed as that int. */
		if (blen == 1 && (b[0] <= 0x17 || (b[0] >= 0x20 && b[0] <= 0x37)))
			cbor_put_raw(&w, b, 1);
		else
			cbor_put_bstr(&w, b, blen);
	} else {
		if (cbor_get_int(&r, &v))
			return cbor_decoding_error;
		cbor_put_int(&w, v);
	}
	if (w.err || r.p != r.end)
		return cbor_encoding_error;
	kid->len = w.len;
	return ok;
}

bool c_x_is_encoded_int(const struct byte_array *c_x)
{
	return c_x->len == 1 &&
	       (c_x->ptr[0] <= 0x17 || (c_x->ptr[0] >= 0x20 && c_x->ptr[0] <= 0x37));
}

bool c_x_item_valid(const uint8_t *item, uint32_t n)
{
	struct cbor_r r;
	const uint8_t *b;
	uint32_t len;

	if (n == 1)
		return c_x_is_encoded_int(&(struct byte_array){ .ptr = (uint8_t *)item,
								 .len = 1 });
	cbor_r_init(&r, item, n);
	return cbor_peek(&r) == CBOR_BSTR && !cbor_get_bstr(&r, &b, &len) &&
	       r.p == r.end &&
	       !c_x_is_encoded_int(&(struct byte_array){ .ptr = (uint8_t *)b,
							  .len = len });
}

/* A bare int or bstr is the compact form of { 4 : kid }; kid is a byte
 * string, and a compact int stands for the one-byte kid that is its own
 * encoding (-14, 0x2d, is h'2d'). A full map is taken as sent unless it is
 * { 4 : kid } alone, which must have been compact. */
enum err id_cred_read(struct cbor_r *r, struct byte_array *id_cred)
{
	const uint8_t *b = r->p;
	uint32_t n;
	int64_t v;
	struct cbor_w w;

	if (cbor_peek(r) == CBOR_MAP) {
		if (cbor_get_item(r, &b, &n) || (n > 1 && b[0] == 0xa1 && b[1] == 0x04))
			return cbor_decoding_error;
		if (n > id_cred->len)
			return buffer_to_small;
		memcpy(id_cred->ptr, b, n);
		id_cred->len = n;
		return ok;
	}
	if (cbor_peek(r) == CBOR_BSTR) {
		if (cbor_get_bstr(r, &b, &n) ||
		    c_x_is_encoded_int(&(struct byte_array){ .ptr = (uint8_t *)b,
							      .len = n }))
			return cbor_decoding_error;
	} else {
		if (cbor_get_int(r, &v) || r->p != b + 1)  /* one-byte ints only */
			return cbor_decoding_error;
		n = 1;
	}
	cbor_w_init(&w, id_cred->ptr, id_cred->len);
	cbor_put_head(&w, CBOR_MAP, 1);
	cbor_put_head(&w, CBOR_UINT, 4);
	cbor_put_bstr(&w, b, n);
	if (w.err)
		return buffer_to_small;
	id_cred->len = w.len;
	return ok;
}
