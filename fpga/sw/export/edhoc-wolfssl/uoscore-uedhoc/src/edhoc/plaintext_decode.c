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
#include <stdbool.h>

#include "edhoc/retrieve_cred.h"
#include "edhoc/plaintext.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/int_encode_decode.h"
#include "edhoc/ead.h"

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor.h"

/* The rest of a plaintext after ID_CRED_x: SGN_or_MAC_x : bstr, ? EAD. EAD
 * is a trailing CBOR sequence, not a bstr. */
static enum err sig_mac_ead_read(struct cbor_r *r,
				 struct byte_array *sign_or_mac,
				 struct byte_array *ead)
{
	const uint8_t *b;
	uint32_t n;

	if (cbor_get_bstr(r, &b, &n))
		return cbor_decoding_error;
	TRY(_memcpy_s(sign_or_mac->ptr, sign_or_mac->len, b, n));
	sign_or_mac->len = n;
	n = (uint32_t)(r->end - r->p);
	TRY(_memcpy_s(ead->ptr, ead->len, r->p, n));
	ead->len = n;
	return ead_validate(ead);
}

enum err plaintext_split(struct byte_array *ptxt, struct byte_array *c_r,
			 struct byte_array *id_cred_x,
			 struct byte_array *sign_or_mac, struct byte_array *ead)
{
	/* PLAINTEXT_2 = ( C_R, ID_CRED_R / bstr / int, SGN_or_MAC_2, ? EAD_2 )
	 * PLAINTEXT_3 = ( ID_CRED_I / bstr / int, SGN_or_MAC_3, ? EAD_3 ) */
	struct cbor_r r;
	const uint8_t *b;
	uint32_t n;
	int64_t v;

	cbor_r_init(&r, ptxt->ptr, ptxt->len);
	/* C_R is present only in plaintext 2. An int C_R is kept in its
	 * encoded form, as the responder chose it. */
	if (c_r != NULL) {
		if (cbor_peek(&r) == CBOR_BSTR) {
			if (cbor_get_bstr(&r, &b, &n))
				return cbor_decoding_error;
			/* RFC 9528 3.3.2, as for C_I */
			if (c_x_is_encoded_int(&(struct byte_array){
				    .ptr = (uint8_t *)b, .len = n }))
				return cbor_decoding_error;
			TRY(_memcpy_s(c_r->ptr, c_r->len, b, n));
			c_r->len = n;
		} else {
			if (cbor_get_int(&r, &v) || v < -24 || v > 23)
				return cbor_decoding_error;
			int32_t c = (int32_t)v;
			TRY(encode_int(&c, 1, c_r));
		}
	}
	TRY(id_cred_read(&r, id_cred_x));
	return sig_mac_ead_read(&r, sign_or_mac, ead);
}
