/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */


#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"
#include "common/byte_array.h"
#include "cbor.h"

enum err encode_bstr(const struct byte_array *in, struct byte_array *out)
{
	struct cbor_w w;

	cbor_w_init(&w, out->ptr, out->len);
	cbor_put_bstr(&w, in->ptr, in->len);
	if (w.err)
		return cbor_encoding_error;
	out->len = w.len;
	return ok;
}

enum err decode_bstr(const struct byte_array *in, struct byte_array *out)
{
	struct cbor_r r;
	const uint8_t *b;
	uint32_t n;

	cbor_r_init(&r, in->ptr, in->len);
	if (cbor_get_bstr(&r, &b, &n) || r.p != r.end)
		return cbor_decoding_error;
	TRY(_memcpy_s(out->ptr, out->len, b, n));
	out->len = n;
	return ok;
}
