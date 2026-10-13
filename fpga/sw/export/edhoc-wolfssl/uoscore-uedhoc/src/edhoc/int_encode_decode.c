/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include "common/oscore_edhoc_error.h"
#include "common/byte_array.h"
#include "cbor.h"





enum err encode_int(const int32_t *in, uint32_t in_len, struct byte_array *out)
{
	struct cbor_w w;

	(void)in_len;
	cbor_w_init(&w, out->ptr, out->len);
	cbor_put_int(&w, *in);
	if (w.err)
		return cbor_encoding_error;
	out->len = w.len;
	return ok;
}
