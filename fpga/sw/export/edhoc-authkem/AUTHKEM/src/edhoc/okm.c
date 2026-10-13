/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/buffer_sizes.h"

#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"

#include "common/crypto_wrapper.h"
#include "cbor.h"
#include "common/oscore_edhoc_error.h"

#include "common/print_util.h"

/* EDHOC_KDF(PRK, label, context, length) = EDHOC_Expand(PRK, info, length)
 * with info = (label : uint, context : bstr, length : uint), RFC 9528
 * Section 4.1.2. The context is given in parts and streamed into the KDF, so
 * a context_2/context_3 that embeds a credential is never assembled. */
#define KDF_MAX_CTX_PARTS 6

enum err edhoc_kdf_parts(enum hash_alg hash_alg, const struct byte_array *prk,
			 uint32_t label, const struct hash_part *ctx,
			 uint32_t n, struct byte_array *okm)
{
	uint8_t lab[9], hdr[9], len[9], h[9];
	struct hash_part p[KDF_MAX_CTX_PARTS + 3];
	uint32_t ctx_len = 0;

	if (n > KDF_MAX_CTX_PARTS)
		return wrong_parameter;
	for (uint32_t i = 0; i < n; i++)
		ctx_len += ctx[i].len + (ctx[i].as_bstr ? cbor_head(h, 2, ctx[i].len) : 0);
	p[0] = (struct hash_part){ .ptr = lab, .len = cbor_head(lab, 0, label) };
	p[1] = (struct hash_part){ .ptr = hdr, .len = cbor_head(hdr, 2, ctx_len) };
	for (uint32_t i = 0; i < n; i++)
		p[2 + i] = ctx[i];
	p[2 + n] = (struct hash_part){ .ptr = len, .len = cbor_head(len, 0, okm->len) };
	return hkdf_expand_parts(hash_alg, prk, p, n + 3, okm);
}

enum err edhoc_kdf(enum hash_alg hash_alg, const struct byte_array *prk,
		   uint32_t label, struct byte_array *context,
		   struct byte_array *okm)
{
	struct hash_part c = { .ptr = context->ptr, .len = context->len };
	return edhoc_kdf_parts(hash_alg, prk, label, &c, 1, okm);
}
