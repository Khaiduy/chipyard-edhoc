/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

/*
 * Transcript hashes for draft-ietf-lake-authkem-edhoc-01. Each input is a
 * CBOR sequence streamed into the hash in parts (crypto_wrapper hash_parts),
 * so no transcript buffer is ever assembled.
 */

#include "edhoc/th.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

/* TH_2 = H( bstr(H(message_1)) || bstr(ct_eph) ) */
enum err authkem_th2_calculate(enum hash_alg alg,
			       const struct byte_array *msg1_hash,
			       const struct byte_array *ct_eph,
			       struct byte_array *th2)
{
	struct hash_part p[2] = {
		{ .ptr = msg1_hash->ptr, .len = msg1_hash->len, .as_bstr = true },
		{ .ptr = ct_eph->ptr, .len = ct_eph->len, .as_bstr = true },
	};
	TRY(hash_parts(alg, p, 2, th2));
	PRINT_ARRAY("authkem TH_2", th2->ptr, th2->len);
	return ok;
}

/* TH_3 = H( bstr(TH_2) || PLAINTEXT_2 || CRED_R || bstr(ct_R) )
 * TH_4 = H( bstr(TH_3) || PLAINTEXT_3 || CRED_I || bstr(ct_I) )
 * TH_5 = H( bstr(TH_4) || PLAINTEXT_4 )                          */
enum err authkem_th_calculate(enum hash_alg alg,
			      const struct byte_array *th_prev,
			      const struct byte_array *plaintext,
			      const struct byte_array *cred,
			      const struct byte_array *ct,
			      struct byte_array *th)
{
	struct hash_part p[4] = {
		{ .ptr = th_prev->ptr, .len = th_prev->len, .as_bstr = true },
		{ .ptr = plaintext->ptr, .len = plaintext->len },
	};
	uint32_t n = 2;

	if (cred)
		p[n++] = (struct hash_part){ .ptr = cred->ptr, .len = cred->len };
	if (ct)
		p[n++] = (struct hash_part){ .ptr = ct->ptr, .len = ct->len, .as_bstr = true };
	TRY(hash_parts(alg, p, n, th));
	PRINT_ARRAY("authkem TH", th->ptr, th->len);
	return ok;
}
