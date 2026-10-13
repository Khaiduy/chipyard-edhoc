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

#include "edhoc/suites.h"
#include "edhoc/prk.h"
#include "edhoc/okm.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

enum err authkem_prk_extract(struct suite suite, uint8_t salt_label,
			     struct byte_array *th,
			     const struct byte_array *prk_in,
			     struct byte_array *kem_ss, uint8_t *prk_out,
			     bool use_th_as_salt)
{
	if (use_th_as_salt) {
		/* PRK_2e = EDHOC_Extract(TH_2, ss_eph) -- section 3.1.1.1. */
		TRY(hkdf_extract(suite.edhoc_hash, th, kem_ss, prk_out));
		return ok;
	}

	/* PRK_3e2m / PRK_4e3m: derive the salt first -- sections 3.1.1.2,
	 * 3.1.1.3. */
	BYTE_ARRAY_NEW(salt, HASH_SIZE, get_hash_len(suite.edhoc_hash));
	TRY(edhoc_kdf(suite.edhoc_hash, prk_in, salt_label, th, &salt));
	PRINT_ARRAY("authkem salt", salt.ptr, salt.len);
	TRY(hkdf_extract(suite.edhoc_hash, &salt, kem_ss, prk_out));
	return ok;
}
