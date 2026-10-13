/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef PRK_H
#define PRK_H

#include <stdint.h>
#include <stdbool.h>

#include "edhoc/suites.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief			One EDHOC_Extract step of the authkem-00 key
 *				schedule (section 3.1.1).
 *
 * All three pseudorandom keys come from a KEM shared secret; Method 5 never
 * performs an ECDH exchange.
 *
 *   PRK_2e   = EDHOC_Extract( TH_2,      ss_eph )   use_th_as_salt = true
 *   PRK_3e2m = EDHOC_Extract( SALT_3e2m, ss_R   )   salt_label = SALT_3e2m
 *   PRK_4e3m = EDHOC_Extract( SALT_4e3m, ss_I   )   salt_label = SALT_4e3m
 *
 * With use_th_as_salt the transcript hash is the salt directly and prk_in is
 * unused. Otherwise the salt is first derived as
 * EDHOC_KDF(prk_in, salt_label, th, hash_length).
 *
 * @param suite			The cipher suite in use.
 * @param salt_label		EDHOC_KDF label for the salt (ignored when
 *				use_th_as_salt is true).
 * @param[in] th		Transcript hash used as salt or as KDF context.
 * @param[in] prk_in		PRK the salt is derived from.
 * @param[in] kem_ss		KEM shared secret used as IKM.
 * @param[out] prk_out		The resulting PRK, PRK_SIZE bytes.
 * @param use_th_as_salt	True to use th directly as the salt.
 * @retval			Ok or error code.
 */
enum err authkem_prk_extract(struct suite suite, uint8_t salt_label,
			     struct byte_array *th,
			     const struct byte_array *prk_in,
			     struct byte_array *kem_ss, uint8_t *prk_out,
			     bool use_th_as_salt);

#endif
