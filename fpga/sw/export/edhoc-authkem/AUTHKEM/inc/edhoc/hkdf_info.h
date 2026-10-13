/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef HKDF_INFO_H
#define HKDF_INFO_H

#include "suites.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

enum info_label {
	KEYSTREAM_2 = 0,
	SALT_3e2m = 1,
	MAC_2 = 2,
	K_3 = 3,
	IV_3 = 4,
	SALT_4e3m = 5,
	MAC_3 = 6,
	PRK_out = 7,
	K_4 = 8,
	IV_4 = 9,
	PRK_exporter = 10,
	PRK_out_update = 11,
	/* draft-ietf-lake-authkem-edhoc-01 Section 4.1.2: message_5_KEM is
	 * protected by its own key, derived from PRK_4e3m with labels 11 and 12
	 * (11 is PRK_out_update in RFC 9528, which derives from PRK_out). */
	K_5 = 11,
	IV_5 = 12,
};

/* Legacy, unused IKR labels retained for source compatibility. The active
 * five-message AuthKEM state machine uses enum info_label above. */
enum ikr_info_label {
	IKR_K_1         = 0,
	IKR_IV_1        = 1,
	IKR_SALT_2m     = 2,
	IKR_MAC_2       = 3,
	IKR_SALT_2e3e3m = 4,
	IKR_K_2         = 5,
	IKR_IV_2        = 6,
	IKR_MAC_3       = 7,
	IKR_K_3         = 8,
	IKR_IV_3        = 9,
	IKR_PRK_out     = 10,
	IKR_K_4         = 11,
	IKR_IV_4        = 12,
	IKR_PRK_exporter= 13,
};

/**
 * @brief   			Encodes the HKDF Info. 
 * 
 * @param label 		An int value indicating what kind of output we 
 * 				are generating.
 * @param[in] context 		All possible contexts are listed in figure 7 
 * 				in the spec.
 * @param okm_len 		The length of the output keying material.
 * @param[out] out 		The result.
 * @return  			Ok or error code.
 */
enum err create_hkdf_info(uint32_t label, struct byte_array *context,
			  uint32_t okm_len, struct byte_array *out);

#endif
