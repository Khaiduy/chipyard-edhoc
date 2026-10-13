/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef TH_H
#define TH_H

#include "suites.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/*
 * Transcript hashes for draft-ietf-lake-authkem-edhoc-01.
 *
 * draft-ietf-lake-authkem-edhoc-01 Section 5. The inputs are streamed into
 * the hash: TH_3/TH_4 embed a credential and a KEM ciphertext, which would
 * otherwise need a ~1.7 kB buffer.
 */

/**
 * @brief			TH_2 = H( H(message_1), ct_eph )
 *				[sections 5.2.2, 5.2.3]
 *
 * Encoded as the CBOR sequence bstr(H(message_1)) || bstr(ct_eph).
 */
enum err authkem_th2_calculate(enum hash_alg alg,
			       const struct byte_array *msg1_hash,
			       const struct byte_array *ct_eph,
			       struct byte_array *th2);

/**
 * @brief			TH_3, TH_4 and TH_5.
 *
 *   TH_3 = H( TH_2, PLAINTEXT_2, CRED_R, ct_R )   [sections 5.3.2, 5.3.3]
 *   TH_4 = H( TH_3, PLAINTEXT_3, CRED_I, ct_I )   [section 5.4.2]
 *   TH_5 = H( TH_4, PLAINTEXT_4 )                 [sections 5.4.2, 5.5.2]
 *
 * Encoded as the CBOR sequence bstr(th_prev) || plaintext || [cred] ||
 * [bstr(ct)], plaintext and cred being already-encoded CBOR, as in RFC 9528
 * Section 5.3.2. Pass cred and ct as NULL for TH_5.
 */
enum err authkem_th_calculate(enum hash_alg alg,
			      const struct byte_array *th_prev,
			      const struct byte_array *plaintext,
			      const struct byte_array *cred,
			      const struct byte_array *ct,
			      struct byte_array *th);

#endif
