/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include "edhoc/bstr_encode_decode.h"
#include "edhoc/retrieve_cred.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"


/**
 * @brief 			Get the local cred object.
 * 
 * @param static_dh_auth 	True if static DH is used for authentication.
 * @param[in] cred_array 	An array of trust anchors
 * @param[in] ID_cred 		The ID of the actual credential.
 * @param[out] cred 		The retrievd credentials	
 * @param[out] pk 		The retrievd signature authentication public key
 * @param[out] g 		The retrievd static DH authentication public key
 * @return 			Ok or error code
 */
static enum err get_local_cred(bool static_dh_auth,
			       struct cred_array *cred_array,
			       struct byte_array *ID_cred,
			       struct byte_array *cred, struct byte_array *pk,
			       struct byte_array *g)
{
	for (uint32_t i = 0; i < cred_array->len; i++) {
		if ((cred_array->ptr[i].id_cred.len == ID_cred->len) &&
		    (0 == memcmp(cred_array->ptr[i].id_cred.ptr, ID_cred->ptr,
				 ID_cred->len))) {
			/*retrieve CRED_x*/
			TRY(_memcpy_s(cred->ptr, cred->len,
				      cred_array->ptr[i].cred.ptr,
				      cred_array->ptr[i].cred.len));
			cred->len = cred_array->ptr[i].cred.len;

			/*retrieve PK*/
			if (static_dh_auth) {
				pk->len = 0;
				if (cred_array->ptr[i].g.len == 65) {
					/*decompressed P256 DH pk*/
					g->ptr[0] = 0x2;
					TRY(_memcpy_s(
						&g->ptr[1], g->len - 1,
						&cred_array->ptr[i].g.ptr[1],
						32));
					g->len = 33;

				} else {
					TRY(_memcpy_s(g->ptr, g->len,
						      cred_array->ptr[i].g.ptr,
						      cred_array->ptr[i].g.len));
					g->len = cred_array->ptr[i].g.len;
				}

			} else {
				g->len = 0;
				TRY(_memcpy_s(pk->ptr, pk->len,
					      cred_array->ptr[i].pk.ptr,
					      cred_array->ptr[i].pk.len));
				pk->len = cred_array->ptr[i].pk.len;
			}
			return ok;
		}
	}

	return credential_not_found;
}

enum err retrieve_cred(bool static_dh_auth, struct cred_array *cred_array,
		       struct byte_array *id_cred, struct byte_array *cred,
		       struct byte_array *pk, struct byte_array *g)
{
	/* Only pre-established credentials are supported: ID_CRED_x is
	 * matched byte for byte against the local trust anchors. */
	return get_local_cred(static_dh_auth, cred_array, id_cred, cred, pk,
			      g);
}
