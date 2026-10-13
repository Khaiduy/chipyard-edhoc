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

#include "edhoc/retrieve_cred.h"

#include "common/oscore_edhoc_error.h"

/* Only kid-referenced, pre-provisioned credentials are supported: the peer's
 * static KEM key is provisioned out of band, so ID_CRED always carries a kid
 * and is matched byte for byte against the local entries. */
enum err authkem_cred_lookup(const struct cred_array *cred_array,
			     const struct byte_array *id_cred,
			     struct byte_array *cred, struct byte_array *pk)
{
	for (uint32_t i = 0; i < cred_array->len; i++) {
		const struct other_party_cred *e = &cred_array->ptr[i];
		if (e->id_cred.len == id_cred->len &&
		    !memcmp(e->id_cred.ptr, id_cred->ptr, id_cred->len)) {
			*cred = e->cred;
			*pk = e->g;
			return ok;
		}
	}
	return credential_not_found;
}
