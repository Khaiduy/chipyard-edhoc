/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef RETRIEVE_CRED_H
#define RETRIEVE_CRED_H

#include <stdbool.h>
#include <stdint.h>

#include "edhoc.h"

#include "common/oscore_edhoc_error.h"

/**
 * @brief	Method 5 (AuthKEM) credential resolution: finds the entry whose
 *		ID_CRED equals id_cred and returns its CRED and static KEM
 *		public key (the entry's g) as views of the entry -- no copy.
 * @retval	ok, or credential_not_found.
 */
enum err authkem_cred_lookup(const struct cred_array *cred_array,
			     const struct byte_array *id_cred,
			     struct byte_array *cred, struct byte_array *pk);

#endif
