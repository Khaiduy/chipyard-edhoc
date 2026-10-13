/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>

#include "edhoc.h"

#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"
#include "edhoc/suites.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"

enum err prk_out2exporter(enum hash_alg app_hash_alg,
			  struct byte_array *prk_out,
			  struct byte_array *prk_exporter)
{
	return edhoc_kdf(app_hash_alg, prk_out, PRK_exporter, &NULL_ARRAY,
			 prk_exporter);
}

enum err edhoc_exporter(enum hash_alg app_hash_alg, uint32_t label,
			struct byte_array *prk_exporter, struct byte_array *out)
{
	return edhoc_kdf(app_hash_alg, prk_exporter, label, &NULL_ARRAY, out);
}
