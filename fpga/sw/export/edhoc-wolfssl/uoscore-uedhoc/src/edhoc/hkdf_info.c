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

#include "edhoc/suites.h"
#include "edhoc/hkdf_info.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "cbor.h"


enum err create_hkdf_info(uint32_t label, struct byte_array *context,
			  uint32_t okm_len, struct byte_array *out)
{
	/* info = ( label : uint, context : bstr, length : uint ), a CBOR
	 * sequence (RFC 9528 Section 4.1.2). */
	struct cbor_w w;

	if (context->ptr == NULL && context->len != 0)
		return wrong_parameter;
	cbor_w_init(&w, out->ptr, out->len);
	cbor_put_head(&w, CBOR_UINT, label);
	cbor_put_bstr(&w, context->ptr, context->len);
	cbor_put_head(&w, CBOR_UINT, okm_len);
	if (w.err)
		return cbor_encoding_error;
	out->len = w.len;
	return ok;
}
