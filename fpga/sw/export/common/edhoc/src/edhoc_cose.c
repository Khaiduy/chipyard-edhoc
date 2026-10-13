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

#include "edhoc/edhoc_cose.h"

#include "common/oscore_edhoc_error.h"
#include "cbor.h"


enum err cose_enc_structure_encode(const struct byte_array *context,
				   const struct byte_array *protected,
				   const struct byte_array *external_aad,
				   struct byte_array *out)
{
	/* [ context : tstr, protected : bstr, external_aad : bstr ] */
	struct cbor_w w;

	if (protected->ptr == NULL && protected->len != 0)
		return wrong_parameter;
	cbor_w_init(&w, out->ptr, out->len);
	cbor_put_head(&w, CBOR_ARRAY, 3);
	cbor_put_tstr(&w, context->ptr, context->len);
	cbor_put_bstr(&w, protected->ptr, protected->len);
	cbor_put_bstr(&w, external_aad->ptr, external_aad->len);
	if (w.err)
		return cbor_encoding_error;
	out->len = w.len;
	return ok;
}

enum err cose_sig_structure_encode(const struct byte_array *context,
				   const struct byte_array *protected,
				   const struct byte_array *external_aad,
				   const struct byte_array *payload,
				   struct byte_array *out)
{
	/* [ context : tstr, protected : bstr, external_aad : bstr,
	 *   payload : bstr ] */
	struct cbor_w w;

	cbor_w_init(&w, out->ptr, out->len);
	cbor_put_head(&w, CBOR_ARRAY, 4);
	cbor_put_tstr(&w, context->ptr, context->len);
	cbor_put_bstr(&w, protected->ptr, protected->len);
	cbor_put_bstr(&w, external_aad->ptr, external_aad->len);
	cbor_put_bstr(&w, payload->ptr, payload->len);
	if (w.err)
		return cbor_encoding_error;
	out->len = w.len;
	return ok;
}
