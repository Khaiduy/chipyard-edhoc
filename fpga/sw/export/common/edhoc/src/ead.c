#include <stdint.h>

#include "cbor.h"
#include "edhoc/ead.h"

enum err ead_validate(const struct byte_array *ead)
{
	/* EAD = 1* ( ead_label : int, ? ead_value : bstr ). No EAD item is
	 * implemented here, so every critical one (negative label) is one we
	 * do not recognize: RFC 9528 3.8 requires an error and abort. Padding
	 * (label 0) and non-critical items are ignored. */
	struct cbor_r r;
	int64_t label;
	const uint8_t *v;
	uint32_t n;

	if (!ead || ead->len == 0)
		return ok;
	cbor_r_init(&r, ead->ptr, ead->len);
	while (r.p < r.end) {
		if (cbor_get_int(&r, &label))
			return cbor_decoding_error;
		if (label < 0)
			return ead_critical_unsupported;
		if (cbor_peek(&r) == CBOR_BSTR && cbor_get_bstr(&r, &v, &n))
			return cbor_decoding_error;
	}
	return ok;
}
