/*
 * edhoc_error_msg.c - RFC 9528 §6 wire-format error messages.
 */
#include "edhoc/edhoc_error_msg.h"
#include <string.h>

#include "cbor.h"

/* Public API ------------------------------------------------------------- */

int edhoc_map_to_wire_err_code(enum err internal)
{
	switch (internal) {
	case unsupported_cipher_suite:
		return EDHOC_ERR_CODE_WRONG_CIPHER_SUITE;
	case credential_not_found:
	case no_such_ca:
		return EDHOC_ERR_CODE_UNKNOWN_CRED;
	default:
		return EDHOC_ERR_CODE_UNSPECIFIED;
	}
}

enum err edhoc_build_error_message(uint8_t *out, uint32_t out_max,
				   int err_code,
				   const char *diag, uint32_t diag_len,
				   const uint8_t *info_cbor, uint32_t info_cbor_len,
				   uint32_t *out_len)
{
	static const uint8_t cbor_true = 0xF5;
	struct cbor_w w;

	if (!out || !out_len) return wrong_parameter;

	cbor_w_init(&w, out, out_max);
	cbor_put_int(&w, err_code);
	switch (err_code) {
	case EDHOC_ERR_CODE_UNSPECIFIED:
		if (!diag) diag = "EDHOC error";
		if (diag_len == 0) diag_len = (uint32_t)strlen(diag);
		cbor_put_tstr(&w, (const uint8_t *)diag, diag_len);
		break;
	case EDHOC_ERR_CODE_WRONG_CIPHER_SUITE:
		if (!info_cbor || info_cbor_len == 0) return wrong_parameter;
		cbor_put_raw(&w, info_cbor, info_cbor_len);
		break;
	case EDHOC_ERR_CODE_UNKNOWN_CRED:
		cbor_put_raw(&w, &cbor_true, 1);
		break;
	default:
		return wrong_parameter;
	}
	if (w.err) return buffer_to_small;

	*out_len = w.len;
	return ok;
}

bool edhoc_is_error_message(const uint8_t *buf, uint32_t len)
{
	if (len < 1) return false;
	uint8_t mt = buf[0] >> 5;
	/* CBOR major type 0 (uint) or 1 (negint) at the start of the
	 * sequence => error message. msg_2/3/4 start with bstr (mt=2). */
	return (mt == 0 || mt == 1);
}
