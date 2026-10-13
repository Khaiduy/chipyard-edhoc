/*
 * authkem_messages.h — CBOR encode/decode for the five authkem-01 messages.
 * draft-ietf-lake-authkem-edhoc-01 section 5.
 */
#ifndef AUTHKEM_MESSAGES_H
#define AUTHKEM_MESSAGES_H

#include <stdint.h>

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/* message_1 = (METHOD : int, SUITES_I : suites, pk_eph : bstr,
 *              C_I : bstr, ? EAD_1)                        [section 5.1.1]
 *
 * The decoder returns pk_eph as a view into msg.
 *
 * SUITES_I is a single int or an array of two or more ints (RFC 9528).
 */
enum err authkem_msg1_encode(int32_t method, const struct byte_array *suites,
			     const struct byte_array *pk_eph,
			     const struct byte_array *c_i,
			     const struct byte_array *ead,
			     struct byte_array *out);

enum err authkem_msg1_decode(const struct byte_array *msg, int32_t *method,
			     struct byte_array *suites, struct byte_array *pk_eph,
			     struct byte_array *c_i, struct byte_array *ead);

/* message_2     = (ct_eph_CIPHERTEXT_2 : bstr)          [section 5.2.1]
 * message_3     = (ct_R_CIPHERTEXT_3 : bstr)            [section 5.3.1]
 * message_4_KEM = (ct_I_CIPHERTEXT_4 : bstr)            [section 5.4.1]
 * message_5_KEM = (CIPHERTEXT_5 : bstr)                 [section 5.5.1]
 *
 * One byte string holding a KEM ciphertext of fixed length (none in
 * message_5) followed by the message's ciphertext.
 *
 * authkem_msg_kem_open() writes the byte-string header into out and returns
 * ct and ciphertext as views into out, for the caller to fill in place: the
 * KEM writes its ciphertext straight into the message and the AEAD encrypts
 * straight into it, so neither is staged in a separate buffer.
 * authkem_msg_kem_split() returns the two halves as views into msg. */
enum err authkem_msg_kem_open(struct byte_array *out, uint32_t ct_len,
			      uint32_t ciphertext_len, struct byte_array *ct,
			      struct byte_array *ciphertext);
enum err authkem_msg_kem_split(const struct byte_array *msg, uint32_t ct_len,
			       struct byte_array *ct,
			       struct byte_array *ciphertext);

#endif
