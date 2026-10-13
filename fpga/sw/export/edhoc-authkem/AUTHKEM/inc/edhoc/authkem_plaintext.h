/*
 * authkem_plaintext.h — plaintexts and MAC contexts for authkem-00.
 * draft-ietf-lake-authkem-edhoc-00 sections 4.2 - 4.5.
 */
#ifndef AUTHKEM_PLAINTEXT_H
#define AUTHKEM_PLAINTEXT_H

#include <stdint.h>

#include "common/byte_array.h"
#include "edhoc/suites.h"
#include "common/oscore_edhoc_error.h"

/* PLAINTEXT_2 = (C_R, ID_CRED_R, ?EAD_2)                   [section 4.2.2]
 * No MAC: the Responder cannot authenticate yet at message 2, because it has
 * not received ct_R. MAC_2 travels in PLAINTEXT_4. */
enum err authkem_plaintext2_encode(const struct byte_array *c_r,
				   const struct byte_array *id_cred_r,
				   const struct byte_array *ead,
				   struct byte_array *out);

enum err authkem_plaintext2_decode(const struct byte_array *in,
				   struct byte_array *c_r,
				   struct byte_array *id_cred_r,
				   struct byte_array *ead);

/* PLAINTEXT_3 = (C_I, ID_CRED_I, ?EAD_3)                   [section 4.3.2] */
enum err authkem_plaintext3_encode(const struct byte_array *c_i,
				   const struct byte_array *id_cred_i,
				   const struct byte_array *ead,
				   struct byte_array *out);

enum err authkem_plaintext3_decode(const struct byte_array *in,
				   struct byte_array *c_i,
				   struct byte_array *id_cred_i,
				   struct byte_array *ead);

/* PLAINTEXT_4 = (MAC_2, ?EAD_4)   [4.4.2], PLAINTEXT_5 = (MAC_3, ?EAD_5) [4.5.2]
 * Same shape, so one encoder/decoder pair serves both. */
enum err authkem_plaintext45_encode(const struct byte_array *mac,
				    const struct byte_array *ead,
				    struct byte_array *out);

enum err authkem_plaintext45_decode(const struct byte_array *in,
				    struct byte_array *mac,
				    struct byte_array *ead);

/* MAC_2 = EDHOC_KDF(PRK_3e2m, 2, context_2, mac_length_2)   [section 5.4.2]
 * MAC_3 = EDHOC_KDF(PRK_4e3m, 6, context_3, mac_length_3)   [section 5.5.2]
 *
 *   context_2 = << C_R, ID_CRED_R, TH_4, CRED_R, ?EAD_4 >>
 *   context_3 = << C_I, ID_CRED_I, TH_5, CRED_I, ?EAD_5 >>
 *
 * c_x, id_cred_x and cred_x are already-encoded CBOR, th is wrapped as a
 * bstr, ead is a CBOR sequence. The context is streamed into the KDF, never
 * assembled; mac->len selects the MAC length. */
enum err authkem_mac(enum hash_alg alg, const struct byte_array *prk,
		     uint32_t label, const struct byte_array *c_x,
		     const struct byte_array *id_cred_x,
		     const struct byte_array *th,
		     const struct byte_array *cred_x,
		     const struct byte_array *ead, struct byte_array *mac);

#endif
