/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H

#include <stdbool.h>

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#include "edhoc/suites.h"

/* Every function declared here is the backend contract: implement them all and
 * the EDHOC library runs on your crypto. Each is WEAK in the default backend
 * (src/common/crypto_wrapper.c), so an application can override any single one
 * -- a hardware ML-KEM or AES core, say -- by defining a strong symbol with
 * the same signature. See the backend notes at the top of crypto_wrapper.c. */
#ifndef WEAK
#define WEAK __attribute__((weak))
#endif

/*Indicates what kind of operation a symmetric cipher will execute*/
enum aes_operation {
	ENCRYPT,
	DECRYPT,
};

/**
 * @brief			Generates an ephemeral KEM key pair.
 *
 * @param alg			The KEM to be used; must be ML_KEM_512.
 * @param[in,out] sk		Seed material in, generated private key out.
 * @param[out] pk		The generated public key.
 * @return			Ok or error code.
 */
enum err WEAK ephemeral_kem_key_gen(enum ecdh_alg alg, struct byte_array *sk,
				    struct byte_array *pk);

/**
 * @brief			KEM encapsulation.
 *
 * @param alg			The KEM to be used.
 * @param[in] pk		Public key to encapsulate to.
 * @param[out] ct		The resulting ciphertext.
 * @param[out] shared_secret	The resulting shared secret.
 * @return			Ok or error code.
 */
enum err WEAK kem_encapsulate(enum ecdh_alg alg, const struct byte_array *pk,
			      struct byte_array *ct,
			      struct byte_array *shared_secret);

/**
 * @brief			KEM decapsulation.
 *
 * @param alg			The KEM to be used.
 * @param[in] ct		The ciphertext.
 * @param[in] sk		The secret key.
 * @param[out] shared_secret	The recovered shared secret.
 * @return			Ok or error code.
 */
enum err WEAK kem_decapsulate(enum ecdh_alg alg, const struct byte_array *ct,
			      const struct byte_array *sk,
			      struct byte_array *shared_secret);

/**
 * @brief			Calculates AEAD encryption decryption.
 * 
 * @param op 			Operation to be executed (ENCRYPT or DECRYPT).
 * @param[in] in		Input message.
 * @param[in] key 		The symmetric key to be used.
 * @param[in] nonce 		The nonce.
 * @param[in] aad 		Additional authenticated data.
 * @param[out] out 		The cipher text.
 * @param[in,out] tag 		The authentication tag.
 * @return 			Ok or error code.
 */
enum err aead(enum aes_operation op, const struct byte_array *in,
	      const struct byte_array *key, struct byte_array *nonce,
	      const struct byte_array *aad, struct byte_array *out,
	      struct byte_array *tag);

/**
 * @brief			HKDF extract function, see rfc5869.
 * 
 * @param alg			Hash algorithm to be used.
 * @param[in] salt		Salt value.
 * @param[in] ikm 		Input keying material.
 * @param[out] out		The result.
 * @return 			Ok or error code.
 */
enum err hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
		      struct byte_array *ikm, uint8_t *out);

/**
 * @brief			Computes a hash.
 * 
 * @param alg 			The hash algorithm to be used.
 * @param[in] in 		The input message.
 * @param[out] out 		The hash.
 * @return 			Ok or error code.
 */
enum err hash(enum hash_alg alg, const struct byte_array *in,
	      struct byte_array *out);

/* One piece of a streamed hash or KDF input. With as_bstr set the piece is
 * absorbed as a CBOR byte string (header, then the bytes). Streaming lets a
 * transcript hash or a KDF info that embeds a credential or a KEM ciphertext
 * be computed without assembling it in a buffer first. */
struct hash_part {
	const uint8_t *ptr;
	uint32_t len;
	bool as_bstr;
};

/**
 * @brief			Hash of the concatenation of n parts.
 */
enum err hash_parts(enum hash_alg alg, const struct hash_part *parts,
		    uint32_t n, struct byte_array *out);

/**
 * @brief			EDHOC_Expand(prk, info, out->len) with info
 *				given as the concatenation of n parts.
 */
enum err hkdf_expand_parts(enum hash_alg alg, const struct byte_array *prk,
			   const struct hash_part *parts, uint32_t n,
			   struct byte_array *out);

#ifdef LIBOQS


#endif


#endif
