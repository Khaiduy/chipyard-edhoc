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

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#include "edhoc/suites.h"

/*Indicates what kind of operation a symmetric cipher will execute*/
enum aes_operation {
	ENCRYPT,
	DECRYPT,
};

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
 * @brief			Derives ECDH shared secret.
 * 
 * @param alg			The ECDH algorithm to be used.
 * @param[in] sk 		Private key.
 * @param[in] pk 		Public key.
 * @param[out] shared_secret 	The result.
 * @return 			Ok or error code.
 */
enum err shared_secret_derive(enum ecdh_alg alg, const struct byte_array *sk,
			      const struct byte_array *pk,
			      uint8_t *shared_secret);

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
 * @brief			HKDF expand function, see rfc5869.
 * 
 * @param alg			Hash algorithm to be used.
 * @param[in] prk 		Input pseudo random key.
 * @param[in] info 		Info input parameter.
 * @param[out] out		The result.
 * @return 			Ok or error code.
 */
enum err hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
		     const struct byte_array *info, struct byte_array *out);

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

/**
 * @brief			Verifies an asymmetric signature.
 * @param alg			Signature algorithm to be used.
 * @param[in] sk 		Secret key.
 * @param[in] pk 		Public key.
 * @param[in] msg 		The message to be signed.
 * @param[out] out 		Signature.
 * @return 			Ok or error code.
 */
enum err sign(enum sign_alg alg, const struct byte_array *sk,
	      const struct byte_array *pk, const struct byte_array *msg,
	      uint8_t *out);

/**
 * @brief			Verifies an asymmetric signature.
 * 
 * @param alg 			Signature algorithm to be used.
 * @param[in] pk 		Public key.
 * @param[in] msg 		The signed message.
 * @param[in] sgn 		Signature.
 * @param[out] result 		True if the verification is successfully.
 * @return 			Ok or error code.
 */
enum err verify(enum sign_alg alg, const struct byte_array *pk,
		struct const_byte_array *msg, struct const_byte_array *sgn,
		bool *result);

/**
 * @brief			Generates an Ed25519 or ECDSA signing key pair
 *				from a 32-byte seed.
 *
 * @param alg			Signature algorithm (EdDSA).
 * @param[in] seed		32-byte seed (consumed/wiped by call for EdDSA).
 * @param[out] sk		Secret key output buffer (64 bytes for EdDSA).
 * @param[out] pk		Public key output buffer (32 bytes for EdDSA).
 * @return			Ok or error code.
 */
enum err sign_key_gen(enum sign_alg alg, const uint8_t *seed,
		      struct byte_array *sk, struct byte_array *pk);

#endif
