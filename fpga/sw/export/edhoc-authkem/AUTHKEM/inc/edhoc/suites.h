/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef SUITES_H
#define SUITES_H

#include <stdint.h>

#include "common/oscore_edhoc_error.h"

/*see https://www.iana.org/assignments/cose/cose.xhtml#algorithms for algorithm number reference*/

#ifndef AUTHKEM_SUITE_TBD2
#define AUTHKEM_SUITE_TBD2 (-24)
#endif
#ifndef AUTHKEM_SUITE_TBD3
#define AUTHKEM_SUITE_TBD3 (-23)
#endif
#ifndef AUTHKEM_SUITE_TBD1
#define AUTHKEM_SUITE_TBD1 (-22)
#endif

/* draft-ietf-lake-pqsuites-01 suites, one per image (SUITE=TBD1/2/3).
 * The values are not assigned yet; until IANA does, they sit in the RFC 9528
 * private-use range (-24..-21). Change them once the registry has them. */
enum suite_label {
	/* AES-CCM-16-128-128, SHAKE256, 16, ML-KEM-512, ML-DSA-44,
	 * AES-CCM-16-64-128, SHA-256 */
	SUITE_PQ_TBD1 = AUTHKEM_SUITE_TBD1,
	/* A256GCM, SHAKE256, 16, ML-KEM-512, ML-DSA-44, A256GCM, SHA-256 */
	SUITE_PQ_TBD2 = AUTHKEM_SUITE_TBD2,
	/* A256GCM, SHA-384, 16, ML-KEM-1024, ML-DSA-87, A256GCM, SHA-384 */
	SUITE_PQ_TBD3 = AUTHKEM_SUITE_TBD3,
};

/* The suite this image implements, as the signed byte carried in
 * SUITES_I / SUITES_R. */
#if AUTHKEM_PQ_SUITE == 1
#define AUTHKEM_SUITE_BYTE ((uint8_t)(int8_t)SUITE_PQ_TBD1)
#elif AUTHKEM_PQ_SUITE == 3
#define AUTHKEM_SUITE_BYTE ((uint8_t)(int8_t)SUITE_PQ_TBD3)
#else
#define AUTHKEM_SUITE_BYTE ((uint8_t)(int8_t)SUITE_PQ_TBD2)
#endif

enum aead_alg {
	AES_CCM_16_64_128 = 10,
	AES_CCM_16_128_128 = 30,
	A256GCM = 3,
};

enum hash_alg { SHA_256 = -16, SHA_384 = -43, SHAKE_256 = -45 };

/* FIPS 203 ML-KEM. Internal identifiers only: a KEM never appears on the
 * wire (a suite travels as its integer label), and the COSE values are still
 * TBD in draft-ietf-jose-pqc-kem. The implementation behind them is FIPS 203,
 * including the section 7.2 modulus check and the section 7.3 secret-key hash
 * check. */
enum ecdh_alg {
	ML_KEM_512 = -48,
	ML_KEM_1024 = -50,
};

/* The suites' signature slot. Method 5 never signs. */
enum sign_alg {
	ML_DSA_44 = -48,
	ML_DSA_87 = -50,
};

enum mac_len {
	MAC8 = 8,
	MAC16 = 16,
};

struct suite {
	enum suite_label suite_label;
	enum aead_alg edhoc_aead;
	enum hash_alg edhoc_hash;
	enum mac_len edhoc_mac_len_static_dh;
	enum ecdh_alg edhoc_ecdh;
	enum sign_alg edhoc_sign;
	enum aead_alg app_aead;
	enum hash_alg app_hash;
};

/**
 * @brief   			Retrieves the algorithms corrsponding to a 
 * 				given suite label.
 * 
 * @param label 		The label of the suite.
 * @param suite 		The algorithms corrsponding to label.
 * @retval			Ok or error.
 */
enum err get_suite(enum suite_label label, struct suite *suite);

/**
 * @brief 			Gets the length of the hash.
 * 
 * @param alg 			The used hash algorithm.
 * @retval			The length.
 */
uint32_t get_hash_len(enum hash_alg alg);

/**
 * @brief 			Gets the length of the MAC.
 * 
 * @param alg 			The used AEAD algorithm.
 * @retval 			The length.
 */
uint32_t get_aead_mac_len(enum aead_alg alg);

/**
 * @brief 			Gets the length of KEY.
 * 
 * @param alg 			The used AEAD algorithm.
 * @retval 			The length.
 */
uint32_t get_aead_key_len(enum aead_alg alg);

/**
 * @brief 			Gets the length of IV.
 * 
 * @param alg 			The used AEAD algorithm.
 * @retval 			The length.
 */
uint32_t get_aead_iv_len(enum aead_alg alg);

#endif
