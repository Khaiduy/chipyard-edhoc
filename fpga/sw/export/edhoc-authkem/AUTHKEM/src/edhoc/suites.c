/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/suites.h"

#include "common/oscore_edhoc_error.h"

enum err get_suite(enum suite_label label, struct suite *suite)
{
	/* Method 5 (AuthKEM) builds implement exactly one cipher suite:
	 * draft-ietf-lake-pqsuites-01 TBD2 (the suite draft-ietf-lake-authkem-
	 * edhoc-01 refers to) or, built with SUITE=TBD1/TBD3, TBD1/TBD3. ML-DSA only
	 * names the signature slot (used to verify X.509 credentials, which
	 * this build does not support); Method 5 authenticates with MAC_2/MAC_3
	 * over KEM shared secrets.
	 *
	 * Any other label is refused rather than agreed to and then performed
	 * with algorithms that are not linked into this image. */
#if AUTHKEM_PQ_SUITE == 1
	/* TBD1 (build with SUITE=TBD1): AES-CCM-16-128-128, SHAKE256, 16,
	 * ML-KEM-512, ML-DSA-44, AES-CCM-16-64-128, SHA-256. */
	if (label != SUITE_PQ_TBD1)
		return unsupported_cipher_suite;
	suite->suite_label = SUITE_PQ_TBD1;
	suite->edhoc_aead = AES_CCM_16_128_128;
	suite->edhoc_hash = SHAKE_256;
	suite->edhoc_mac_len_static_dh = MAC16;
	suite->edhoc_ecdh = ML_KEM_512;
	suite->edhoc_sign = ML_DSA_44;
	suite->app_aead = AES_CCM_16_64_128;
	suite->app_hash = SHA_256;
#elif AUTHKEM_PQ_SUITE == 3
	/* TBD3 (build with SUITE=TBD3): A256GCM, SHA-384, 16, ML-KEM-1024,
	 * ML-DSA-87 (-50), A256GCM, SHA-384 -- draft-ietf-lake-pqsuites-01
	 * Table 3. Method 5 never signs; the slot is carried for completeness. */
	if (label != SUITE_PQ_TBD3)
		return unsupported_cipher_suite;
	suite->suite_label = SUITE_PQ_TBD3;
	suite->edhoc_aead = A256GCM;
	suite->edhoc_hash = SHA_384;
	suite->edhoc_mac_len_static_dh = MAC16;
	suite->edhoc_ecdh = ML_KEM_1024;
	suite->edhoc_sign = ML_DSA_87;
	suite->app_aead = A256GCM;
	suite->app_hash = SHA_384;
#else
	if (label != SUITE_PQ_TBD2)
		return unsupported_cipher_suite;
	suite->suite_label = SUITE_PQ_TBD2;
	suite->edhoc_aead = A256GCM;
	suite->edhoc_hash = SHAKE_256;
	suite->edhoc_mac_len_static_dh = MAC16;
	suite->edhoc_ecdh = ML_KEM_512;
	suite->edhoc_sign = ML_DSA_44;
	suite->app_aead = A256GCM;
	suite->app_hash = SHA_256;
#endif
	return ok;
}

uint32_t get_hash_len(enum hash_alg alg)
{
	switch (alg) {
	case SHA_256:
		return 32;
		break;
	case SHAKE_256:
		return 64;   /* COSE -45: SHAKE256 with 512-bit output */
		break;
	case SHA_384:
		return 48;
		break;
	}
	return 0;
}

uint32_t get_aead_mac_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
		return 16;
		break;
	case AES_CCM_16_64_128:
		return 8;
		break;
	case A256GCM:
		return 16;
		break;
	}
	return 0;
}

uint32_t get_aead_key_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
	case AES_CCM_16_64_128:
		return 16;
		break;
	case A256GCM:
		return 32;
		break;
	}
	return 0;
}

uint32_t get_aead_iv_len(enum aead_alg alg)
{
	switch (alg) {
	case AES_CCM_16_128_128:
	case AES_CCM_16_64_128:
		return 13;
		break;
	case A256GCM:
		return 12;
		break;
	}
	return 0;
}
