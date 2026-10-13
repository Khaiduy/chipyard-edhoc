/*
 * Copyright (c) 2023 Eriptic Technologies
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

/*
 * Compile-time buffer sizes for EDHOC Method 5 (draft-ietf-lake-authkem-
 * edhoc-01) with one draft-ietf-lake-pqsuites-01 suite per image:
 *   TBD1, TBD2: ML-KEM-512,  SHAKE256 (64-byte hash)
 *   TBD3:       ML-KEM-1024, SHA-384  (48-byte hash)
 * EAD_SIZE, C_I_SIZE, C_R_SIZE, SUITES_I_SIZE and ID_CRED_{I,R}_SIZE come
 * from the build (mk/config.mk).
 */

#ifndef BUFFER_SIZES_H
#define BUFFER_SIZES_H

#include <stdint.h>

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define BSTR_ENCODING_OVERHEAD(x)                                              \
	(((x) <= 5) ? 1 : ((x) <= UINT8_MAX) ? 2 : ((x) <= UINT16_MAX) ? 3 : 5)
#define AS_BSTR_SIZE(x) (BSTR_ENCODING_OVERHEAD(x) + (x))

/* FIPS 203 key, ciphertext and shared-secret sizes. */
#if MLK_CONFIG_PARAMETER_SET == 1024
#define KEM_SK_SIZE 3168
#define KEM_PK_SIZE 1568
#define KEM_CT_SIZE 1568
#else
#define KEM_SK_SIZE 1632
#define KEM_PK_SIZE 800
#define KEM_CT_SIZE 768
#endif
#define KEM_SECRET_SIZE 32

/* EDHOC hash: TH, PRK and PRK_out lengths. */
#if AUTHKEM_PQ_SUITE == 3
#define HASH_SIZE 48
#else
#define HASH_SIZE 64
#endif
#define PRK_SIZE HASH_SIZE

#define AEAD_IV_SIZE 13 /* AES-CCM nonce; the GCM IV is 12 */
#define MAC_SIZE 16
/* COSE Enc_structure ["Encrypt0", h'', TH]: array head 1 + "Encrypt0" 9 +
 * h'' 1 + bstr head 2 + the transcript hash. */
#define AAD_SIZE (13 + HASH_SIZE)

/* PLAINTEXT_2 = (C_R, ID_CRED_R, ?EAD_2)   [section 5.2.2]
 * PLAINTEXT_3 = (C_I, ID_CRED_I, ?EAD_3)   [section 5.3.2]
 * PLAINTEXT_4 = (MAC_2, ?EAD_4), PLAINTEXT_5 = (MAC_3, ?EAD_5) */
#define AUTHKEM_PLAINTEXT2_SIZE                                                \
	(AS_BSTR_SIZE(C_R_SIZE) + ID_CRED_R_SIZE + EAD_SIZE + 8)
#define AUTHKEM_PLAINTEXT3_SIZE                                                \
	(AS_BSTR_SIZE(C_I_SIZE) + ID_CRED_I_SIZE + EAD_SIZE + 8)
#define AUTHKEM_PLAINTEXT4_SIZE (AS_BSTR_SIZE(MAC_SIZE) + EAD_SIZE + 8)
#define AUTHKEM_PLAINTEXT5_SIZE (AS_BSTR_SIZE(MAC_SIZE) + EAD_SIZE + 8)

/* Message wire sizes. CIPHERTEXT_2 is a keystream XOR (no tag); 3-5 carry
 * the AEAD tag.
 * msg1 = (METHOD, SUITES_I, pk_eph, C_I, ?EAD_1)
 * msg2 = bstr(ct_eph || CIPHERTEXT_2)
 * msg3 = bstr(ct_R || CIPHERTEXT_3), msg4 = bstr(ct_I || CIPHERTEXT_4)
 * msg5 = bstr(CIPHERTEXT_5) */
#define AUTHKEM_MSG1_SIZE                                                      \
	(2 + SUITES_I_SIZE + AS_BSTR_SIZE(KEM_PK_SIZE) +                       \
	 AS_BSTR_SIZE(C_I_SIZE) + EAD_SIZE + 8)
#define AUTHKEM_MSG2_SIZE AS_BSTR_SIZE(KEM_CT_SIZE + AUTHKEM_PLAINTEXT2_SIZE)
#define AUTHKEM_MSG34_SIZE                                                     \
	AS_BSTR_SIZE(KEM_CT_SIZE +                                             \
		     MAX(AUTHKEM_PLAINTEXT3_SIZE, AUTHKEM_PLAINTEXT4_SIZE) +   \
		     MAC_SIZE)
#define MSG_MAX_SIZE                                                           \
	MAX(AUTHKEM_MSG1_SIZE, MAX(AUTHKEM_MSG2_SIZE, AUTHKEM_MSG34_SIZE))

#endif /* BUFFER_SIZES_H */
