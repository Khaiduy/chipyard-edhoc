/*
 * aes_ccm.h - AES-128-CCM (NIST SP 800-38C, RFC 3610) with a 13-byte nonce
 * (L = 2): COSE algorithms 30 (AES-CCM-16-128-128, 16-byte tag) and 10
 * (AES-CCM-16-64-128, 8-byte tag), the EDHOC and application AEADs of the
 * draft-ietf-lake-pqsuites cipher suite TBD1.
 */
#ifndef AES_CCM_H
#define AES_CCM_H

#include <stdint.h>

#define AES_CCM_KEY_LEN   16
#define AES_CCM_NONCE_LEN 13

/* tag_len is 8 or 16; aad_len < 0xff00; len < 65536. out may equal in. */
void aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[13],
		     const uint8_t *aad, uint32_t aad_len,
		     const uint8_t *in, uint32_t len,
		     uint8_t *out, uint8_t *tag, uint32_t tag_len);

/* Returns 0 on success, -1 on a tag mismatch; on mismatch out is zeroed. */
int aes_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13],
		    const uint8_t *aad, uint32_t aad_len,
		    const uint8_t *in, uint32_t len,
		    const uint8_t *tag, uint32_t tag_len, uint8_t *out);

#endif /* AES_CCM_H */
