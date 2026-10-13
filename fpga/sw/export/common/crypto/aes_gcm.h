/*
 * aes_gcm.h - AES-GCM (FIPS 197, NIST SP 800-38D) with a 96-bit IV and a
 * 128-bit tag, 128- or 256-bit key: COSE algorithms 1 (A128GCM, RFC 9528
 * suite 6) and 3 (A256GCM, suite 24 and pqsuites TBD2/TBD3).
 */
#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>

#define AES_GCM_IV_LEN  12
#define AES_GCM_TAG_LEN 16

/* out may equal in. Writes len bytes of ciphertext and the 16-byte tag. */
/* key_len is 16 or 32. */
void aes_gcm_encrypt(const uint8_t *key, uint32_t key_len, const uint8_t iv[12],
			const uint8_t *aad, uint32_t aad_len,
			const uint8_t *in, uint32_t len,
			uint8_t *out, uint8_t tag[16]);

/* Verifies the tag over aad and the ciphertext first; decrypts only if it
 * matches. Returns 0 on success, -1 on a tag mismatch (out untouched). */
int aes_gcm_decrypt(const uint8_t *key, uint32_t key_len, const uint8_t iv[12],
		       const uint8_t *aad, uint32_t aad_len,
		       const uint8_t *in, uint32_t len,
		       const uint8_t tag[16], uint8_t *out);

#endif /* AES_GCM_H */
