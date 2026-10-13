/*
 * aes.h - the AES block cipher (FIPS 197), encryption only, 128- or 256-bit
 * keys. Shared by aes_gcm.c (A128GCM / A256GCM) and aes_ccm.c
 * (AES-CCM-16-128-128 / AES-CCM-16-64-128, pqsuites TBD1).
 */
#ifndef AES_H
#define AES_H

#include <stdint.h>

struct aes_key {
	uint32_t w[60];   /* round keys, 4 * (Nr + 1) words, Nr = 14 at most */
	uint32_t nr;      /* 10 (AES-128) or 14 (AES-256) */
};

/* key_len is 16 or 32. */
void aes_setkey(struct aes_key *k, const uint8_t *key, uint32_t key_len);
void aes_encrypt_block(const struct aes_key *k, const uint8_t in[16],
		       uint8_t out[16]);

#endif /* AES_H */
