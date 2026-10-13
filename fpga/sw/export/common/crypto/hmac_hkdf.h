/*
 * hmac_hkdf.h - HMAC (RFC 2104) and HKDF (RFC 5869) over any hash described
 * by a struct hash_desc. One implementation serves SHA-256 and SHA-384.
 */
#ifndef HMAC_HKDF_H
#define HMAC_HKDF_H

#include <stdint.h>
#include "sha256.h"
#include "sha384.h"

#define HASH_MAX_LEN   SHA384_LEN
#define HASH_MAX_BLOCK SHA384_BLOCK

struct hash_desc {
	uint32_t len;     /* digest bytes */
	uint32_t block;   /* block bytes */
	void (*init)(void *ctx);
	void (*update)(void *ctx, const uint8_t *in, uint32_t len);
	void (*final)(void *ctx, uint8_t *out);
};

extern const struct hash_desc hash_sha256, hash_sha384;

union hash_ctx {
	struct sha256_ctx sha256;
	struct sha384_ctx sha384;
};

struct hmac_ctx {
	const struct hash_desc *h;
	union hash_ctx ctx;
	uint8_t key[HASH_MAX_BLOCK];  /* zero-padded key, kept for the outer hash */
};

void hmac_init(struct hmac_ctx *m, const struct hash_desc *h,
	       const uint8_t *key, uint32_t key_len);
void hmac_update(struct hmac_ctx *m, const uint8_t *in, uint32_t len);
void hmac_final(struct hmac_ctx *m, uint8_t *out);

/* PRK = HMAC(salt, ikm); an empty salt is HashLen zeros (RFC 5869 2.2),
 * which HMAC's zero padding makes the same as an empty key. */
void hkdf_extract_h(const struct hash_desc *h, const uint8_t *salt,
		    uint32_t salt_len, const uint8_t *ikm, uint32_t ikm_len,
		    uint8_t *prk);
/* T(i) = HMAC(PRK, T(i-1) || info || i); out_len <= 255 * h->len. */
int hkdf_expand_h(const struct hash_desc *h, const uint8_t *prk,
		  uint32_t prk_len, const uint8_t *info, uint32_t info_len,
		  uint8_t *out, uint32_t out_len);

#endif /* HMAC_HKDF_H */
