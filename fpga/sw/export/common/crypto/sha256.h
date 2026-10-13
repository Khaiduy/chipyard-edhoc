/* sha256.h - SHA-256 (FIPS 180-4), incremental. */
#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define SHA256_LEN   32
#define SHA256_BLOCK 64

struct sha256_ctx {
	uint32_t h[8];
	uint64_t len;                 /* bytes absorbed so far */
	uint8_t buf[SHA256_BLOCK];
};

void sha256_init(struct sha256_ctx *c);
void sha256_update(struct sha256_ctx *c, const uint8_t *in, uint32_t len);
void sha256_final(struct sha256_ctx *c, uint8_t out[SHA256_LEN]);

/* One-shot SHA-256(in). */
void sha256_hash(const uint8_t *in, uint32_t len, uint8_t out[SHA256_LEN]);

#endif /* SHA256_H */
