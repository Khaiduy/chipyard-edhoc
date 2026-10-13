/* sha384.h - SHA-384 (FIPS 180-4), incremental. */
#ifndef SHA384_H
#define SHA384_H

#include <stdint.h>

#define SHA384_LEN   48
#define SHA384_BLOCK 128

struct sha384_ctx {
	uint64_t h[8];
	uint64_t len;                 /* bytes absorbed so far */
	uint8_t buf[SHA384_BLOCK];
};

void sha384_init(struct sha384_ctx *c);
void sha384_update(struct sha384_ctx *c, const uint8_t *in, uint32_t len);
void sha384_final(struct sha384_ctx *c, uint8_t out[SHA384_LEN]);

/* One-shot SHA-384(in). */
void sha384_hash(const uint8_t *in, uint32_t len, uint8_t out[SHA384_LEN]);

#endif /* SHA384_H */
