/*
 * sha256.c - see sha256.h. One rolled round loop, a 16-word message schedule
 * kept in a ring, and whole blocks compressed straight from the input.
 */
#include <string.h>
#include "sha256.h"
#include "hmac_hkdf.h"

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint32_t IV[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void compress(uint32_t h[8], const uint8_t *blk)
{
	uint32_t w[16], s[8];

	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)blk[4 * i] << 24 | (uint32_t)blk[4 * i + 1] << 16 |
		       (uint32_t)blk[4 * i + 2] << 8 | blk[4 * i + 3];
	memcpy(s, h, sizeof(s));
	for (int t = 0; t < 64; t++) {
		if (t >= 16) {
			uint32_t w15 = w[(t - 15) & 15], w2 = w[(t - 2) & 15];
			w[t & 15] += (ROR(w15, 7) ^ ROR(w15, 18) ^ (w15 >> 3)) +
				     w[(t - 7) & 15] +
				     (ROR(w2, 17) ^ ROR(w2, 19) ^ (w2 >> 10));
		}
		uint32_t e = s[4], a = s[0];
		uint32_t t1 = s[7] + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) +
			      ((e & s[5]) ^ (~e & s[6])) + K[t] + w[t & 15];
		uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) +
			      ((a & s[1]) ^ (a & s[2]) ^ (s[1] & s[2]));
		memmove(s + 1, s, 7 * sizeof(s[0]));
		s[4] += t1;
		s[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++)
		h[i] += s[i];
}

void sha256_init(struct sha256_ctx *c)
{
	memcpy(c->h, IV, sizeof(c->h));
	c->len = 0;
}

void sha256_update(struct sha256_ctx *c, const uint8_t *in, uint32_t len)
{
	uint32_t fill = (uint32_t)(c->len % SHA256_BLOCK);

	if (!len)               /* in may be NULL: memcpy must not see it */
		return;
	c->len += len;
	if (fill) {
		uint32_t n = SHA256_BLOCK - fill;
		if (n > len)
			n = len;
		memcpy(c->buf + fill, in, n);
		in += n;
		len -= n;
		if (fill + n < SHA256_BLOCK)
			return;
		compress(c->h, c->buf);
	}
	for (; len >= SHA256_BLOCK; in += SHA256_BLOCK, len -= SHA256_BLOCK)
		compress(c->h, in);
	memcpy(c->buf, in, len);
}

void sha256_final(struct sha256_ctx *c, uint8_t out[SHA256_LEN])
{
	uint64_t bits = c->len * 8;
	uint32_t fill = (uint32_t)(c->len % SHA256_BLOCK);

	c->buf[fill++] = 0x80;
	if (fill > SHA256_BLOCK - 8) {
		memset(c->buf + fill, 0, SHA256_BLOCK - fill);
		compress(c->h, c->buf);
		fill = 0;
	}
	memset(c->buf + fill, 0, SHA256_BLOCK - 8 - fill);
	for (int i = 0; i < 8; i++)
		c->buf[SHA256_BLOCK - 1 - i] = (uint8_t)(bits >> (8 * i));
	compress(c->h, c->buf);
	for (int i = 0; i < SHA256_LEN; i++)
		out[i] = (uint8_t)(c->h[i / 4] >> (24 - 8 * (i % 4)));
}

void sha256_hash(const uint8_t *in, uint32_t len, uint8_t out[SHA256_LEN])
{
	struct sha256_ctx c;

	sha256_init(&c);
	sha256_update(&c, in, len);
	sha256_final(&c, out);
}

/* Descriptor for hmac_hkdf.c; defined here so only images that use SHA-256
 * link it. */
static void d_init(void *c) { sha256_init(c); }
static void d_update(void *c, const uint8_t *in, uint32_t n) { sha256_update(c, in, n); }
static void d_final(void *c, uint8_t *out) { sha256_final(c, out); }
const struct hash_desc hash_sha256 = { SHA256_LEN, SHA256_BLOCK, d_init, d_update, d_final };
