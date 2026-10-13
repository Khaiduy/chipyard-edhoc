/*
 * sha384.c - see sha384.h. SHA-512 compression (FIPS 180-4 Section 6.4) with
 * the SHA-384 initial value: one rolled round loop, a 16-word message
 * schedule kept in a ring, whole blocks compressed straight from the input.
 */
#include <string.h>
#include "sha384.h"
#include "hmac_hkdf.h"

static const uint64_t K[80] = {
	0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
	0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
	0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
	0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
	0xd807aa98a3030242ull, 0x12835b0145706fbeull,
	0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
	0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
	0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
	0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
	0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
	0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
	0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
	0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
	0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
	0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
	0x06ca6351e003826full, 0x142929670a0e6e70ull,
	0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
	0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
	0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
	0x81c2c92e47edaee6ull, 0x92722c851482353bull,
	0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
	0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
	0xd192e819d6ef5218ull, 0xd69906245565a910ull,
	0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
	0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
	0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
	0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
	0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
	0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
	0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
	0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
	0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
	0xca273eceea26619cull, 0xd186b8c721c0c207ull,
	0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
	0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
	0x113f9804bef90daeull, 0x1b710b35131c471bull,
	0x28db77f523047d84ull, 0x32caab7b40c72493ull,
	0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
	0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
	0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

static const uint64_t IV384[8] = {
	0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
	0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
	0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
	0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint64_t load_be64(const uint8_t *p)
{
	uint64_t v = 0;

	for (int i = 0; i < 8; i++)
		v = (v << 8) | p[i];
	return v;
}

static void compress(uint64_t h[8], const uint8_t blk[SHA384_BLOCK])
{
	uint64_t w[16], s[8];

	for (int i = 0; i < 16; i++)
		w[i] = load_be64(blk + 8 * i);
	memcpy(s, h, sizeof(s));
	for (int t = 0; t < 80; t++) {
		if (t >= 16) {
			uint64_t w15 = w[(t - 15) & 15], w2 = w[(t - 2) & 15];
			w[t & 15] += (ROR(w15, 1) ^ ROR(w15, 8) ^ (w15 >> 7)) +
				     w[(t - 7) & 15] +
				     (ROR(w2, 19) ^ ROR(w2, 61) ^ (w2 >> 6));
		}
		uint64_t e = s[4], a = s[0];
		uint64_t t1 = s[7] + (ROR(e, 14) ^ ROR(e, 18) ^ ROR(e, 41)) +
			      ((e & s[5]) ^ (~e & s[6])) + K[t] + w[t & 15];
		uint64_t t2 = (ROR(a, 28) ^ ROR(a, 34) ^ ROR(a, 39)) +
			      ((a & s[1]) ^ (a & s[2]) ^ (s[1] & s[2]));
		memmove(s + 1, s, 7 * sizeof(s[0]));
		s[4] += t1;
		s[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++)
		h[i] += s[i];
}

void sha384_init(struct sha384_ctx *c)
{
	memcpy(c->h, IV384, sizeof(c->h));
	c->len = 0;
}

void sha384_update(struct sha384_ctx *c, const uint8_t *in, uint32_t len)
{
	uint32_t fill = (uint32_t)(c->len % SHA384_BLOCK);

	c->len += len;
	if (fill) {
		uint32_t n = SHA384_BLOCK - fill;
		if (n > len)
			n = len;
		memcpy(c->buf + fill, in, n);
		in += n;
		len -= n;
		if (fill + n < SHA384_BLOCK)
			return;
		compress(c->h, c->buf);
	}
	for (; len >= SHA384_BLOCK; in += SHA384_BLOCK, len -= SHA384_BLOCK)
		compress(c->h, in);
	memcpy(c->buf, in, len);
}

void sha384_final(struct sha384_ctx *c, uint8_t out[SHA384_LEN])
{
	uint64_t bits = c->len * 8;
	uint32_t fill = (uint32_t)(c->len % SHA384_BLOCK);

	c->buf[fill++] = 0x80;
	if (fill > SHA384_BLOCK - 16) {
		memset(c->buf + fill, 0, SHA384_BLOCK - fill);
		compress(c->h, c->buf);
		fill = 0;
	}
	memset(c->buf + fill, 0, SHA384_BLOCK - 8 - fill);  /* incl. high 64 length bits */
	for (int i = 0; i < 8; i++)
		c->buf[SHA384_BLOCK - 1 - i] = (uint8_t)(bits >> (8 * i));
	compress(c->h, c->buf);
	for (int i = 0; i < SHA384_LEN; i++)
		out[i] = (uint8_t)(c->h[i / 8] >> (56 - 8 * (i % 8)));
}

void sha384_hash(const uint8_t *in, uint32_t len, uint8_t out[SHA384_LEN])
{
	struct sha384_ctx c;

	sha384_init(&c);
	sha384_update(&c, in, len);
	sha384_final(&c, out);
}

/* Descriptor for hmac_hkdf.c; defined here so only images that use SHA-384
 * link it. */
static void d_init(void *c) { sha384_init(c); }
static void d_update(void *c, const uint8_t *in, uint32_t n) { sha384_update(c, in, n); }
static void d_final(void *c, uint8_t *out) { sha384_final(c, out); }
const struct hash_desc hash_sha384 = { SHA384_LEN, SHA384_BLOCK, d_init, d_update, d_final };
