/*
 * aes_gcm.c - see aes_gcm.h.
 *
 * The AES block cipher is common/aes.c (TinyCrypt-derived, table S-box).
 *
 * GHASH multiplies bit by bit with masks (SP 800-38D Algorithm 1): no tables
 * and no data-dependent branches.
 */
#include <string.h>
#include "aes_gcm.h"
#include "aes.h"
#include "secure_wipe.h"

struct gcm {
	struct aes_key k;            /* AES-128/256 round keys */
	uint8_t h[16];               /* GHASH key E(K, 0^128) */
	uint8_t y[16];               /* GHASH accumulator */
};

static uint64_t ld64(const uint8_t *p)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = (v << 8) | p[i];
	return v;
}

static void st64(uint8_t *p, uint64_t v)
{
	for (int i = 7; i >= 0; i--, v >>= 8)
		p[i] = (uint8_t)v;
}

/* All ones if the top bit of x is set. An arithmetic shift, not 0 - bit:
 * GCC turns (0 - bit) & v into bit * v, and this core's multiplier is
 * bit-serial (~64 cycles), which made GHASH 8x slower. */
static inline uint64_t top_mask(uint64_t x)
{
	return (uint64_t)((int64_t)x >> 63);
}

/* y = y * h in GF(2^128), SP 800-38D Algorithm 1. */
static void gf_mul(uint8_t y[16], const uint8_t h[16])
{
	uint64_t xh = ld64(y), xl = ld64(y + 8);
	uint64_t vh = ld64(h), vl = ld64(h + 8);
	uint64_t zh = 0, zl = 0;

	for (int i = 0; i < 128; i++) {
		uint64_t m = top_mask(xh);
		xh = (xh << 1) | (xl >> 63);
		xl <<= 1;
		zh ^= vh & m;
		zl ^= vl & m;
		uint64_t r = top_mask(vl << 63);
		vl = (vl >> 1) | (vh << 63);
		vh = (vh >> 1) ^ (0xe100000000000000ull & r);
	}
	st64(y, zh);
	st64(y + 8, zl);
}

/* Absorb d into GHASH, the last partial block zero-padded. */
static void ghash(struct gcm *g, const uint8_t *d, uint32_t len)
{
	while (len) {
		uint32_t n = len < 16 ? len : 16;
		for (uint32_t i = 0; i < n; i++)
			g->y[i] ^= d[i];
		gf_mul(g->y, g->h);
		d += n;
		len -= n;
	}
}

/* GCTR starting at inc32(J0), J0 = IV || 0^31 || 1. */
static void gctr(const struct gcm *g, const uint8_t iv[12], const uint8_t *in,
		 uint32_t len, uint8_t *out)
{
	uint8_t cb[16], ks[16];
	uint32_t ctr = 1;

	memcpy(cb, iv, 12);
	while (len) {
		ctr++;
		cb[12] = (uint8_t)(ctr >> 24); cb[13] = (uint8_t)(ctr >> 16);
		cb[14] = (uint8_t)(ctr >> 8);  cb[15] = (uint8_t)ctr;
		aes_encrypt_block(&g->k, cb, ks);
		uint32_t n = len < 16 ? len : 16;
		for (uint32_t i = 0; i < n; i++)
			out[i] = in[i] ^ ks[i];
		in += n;
		out += n;
		len -= n;
	}
}

/* T = E(K, J0) xor GHASH(A || C || [len(A)]64 || [len(C)]64) */
static void tag_compute(struct gcm *g, const uint8_t iv[12], const uint8_t *aad,
			uint32_t aad_len, const uint8_t *ct, uint32_t len,
			uint8_t t[16])
{
	uint8_t blk[16];

	memset(g->y, 0, 16);
	ghash(g, aad, aad_len);
	ghash(g, ct, len);
	st64(blk, 8ull * aad_len);
	st64(blk + 8, 8ull * len);
	ghash(g, blk, 16);
	memcpy(blk, iv, 12);
	blk[12] = 0; blk[13] = 0; blk[14] = 0; blk[15] = 1;
	aes_encrypt_block(&g->k, blk, t);
	for (int i = 0; i < 16; i++)
		t[i] ^= g->y[i];
}

static void setup(struct gcm *g, const uint8_t *key, uint32_t key_len)
{
	static const uint8_t zero[16];
	aes_setkey(&g->k, key, key_len);
	aes_encrypt_block(&g->k, zero, g->h);
}

void aes_gcm_encrypt(const uint8_t *key, uint32_t key_len, const uint8_t iv[12],
			const uint8_t *aad, uint32_t aad_len,
			const uint8_t *in, uint32_t len,
			uint8_t *out, uint8_t tag[16])
{
	struct gcm g;
	setup(&g, key, key_len);
	gctr(&g, iv, in, len, out);
	tag_compute(&g, iv, aad, aad_len, out, len, tag);
	edhoc_wipe(&g, sizeof(g));
}

int aes_gcm_decrypt(const uint8_t *key, uint32_t key_len, const uint8_t iv[12],
		       const uint8_t *aad, uint32_t aad_len,
		       const uint8_t *in, uint32_t len,
		       const uint8_t tag[16], uint8_t *out)
{
	struct gcm g;
	uint8_t t[16];
	uint8_t diff = 0;

	setup(&g, key, key_len);
	tag_compute(&g, iv, aad, aad_len, in, len, t);
	for (int i = 0; i < 16; i++)
		diff |= (uint8_t)(t[i] ^ tag[i]);
	if (!diff)
		gctr(&g, iv, in, len, out);
	edhoc_wipe(&g, sizeof(g));
	edhoc_wipe(t, sizeof(t));
	return diff ? -1 : 0;
}
