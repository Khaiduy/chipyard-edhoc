/*
 * keccak_kmac.c - see keccak_kmac.h.
 *
 * Built on the Keccak-f[1600] permutation that mlkem-native already links in
 * for ML-KEM, so the SHAKE256 suite adds no second Keccak implementation.
 * Lanes are addressed as bytes, which assumes a little-endian target (RISC-V
 * and the x86 host the tests run on).
 */
#include <string.h>
#include "keccak_kmac.h"
#include "cbor.h"

/* mlkem-native's permutation, namespaced by the parameter set it is built
 * for (MLK_CONFIG_PARAMETER_SET: 512 or 1024). */
#define KECCAK_PERM__(l) PQCP_MLKEM_NATIVE_MLKEM##l##_keccakf1600_permute
#define KECCAK_PERM_(l) KECCAK_PERM__(l)
#define KECCAK_PERM KECCAK_PERM_(MLK_CONFIG_PARAMETER_SET)
void KECCAK_PERM(uint64_t *state);
#define permute(c) KECCAK_PERM((c)->s)

#define RATE 136u            /* Keccak[512]: SHAKE256, cSHAKE256, KMAC256 */
#define PAD_SHAKE  0x1fu     /* FIPS 202 domain bits 1111, then pad10*1 */
#define PAD_CSHAKE 0x04u     /* SP 800-185 domain bits 00, then pad10*1 */

static void absorb_byte(struct keccak_ctx *c, uint8_t b)
{
	((uint8_t *)c->s)[c->pos++] ^= b;
	if (c->pos == RATE) {
		permute(c);
		c->pos = 0;
	}
}

void keccak_absorb(struct keccak_ctx *c, const uint8_t *in, uint32_t len)
{
	while (len--)
		absorb_byte(c, *in++);
}

/* bytepad's trailing zeros: XORing zeros is a no-op, so only the
 * permutation of a partially filled block remains. */
static void pad_block(struct keccak_ctx *c)
{
	if (c->pos) {
		permute(c);
		c->pos = 0;
	}
}

static void finish(struct keccak_ctx *c, uint8_t pad)
{
	((uint8_t *)c->s)[c->pos] ^= pad;
	((uint8_t *)c->s)[RATE - 1] ^= 0x80;
	permute(c);
	c->pos = 0;
}

static void squeeze(struct keccak_ctx *c, uint8_t *out, uint32_t len)
{
	while (len--) {
		if (c->pos == RATE) {
			permute(c);
			c->pos = 0;
		}
		*out++ = ((uint8_t *)c->s)[c->pos++];
	}
}

/* SP 800-185 Section 2.3.1: left_encode(x) = n || x (big endian, n bytes),
 * right_encode(x) = x || n. */
static void encode(struct keccak_ctx *c, uint64_t x, int right)
{
	uint8_t b[8];
	uint8_t n = 0;

	do {
		b[n++] = (uint8_t)x;
		x >>= 8;
	} while (x);
	if (!right)
		absorb_byte(c, n);
	for (uint8_t i = n; i; i--)
		absorb_byte(c, b[i - 1]);
	if (right)
		absorb_byte(c, n);
}

void shake256_init(struct keccak_ctx *c)
{
	memset(c, 0, sizeof(*c));
}

void shake256_final(struct keccak_ctx *c, uint8_t *out, uint32_t len)
{
	finish(c, PAD_SHAKE);
	squeeze(c, out, len);
}

void kmac256_init(struct keccak_ctx *c, const uint8_t *key, uint32_t key_len)
{
	static const uint8_t kmac_n[4] = { 'K', 'M', 'A', 'C' };

	memset(c, 0, sizeof(*c));
	/* bytepad(encode_string("KMAC") || encode_string(""), 136) */
	encode(c, RATE, 0);
	encode(c, 8 * sizeof(kmac_n), 0);
	keccak_absorb(c, kmac_n, sizeof(kmac_n));
	encode(c, 0, 0);
	pad_block(c);
	/* bytepad(encode_string(K), 136) */
	encode(c, RATE, 0);
	encode(c, 8ull * key_len, 0);
	keccak_absorb(c, key, key_len);
	pad_block(c);
}

void kmac256_final(struct keccak_ctx *c, uint8_t *out, uint32_t len)
{
	encode(c, 8ull * len, 1);
	finish(c, PAD_CSHAKE);
	squeeze(c, out, len);
}

void keccak_absorb_bstr(struct keccak_ctx *c, const uint8_t *in, uint32_t len)
{
	uint8_t h[9];
	keccak_absorb(c, h, cbor_head(h, 2, len));
	keccak_absorb(c, in, len);
}
