/*
 * aes_ccm.c - see inc/common/aes_ccm.h.
 *
 * CBC-MAC over B0 || encoded AAD || payload, and CTR encryption with
 * counter blocks A_i (SP 800-38C Appendix A; RFC 3610 Section 2), on the
 * AES block cipher in common/aes.c. The nonce is 13 bytes, so the length
 * field is L = 2 bytes.
 */
#include <string.h>
#include "aes_ccm.h"
#include "aes.h"
#include "secure_wipe.h"

struct ccm {
	struct aes_key k;
	uint8_t x[16];     /* CBC-MAC state */
	uint32_t fill;     /* bytes of the current block absorbed */
};

static void mac_byte(struct ccm *c, uint8_t b)
{
	c->x[c->fill++] ^= b;
	if (c->fill == 16) {
		aes_encrypt_block(&c->k, c->x, c->x);
		c->fill = 0;
	}
}

/* Zero-pad the current block: XOR with zeros is a no-op, so only the
 * pending encryption remains. */
static void mac_pad(struct ccm *c)
{
	if (c->fill) {
		aes_encrypt_block(&c->k, c->x, c->x);
		c->fill = 0;
	}
}

/* Block with flags byte f, the nonce, and a 2-byte big-endian value v. */
static void block(uint8_t b[16], uint8_t f, const uint8_t nonce[13],
		  uint32_t v)
{
	b[0] = f;
	memcpy(b + 1, nonce, 13);
	b[14] = (uint8_t)(v >> 8);
	b[15] = (uint8_t)v;
}

/* T = first tag_len bytes of CBC-MAC(B0 || [a] || m). */
static void cbc_mac(struct ccm *c, const uint8_t nonce[13], const uint8_t *aad,
		    uint32_t aad_len, const uint8_t *m, uint32_t len,
		    uint32_t tag_len)
{
	uint8_t flags = (uint8_t)((aad_len ? 0x40 : 0) |
				  (((tag_len - 2) / 2) << 3) | (2 - 1));

	block(c->x, flags, nonce, len);
	aes_encrypt_block(&c->k, c->x, c->x);
	c->fill = 0;
	if (aad_len) {
		mac_byte(c, (uint8_t)(aad_len >> 8));
		mac_byte(c, (uint8_t)aad_len);
		for (uint32_t i = 0; i < aad_len; i++)
			mac_byte(c, aad[i]);
		mac_pad(c);
	}
	for (uint32_t i = 0; i < len; i++)
		mac_byte(c, m[i]);
	mac_pad(c);
}

/* out = in xor S_1 S_2 ...; returns S_0 in s0 for the tag. */
static void ctr(const struct ccm *c, const uint8_t nonce[13],
		const uint8_t *in, uint32_t len, uint8_t *out, uint8_t s0[16])
{
	uint8_t a[16], s[16];

	block(a, 2 - 1, nonce, 0);
	aes_encrypt_block(&c->k, a, s0);
	for (uint32_t i = 0, n = 1; i < len; n++) {
		block(a, 2 - 1, nonce, n);
		aes_encrypt_block(&c->k, a, s);
		for (uint32_t j = 0; j < 16 && i < len; j++, i++)
			out[i] = in[i] ^ s[j];
	}
}

void aes_ccm_encrypt(const uint8_t key[16], const uint8_t nonce[13],
		     const uint8_t *aad, uint32_t aad_len,
		     const uint8_t *in, uint32_t len,
		     uint8_t *out, uint8_t *tag, uint32_t tag_len)
{
	struct ccm c;
	uint8_t s0[16];

	aes_setkey(&c.k, key, 16);
	cbc_mac(&c, nonce, aad, aad_len, in, len, tag_len);
	ctr(&c, nonce, in, len, out, s0);
	for (uint32_t i = 0; i < tag_len; i++)
		tag[i] = c.x[i] ^ s0[i];
	edhoc_wipe(&c, sizeof(c));
	edhoc_wipe(s0, sizeof(s0));
}

int aes_ccm_decrypt(const uint8_t key[16], const uint8_t nonce[13],
		    const uint8_t *aad, uint32_t aad_len,
		    const uint8_t *in, uint32_t len,
		    const uint8_t *tag, uint32_t tag_len, uint8_t *out)
{
	struct ccm c;
	uint8_t s0[16], diff = 0;

	aes_setkey(&c.k, key, 16);
	ctr(&c, nonce, in, len, out, s0);
	cbc_mac(&c, nonce, aad, aad_len, out, len, tag_len);
	for (uint32_t i = 0; i < tag_len; i++)
		diff |= (uint8_t)(c.x[i] ^ s0[i] ^ tag[i]);
	if (diff)
		edhoc_wipe(out, len);
	edhoc_wipe(&c, sizeof(c));
	edhoc_wipe(s0, sizeof(s0));
	return diff ? -1 : 0;
}
