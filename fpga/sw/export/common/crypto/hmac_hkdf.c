/* hmac_hkdf.c - see hmac_hkdf.h. */
#include <string.h>
#include "hmac_hkdf.h"
#include "secure_wipe.h"

static void pad_key(struct hmac_ctx *m, uint8_t x)
{
	uint8_t blk[HASH_MAX_BLOCK];

	for (uint32_t i = 0; i < m->h->block; i++)
		blk[i] = m->key[i] ^ x;
	m->h->update(&m->ctx, blk, m->h->block);
	edhoc_wipe(blk, sizeof(blk));
}

void hmac_init(struct hmac_ctx *m, const struct hash_desc *h,
	       const uint8_t *key, uint32_t key_len)
{
	m->h = h;
	memset(m->key, 0, sizeof(m->key));
	if (key_len > h->block) {
		h->init(&m->ctx);
		h->update(&m->ctx, key, key_len);
		h->final(&m->ctx, m->key);
	} else if (key_len) {
		memcpy(m->key, key, key_len);
	}
	h->init(&m->ctx);
	pad_key(m, 0x36);
}

void hmac_update(struct hmac_ctx *m, const uint8_t *in, uint32_t len)
{
	m->h->update(&m->ctx, in, len);
}

void hmac_final(struct hmac_ctx *m, uint8_t *out)
{
	uint8_t ih[HASH_MAX_LEN];

	m->h->final(&m->ctx, ih);
	m->h->init(&m->ctx);
	pad_key(m, 0x5c);
	m->h->update(&m->ctx, ih, m->h->len);
	m->h->final(&m->ctx, out);
	edhoc_wipe(ih, sizeof(ih));
	edhoc_wipe(m, sizeof(*m));
}

void hkdf_extract_h(const struct hash_desc *h, const uint8_t *salt,
		    uint32_t salt_len, const uint8_t *ikm, uint32_t ikm_len,
		    uint8_t *prk)
{
	struct hmac_ctx m;

	hmac_init(&m, h, salt, salt_len);
	hmac_update(&m, ikm, ikm_len);
	hmac_final(&m, prk);
}

int hkdf_expand_h(const struct hash_desc *h, const uint8_t *prk,
		  uint32_t prk_len, const uint8_t *info, uint32_t info_len,
		  uint8_t *out, uint32_t out_len)
{
	struct hmac_ctx m;
	uint8_t t[HASH_MAX_LEN];

	if (out_len > 255 * h->len)
		return -1;
	for (uint8_t i = 1; out_len; i++) {
		uint32_t k = out_len < h->len ? out_len : h->len;
		hmac_init(&m, h, prk, prk_len);
		if (i > 1)
			hmac_update(&m, t, h->len);
		hmac_update(&m, info, info_len);
		hmac_update(&m, &i, 1);
		hmac_final(&m, t);
		memcpy(out, t, k);
		out += k;
		out_len -= k;
	}
	edhoc_wipe(t, sizeof(t));
	return 0;
}
