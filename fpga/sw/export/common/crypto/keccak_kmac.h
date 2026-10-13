/*
 * keccak_kmac.h - incremental SHAKE256 and KMAC256 (FIPS 202, NIST SP 800-185)
 * for the SHAKE256 EDHOC hash of the draft-ietf-lake-pqsuites cipher suites.
 *
 * RFC 9528 Sections 4.1.1 and 4.1.2 with EDHOC hash SHAKE256:
 *   H(x)                       = SHAKE256(x, 512)
 *   EDHOC_Extract(salt, IKM)   = KMAC256(salt, IKM, 512, "")
 *   EDHOC_Expand(PRK, info, n) = KMAC256(PRK, info, 8 * n, "")
 *
 * Inputs are absorbed piecewise, so a transcript hash or a KDF info that
 * embeds a credential never has to be assembled in a buffer first.
 */
#ifndef KECCAK_KMAC_H
#define KECCAK_KMAC_H

#include <stdint.h>

struct keccak_ctx {
	uint64_t s[25];
	uint32_t pos;   /* next byte of the rate to absorb or squeeze */
};

void shake256_init(struct keccak_ctx *c);
void keccak_absorb(struct keccak_ctx *c, const uint8_t *in, uint32_t len);
/* Absorb a CBOR byte string: the major-type-2 header, then the bytes. */
void keccak_absorb_bstr(struct keccak_ctx *c, const uint8_t *in, uint32_t len);
void shake256_final(struct keccak_ctx *c, uint8_t *out, uint32_t len);

/* KMAC256 with an empty customization string, as RFC 9528 uses it. */
void kmac256_init(struct keccak_ctx *c, const uint8_t *key, uint32_t key_len);
void kmac256_final(struct keccak_ctx *c, uint8_t *out, uint32_t len);


#endif /* KECCAK_KMAC_H */
