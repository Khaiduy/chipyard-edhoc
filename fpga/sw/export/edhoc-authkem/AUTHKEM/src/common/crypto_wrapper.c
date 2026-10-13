/*
 * crypto_wrapper.c — the crypto backend for this tree.
 *
 * Single implementation of the backend contract declared in
 * inc/common/crypto_wrapper.h. It retains the same filename and role as the
 * upstream uoscore-uedhoc backend.
 *
 * Software backend for Method 5 (draft-ietf-lake-authkem-edhoc-01) with one
 * draft-ietf-lake-pqsuites-01 cipher suite, chosen at build time:
 *            TBD1 (SUITE=TBD1)    TBD2 (default)      TBD3 (SUITE=TBD3)
 *   KEM   : ML-KEM-512           ML-KEM-512          ML-KEM-1024  (mlkem-native)
 *   AEAD  : AES-CCM-16-128-128,  A256GCM             A256GCM      (aes_ccm.c,
 *           app AES-CCM-16-64-128                                  aes_gcm.c)
 *   Hash  : SHAKE256             SHAKE256            SHA-384  (keccak_kmac.c,
 *   KDF   : KMAC256              KMAC256             HKDF-SHA-384  sha384.c,
 *                                                                hmac_hkdf.c)
 * The primitives are in ../common/crypto, shared with edhoc-wolfssl.
 *
 * Method 5 authenticates purely by KEM encapsulation, with a MAC over
 * KEM-derived keys, so there is no ECDH or signature entry.
 *
 * ---------------------------------------------------------------------------
 * Adding a backend (for example an ML-KEM or AES hardware core)
 * ---------------------------------------------------------------------------
 * Every function here is WEAK. To accelerate one primitive, define a strong
 * symbol with the same signature in the application; it wins at link time and
 * nothing in the library changes. To replace the whole backend, write another
 * file implementing crypto_wrapper.h and swap this one out of the build.
 *
 * The contract is exactly these 8 functions:
 *   KEM        ephemeral_kem_key_gen, kem_encapsulate, kem_decapsulate
 *   AEAD       aead
 *   Hash       hash, hash_parts
 *   KDF        hkdf_extract, hkdf_expand_parts
 */
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "edhoc.h"
#include "common/crypto_wrapper.h"
#include "kprintf.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "edhoc/suites.h"
#include "edhoc/buffer_sizes.h"

/* FIPS 203 ML-KEM (portable C, including mandatory key checks), single
 * parameter set chosen by MLK_CONFIG_PARAMETER_SET (512 or 1024). */
#include "mlkem_native.h"

#define KEM_LVL MLK_CONFIG_PARAMETER_SET
#define KEM_FN__(l, f) PQCP_MLKEM_NATIVE_MLKEM##l##_##f
#define KEM_FN_(l, f) KEM_FN__(l, f)
#define KEM_FN(f) KEM_FN_(KEM_LVL, f)
/* edhoc/buffer_sizes.h sizes the buffers; they must match FIPS 203. */
_Static_assert(KEM_SK_SIZE == MLKEM_SECRETKEYBYTES(KEM_LVL), "KEM_SK_SIZE");
_Static_assert(KEM_PK_SIZE == MLKEM_PUBLICKEYBYTES(KEM_LVL), "KEM_PK_SIZE");
_Static_assert(KEM_CT_SIZE == MLKEM_CIPHERTEXTBYTES(KEM_LVL), "KEM_CT_SIZE");
_Static_assert(KEM_SECRET_SIZE == MLKEM_BYTES, "KEM_SECRET_SIZE");
#if KEM_LVL == 1024
#define KEM_ALG ML_KEM_1024
#else
#define KEM_ALG ML_KEM_512
#endif

extern int default_CSPRNG(uint8_t *dest, unsigned int size);

#if AUTHKEM_PQ_SUITE == 1
#include "aes_ccm.h"
#else
#include "aes_gcm.h"
#endif
#if AUTHKEM_PQ_SUITE == 3
#include "hmac_hkdf.h"
#else
#include "keccak_kmac.h"
#endif
#include "cbor.h"
#include "secure_wipe.h"

/* =====================================================================
 * ML-KEM KEM primitives (ML-KEM-512 or ML-KEM-1024, one per image)
 * ===================================================================== */


/* KEM backend: mlkem-native. It is correct on this target -- a standalone
 * on-board keygen/encap/decap round-trip matches with 51 kB of stack headroom
 * -- and it is far leaner than PQClean's reference code, which needs ~11.5 kB
 * of stack for decapsulation (it materialises the whole matrix) against the
 * ~9.4 kB available here. An earlier DIFFER result with this backend was
 * .bss corruption from a stack overflow, not a fault in the library. */

enum err WEAK ephemeral_kem_key_gen(enum ecdh_alg alg,
				    struct byte_array *sk,
				    struct byte_array *pk)
{
	/* The only KEM linked into this image is KEM_ALG. Refuse any other
	 * identifier rather than silently running ML-KEM under its name. */
	if (alg != KEM_ALG)
		return unsupported_ecdh_curve;
	if (sk->len < KEM_SK_SIZE || pk->len < KEM_PK_SIZE)
		return buffer_to_small;
	uint8_t coins[2 * MLKEM_SYMBYTES];
	if (default_CSPRNG(coins, sizeof(coins)) != 1)
		return unexpected_result_from_ext_lib;
	if (KEM_FN(keypair_derand)(pk->ptr, sk->ptr, coins) != 0)
		return unexpected_result_from_ext_lib;
	sk->len = KEM_SK_SIZE;
	pk->len = KEM_PK_SIZE;
	return ok;
}

enum err WEAK kem_encapsulate(enum ecdh_alg alg,
			      const struct byte_array *pk,
			      struct byte_array *ct,
			      struct byte_array *ss)
{
	if (alg != KEM_ALG)
		return unsupported_ecdh_curve;
	if (pk->len != KEM_PK_SIZE || ct->len < KEM_CT_SIZE ||
	    ss->len < MLKEM_BYTES)
		return wrong_parameter;
	uint8_t coins[MLKEM_SYMBYTES];
	if (default_CSPRNG(coins, sizeof(coins)) != 1)
		return unexpected_result_from_ext_lib;
	if (KEM_FN(enc_derand)(ct->ptr, ss->ptr, pk->ptr, coins) != 0)
		return unexpected_result_from_ext_lib;
	ct->len = KEM_CT_SIZE;
	ss->len = MLKEM_BYTES;
	return ok;
}

enum err WEAK kem_decapsulate(enum ecdh_alg alg,
			 const struct byte_array *ct,
			 const struct byte_array *sk,
			 struct byte_array *ss)
{
	if (alg != KEM_ALG)
		return unsupported_ecdh_curve;
	if (ct->len != KEM_CT_SIZE || sk->len != KEM_SK_SIZE ||
	    ss->len < MLKEM_BYTES)
		return wrong_parameter;
	if (KEM_FN(dec)(ss->ptr, ct->ptr, sk->ptr) != 0)
		return unexpected_result_from_ext_lib;
	ss->len = MLKEM_BYTES;
	return ok;
}

#if AUTHKEM_PQ_SUITE == 1
/* =====================================================================
 * AEAD — AES-CCM with a 13-byte nonce and a 16-byte (COSE 30, EDHOC) or
 * 8-byte (COSE 10, application) tag: suite TBD1.
 * ENCRYPT: in is the plaintext, out->len == in->len, tag receives the tag.
 * DECRYPT: in is ciphertext || tag, out->len is the plaintext length.
 * ===================================================================== */

enum err WEAK aead(enum aes_operation op, const struct byte_array *in,
		   const struct byte_array *key, struct byte_array *nonce,
		   const struct byte_array *aad, struct byte_array *out,
		   struct byte_array *tag)
{
	if (key->len != AES_CCM_KEY_LEN || nonce->len != AES_CCM_NONCE_LEN ||
	    (tag->len != 16 && tag->len != 8))
		return wrong_parameter;
	if (op == DECRYPT) {
		if (in->len != out->len + tag->len)
			return wrong_parameter;
		if (aes_ccm_decrypt(key->ptr, nonce->ptr, aad->ptr, aad->len,
				    in->ptr, out->len, in->ptr + out->len,
				    tag->len, out->ptr))
			return mac_authentication_failed;
	} else {
		if (out->len != in->len)
			return wrong_parameter;
		aes_ccm_encrypt(key->ptr, nonce->ptr, aad->ptr, aad->len,
				in->ptr, in->len, out->ptr, tag->ptr, tag->len);
	}
	return ok;
}
#else
/* =====================================================================
 * AEAD — A256GCM (COSE 3), the EDHOC and application AEAD of the
 * draft-ietf-lake-pqsuites-01 suites TBD2 and TBD3. 12-byte IV, 16-byte tag.
 * ENCRYPT: in is the plaintext, out->len == in->len, tag receives the tag.
 * DECRYPT: in is ciphertext || tag, out->len is the plaintext length.
 * ===================================================================== */

enum err WEAK aead(enum aes_operation op, const struct byte_array *in,
		   const struct byte_array *key, struct byte_array *nonce,
		   const struct byte_array *aad, struct byte_array *out,
		   struct byte_array *tag)
{
	if (key->len != 32 || nonce->len != AES_GCM_IV_LEN ||
	    tag->len != AES_GCM_TAG_LEN)
		return wrong_parameter;
	if (op == DECRYPT) {
		if (in->len != out->len + AES_GCM_TAG_LEN)
			return wrong_parameter;
		if (aes_gcm_decrypt(key->ptr, 32, nonce->ptr, aad->ptr, aad->len,
				    in->ptr, out->len, in->ptr + out->len,
				    out->ptr))
			return mac_authentication_failed;
	} else {
		if (out->len != in->len)
			return wrong_parameter;
		aes_gcm_encrypt(key->ptr, 32, nonce->ptr, aad->ptr, aad->len,
				in->ptr, in->len, out->ptr, tag->ptr);
	}
	return ok;
}
#endif /* AUTHKEM_PQ_SUITE == 1 */

#if AUTHKEM_PQ_SUITE == 3
/* =====================================================================
 * Hash and KDF — SHA-384 / HKDF-SHA-384 (RFC 9528 Sections 4.1.1, 4.1.2)
 *   H(x)                       = SHA-384(x)
 *   EDHOC_Extract(salt, IKM)   = HKDF-Extract(salt, IKM)
 *   EDHOC_Expand(PRK, info, L) = HKDF-Expand(PRK, info, L)    (RFC 5869)
 * ===================================================================== */

/* Feed parts into a hash or an HMAC; bstr parts get their CBOR head first. */
static void feed_parts(void (*update)(void *, const uint8_t *, uint32_t),
		       void *ctx, const struct hash_part *p, uint32_t n)
{
	uint8_t h[9];

	for (uint32_t i = 0; i < n; i++) {
		if (p[i].as_bstr)
			update(ctx, h, cbor_head(h, CBOR_BSTR, p[i].len));
		update(ctx, p[i].ptr, p[i].len);
	}
}

static void hmac_feed(void *m, const uint8_t *in, uint32_t len)
{
	hmac_update(m, in, len);
}

enum err WEAK hash_parts(enum hash_alg alg, const struct hash_part *parts,
			 uint32_t n, struct byte_array *out)
{
	union hash_ctx c;

	if (alg != SHA_384)
		return crypto_operation_not_implemented;
	if (out->len < SHA384_LEN)
		return buffer_to_small;
	hash_sha384.init(&c);
	feed_parts(hash_sha384.update, &c, parts, n);
	hash_sha384.final(&c, out->ptr);
	out->len = SHA384_LEN;
	return ok;
}

enum err WEAK hash(enum hash_alg alg, const struct byte_array *in,
		   struct byte_array *out)
{
	struct hash_part p = { .ptr = in->ptr, .len = in->len, .as_bstr = false };
	return hash_parts(alg, &p, 1, out);
}

enum err WEAK hkdf_extract(enum hash_alg alg,
			   const struct byte_array *salt,
			   struct byte_array *ikm, uint8_t *out)
{
	if (alg != SHA_384)
		return crypto_operation_not_implemented;
	hkdf_extract_h(&hash_sha384, salt->ptr, salt->len, ikm->ptr, ikm->len,
		       out);
	return ok;
}

/* T(i) = HMAC(PRK, T(i-1) || info || i); the info parts are fed again for
 * every block, so info is never assembled. */
enum err WEAK hkdf_expand_parts(enum hash_alg alg,
				const struct byte_array *prk,
				const struct hash_part *parts, uint32_t n,
				struct byte_array *out)
{
	struct hmac_ctx m;
	uint8_t t[SHA384_LEN];
	uint32_t done = 0;

	if (alg != SHA_384)
		return crypto_operation_not_implemented;
	if (out->len > 255 * SHA384_LEN)
		return wrong_parameter;
	for (uint8_t i = 1; done < out->len; i++) {
		uint32_t k = out->len - done;
		hmac_init(&m, &hash_sha384, prk->ptr, prk->len);
		if (i > 1)
			hmac_update(&m, t, SHA384_LEN);
		feed_parts(hmac_feed, &m, parts, n);
		hmac_update(&m, &i, 1);
		hmac_final(&m, t);
		if (k > SHA384_LEN)
			k = SHA384_LEN;
		memcpy(out->ptr + done, t, k);
		done += k;
	}
	edhoc_wipe(t, sizeof(t));
	return ok;
}

#else
/* =====================================================================
 * Hash and KDF — SHAKE256 / KMAC256 (RFC 9528 Sections 4.1.1, 4.1.2)
 *   H(x)                       = SHAKE256(x, 512)
 *   EDHOC_Extract(salt, IKM)   = KMAC256(salt, IKM, 512, "")
 *   EDHOC_Expand(PRK, info, L) = KMAC256(PRK, info, 8 * L, "")
 * ===================================================================== */

#define SHAKE256_HASH_LEN 64

static void absorb_parts(struct keccak_ctx *k, const struct hash_part *p,
			 uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		if (p[i].as_bstr)
			keccak_absorb_bstr(k, p[i].ptr, p[i].len);
		else
			keccak_absorb(k, p[i].ptr, p[i].len);
	}
}

enum err WEAK hash_parts(enum hash_alg alg, const struct hash_part *parts,
			 uint32_t n, struct byte_array *out)
{
	struct keccak_ctx k;

	if (alg != SHAKE_256)
		return crypto_operation_not_implemented;
	if (out->len < SHAKE256_HASH_LEN)
		return buffer_to_small;
	shake256_init(&k);
	absorb_parts(&k, parts, n);
	shake256_final(&k, out->ptr, SHAKE256_HASH_LEN);
	out->len = SHAKE256_HASH_LEN;
	return ok;
}

enum err WEAK hash(enum hash_alg alg, const struct byte_array *in,
		   struct byte_array *out)
{
	struct hash_part p = { .ptr = in->ptr, .len = in->len, .as_bstr = false };
	return hash_parts(alg, &p, 1, out);
}

enum err WEAK hkdf_extract(enum hash_alg alg,
			   const struct byte_array *salt,
			   struct byte_array *ikm, uint8_t *out)
{
	struct keccak_ctx k;

	if (alg != SHAKE_256)
		return crypto_operation_not_implemented;
	kmac256_init(&k, salt->ptr, salt->len);
	keccak_absorb(&k, ikm->ptr, ikm->len);
	kmac256_final(&k, out, SHAKE256_HASH_LEN);
	edhoc_wipe(&k, sizeof(k));
	return ok;
}

enum err WEAK hkdf_expand_parts(enum hash_alg alg,
				const struct byte_array *prk,
				const struct hash_part *parts, uint32_t n,
				struct byte_array *out)
{
	struct keccak_ctx k;

	if (alg != SHAKE_256)
		return crypto_operation_not_implemented;
	kmac256_init(&k, prk->ptr, prk->len);
	absorb_parts(&k, parts, n);
	kmac256_final(&k, out->ptr, out->len);
	edhoc_wipe(&k, sizeof(k));
	return ok;
}

#endif /* AUTHKEM_PQ_SUITE */
