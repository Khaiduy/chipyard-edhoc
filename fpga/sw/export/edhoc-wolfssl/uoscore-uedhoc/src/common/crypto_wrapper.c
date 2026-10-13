/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include "edhoc.h"

#include "common/crypto_wrapper.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

#include "edhoc/suites.h"
#include "edhoc/buffer_sizes.h"

#include <wolfssl/wolfcrypt/sha3.h>
#if EDHOC_CRYPTO_SUITE == 25
#include <wolfssl/wolfcrypt/kmac.h>
#include <wolfssl/wolfcrypt/hash.h>   /* wc_Shake256Hash */
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve448.h>
/* wolfssl/wolfcrypt/ed448.h defines enum { Ed448=0, Ed448ph=1 } which
 * conflicts with our sign_alg.Ed448=-49.  Rename it during include. */
#define Ed448 wc_Ed448HashType
#include <wolfssl/wolfcrypt/ed448.h>
#undef Ed448
#include <wolfssl/wolfcrypt/random.h>
/* Symmetric primitives shared with edhoc-authkem (common/crypto) and
 * Monocypher's RFC 8439 ChaCha20-Poly1305. */
#include "aes_ccm.h"
#include "aes_gcm.h"
#include "hmac_hkdf.h"
#include "monocypher.h"

/* Compile-time suite classification — mirrors edhoc_suite_defs.h.
 * Guards below prevent dead ECC/Ed448/hash branches from being compiled,
 * allowing --gc-sections to remove unreferenced wolfCrypt code. */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || EDHOC_CRYPTO_SUITE == 5
#  define _SUITE_USES_P256 1   /* P-256 for ECDH */
#else
#  define _SUITE_USES_P256 0
#endif
#if EDHOC_CRYPTO_SUITE == 24
#  define _SUITE_USES_P384 1
#else
#  define _SUITE_USES_P384 0
#endif
#if EDHOC_CRYPTO_SUITE == 25
#  define _SUITE_USES_X448 1
#else
#  define _SUITE_USES_X448 0
#endif
/* ES256 for signing — Suites 2/3/5 (with P-256 ECDH) and Suite 6 (with X25519 ECDH).
 * Per RFC 9528 Table 6, Suite 6 is the mixed case. */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || \
    EDHOC_CRYPTO_SUITE == 5 || EDHOC_CRYPTO_SUITE == 6
#  define _SUITE_USES_ES256 1
#else
#  define _SUITE_USES_ES256 0
#endif
#define _SUITE_USES_ECC (_SUITE_USES_P256 || _SUITE_USES_P384 || _SUITE_USES_ES256)
/* Curve25519 runs on RV64-friendly code instead of wolfCrypt's
 * CURVE25519_SMALL/ED25519_SMALL (byte-radix field, ~328 M cycles per X25519
 * on this core): X25519 is curve25519-donna-c64 (radix 2^51, 128-bit
 * products), Ed25519 is Monocypher's RFC 8032 implementation. */
#if EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || \
    EDHOC_CRYPTO_SUITE == 4 || EDHOC_CRYPTO_SUITE == 6
#  define _SUITE_USES_X25519 1
int curve25519_donna(uint8_t *mypublic, const uint8_t *secret,
		     const uint8_t *basepoint);
#else
#  define _SUITE_USES_X25519 0
#endif
#if EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || \
    EDHOC_CRYPTO_SUITE == 4
#  define _SUITE_USES_ED25519 1
#  include "monocypher-ed25519.h"
#else
#  define _SUITE_USES_ED25519 0
#endif

#if _SUITE_USES_P256 || _SUITE_USES_ES256
static const byte p256n[32] = {   /* P-256 group order n */
	0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51
};
#endif
#if _SUITE_USES_P384
static const byte p384n[48] = {   /* P-384 group order n */
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC7,0x63,0x4D,0x81,0xF4,0x37,0x2D,0xDF,
	0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A,0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73
};
#endif
#if _SUITE_USES_ECC
/* Give an EC key pair an even y by negating the scalar when y is odd (same x,
 * opposite y). Public keys travel as x alone and CCS credentials carry
 * y = false (even y, RFC 9053 2.1), so this keeps that claim true for every
 * key, signature or static DH. pub receives the compressed SEC1 point. */
static int ecc_even_y(ecc_key *key, const byte *order, word32 olen,
		      byte *pub, word32 *pub_len)
{
	word32 cap = *pub_len;
	int r = wc_ecc_export_x963_ex(key, pub, pub_len, 1);

	if (r == 0 && pub[0] == 0x03) {
		mp_int n, neg;

		mp_init(&n);
		mp_init(&neg);
		r = mp_read_unsigned_bin(&n, order, olen);
		if (r == 0)
			r = mp_sub(&n, &key->k[0], &neg);
		if (r == 0)
			r = mp_copy(&neg, &key->k[0]);
		mp_clear(&n);
		mp_clear(&neg);
		if (r == 0)
			r = wc_ecc_make_pub(key, NULL);
		*pub_len = cap;
		if (r == 0)
			r = wc_ecc_export_x963_ex(key, pub, pub_len, 1);
	}
	return r;
}
#endif

enum err WEAK aead(enum aes_operation op, const struct byte_array *in,
		   const struct byte_array *key, struct byte_array *nonce,
		   const struct byte_array *aad, struct byte_array *out,
		   struct byte_array *tag)
{

	/* ENCRYPT: in is the plaintext, out->len == in->len, tag receives the tag.
	 * DECRYPT: in is ciphertext || tag, out receives the plaintext. */
	uint32_t len = op == DECRYPT ? in->len - tag->len : in->len;
	const uint8_t *in_tag = in->ptr + len;

#if EDHOC_CRYPTO_SUITE == 0 || EDHOC_CRYPTO_SUITE == 1 || \
    EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3
	/* AES-CCM: key 16, nonce 13, tag 8 (suites 0/2) or 16 (suites 1/3) */
	if (key->len != AES_CCM_KEY_LEN || nonce->len != AES_CCM_NONCE_LEN)
		return wrong_parameter;
	if (op == DECRYPT)
		return aes_ccm_decrypt(key->ptr, nonce->ptr, aad->ptr, aad->len,
				       in->ptr, len, in_tag, tag->len,
				       out->ptr) ? mac_authentication_failed : ok;
	aes_ccm_encrypt(key->ptr, nonce->ptr, aad->ptr, aad->len, in->ptr, len,
			out->ptr, tag->ptr, tag->len);
	return ok;
#elif EDHOC_CRYPTO_SUITE == 4 || EDHOC_CRYPTO_SUITE == 5 || \
      EDHOC_CRYPTO_SUITE == 25
	/* ChaCha20/Poly1305 (RFC 8439): key 32, nonce 12, tag 16 */
	crypto_aead_ctx x;
	if (key->len != 32 || nonce->len != 12 || tag->len != 16)
		return wrong_parameter;
	crypto_aead_init_ietf(&x, key->ptr, nonce->ptr);
	if (op == DECRYPT)
		return crypto_aead_read(&x, out->ptr, in_tag, aad->ptr, aad->len,
					in->ptr, len) ? mac_authentication_failed : ok;
	crypto_aead_write(&x, out->ptr, tag->ptr, aad->ptr, aad->len, in->ptr,
			  len);
	return ok;
#elif EDHOC_CRYPTO_SUITE == 6 || EDHOC_CRYPTO_SUITE == 24
	/* AES-GCM: key 16 (suite 6) or 32 (suite 24), nonce 12, tag 16 */
	if ((key->len != 16 && key->len != 32) ||
	    nonce->len != AES_GCM_IV_LEN || tag->len != AES_GCM_TAG_LEN)
		return wrong_parameter;
	if (op == DECRYPT)
		return aes_gcm_decrypt(key->ptr, key->len, nonce->ptr, aad->ptr,
				       aad->len, in->ptr, len, in_tag,
				       out->ptr) ? mac_authentication_failed : ok;
	aes_gcm_encrypt(key->ptr, key->len, nonce->ptr, aad->ptr, aad->len,
			in->ptr, len, out->ptr, tag->ptr);
	return ok;
#else
	(void)op; (void)key; (void)nonce; (void)aad; (void)out; (void)in_tag;
#endif
	return ok;
}

enum err WEAK sign(enum sign_alg alg, const struct byte_array *sk,
		   const struct byte_array *pk, const struct byte_array *msg,
		   uint8_t *out)
{

#if _SUITE_USES_ED25519
	if (alg == EdDSA) {
		/* sk->ptr[0..31] = 32-byte seed; pk->ptr = 32-byte public key.
		 * Monocypher takes the 64-byte seed || public key form. */
		uint8_t sk64[64];
		if (pk->len != 32)
			return wrong_parameter;
		memcpy(sk64, sk->ptr, 32);
		memcpy(sk64 + 32, pk->ptr, 32);
		crypto_ed25519_sign(out, sk64, msg->ptr, msg->len);
		crypto_wipe(sk64, sizeof(sk64));
		return ok;
	}
#endif /* _SUITE_USES_ED25519 */
#if _SUITE_USES_ES256 && defined(HAVE_ECC_SIGN)
	if (alg == ES256) {
		/* sp_ecc_sign_256 is LTO-eliminated when called indirectly through
		 * wc_ecc_sign_hash_ex.  Declare and call it directly so the linker
		 * sees a live reference and keeps the symbol (and its callees). */
		extern int sp_ecc_sign_256(const byte* hash, word32 hashLen,
		    WC_RNG* rng, const mp_int* priv, mp_int* rm, mp_int* sm,
		    mp_int* km, void* heap);

		ecc_key wc_key;
		mp_int r, s;
		WC_RNG rng;
		byte hash[32];
		wc_ecc_init(&wc_key);
		wc_ecc_import_private_key_ex(sk->ptr, sk->len, NULL, 0,
					     &wc_key, ECC_SECP256R1);
		sha256_hash(msg->ptr, msg->len, hash);
		mp_init(&r);
		mp_init(&s);
		wc_InitRng(&rng);
		sp_ecc_sign_256(hash, 32, &rng, wc_key.k, &r, &s, NULL, wc_key.heap);
		wc_FreeRng(&rng);
		mp_to_unsigned_bin_len(&r, out, 32);
		mp_to_unsigned_bin_len(&s, out + 32, 32);
		mp_clear(&r);
		mp_clear(&s);
		wc_ecc_free(&wc_key);
		return ok;
	}
#endif /* _SUITE_USES_ES256 && HAVE_ECC_SIGN */
#if _SUITE_USES_P384 && defined(HAVE_ECC_SIGN)
	if (alg == ES384) {
		ecc_key wc_key;
		mp_int r, s;
		WC_RNG rng;
		byte hash[48];
		wc_ecc_init(&wc_key);
		wc_ecc_import_private_key_ex(sk->ptr, sk->len, NULL, 0,
					     &wc_key, ECC_SECP384R1);
		sha384_hash(msg->ptr, msg->len, hash);
		mp_init(&r);
		mp_init(&s);
		wc_InitRng(&rng);
		wc_ecc_sign_hash_ex(hash, 48, &rng, &wc_key, &r, &s);
		wc_FreeRng(&rng);
		mp_to_unsigned_bin_len(&r, out, 48);
		mp_to_unsigned_bin_len(&s, out + 48, 48);
		mp_clear(&r);
		mp_clear(&s);
		wc_ecc_free(&wc_key);
		return ok;
	}
#endif /* _SUITE_USES_P384 && HAVE_ECC_SIGN */
#if _SUITE_USES_X448 && defined(HAVE_ED448) && !defined(NO_ED448_SIGN)
	if (alg == Ed448) {
		ed448_key wc_key;
		word32 sig_len = 114;
		wc_ed448_init(&wc_key);
		wc_ed448_import_private_key(sk->ptr, sk->len,
					    pk->ptr, pk->len, &wc_key);
		wc_ed448_sign_msg(msg->ptr, msg->len, out, &sig_len,
				  &wc_key, NULL, 0);
		wc_ed448_free(&wc_key);
		return ok;
	}
#endif /* _SUITE_USES_X448 && HAVE_ED448 && !NO_ED448_SIGN */
	return unsupported_ecdh_curve;
}

enum err WEAK verify(enum sign_alg alg, const struct byte_array *pk,
		     struct const_byte_array *msg, struct const_byte_array *sgn,
		     bool *result)
{

#if _SUITE_USES_ED25519
	if (alg == EdDSA) {
		*result = pk->len == 32 && sgn->len == 64 &&
			  crypto_ed25519_check(sgn->ptr, pk->ptr, msg->ptr,
					       msg->len) == 0;
		return ok;
	}
#endif /* _SUITE_USES_ED25519 */
#if _SUITE_USES_ES256 && defined(HAVE_ECC_VERIFY)
	if (alg == ES256) {
		/* CCS credentials store only X — try Y=even (0x02), fall back to Y=odd (0x03). */
		ecc_key wc_key;
		mp_int r, s;
		byte hash[32];
		byte compressed[33];
		int stat = 0;
		sha256_hash(msg->ptr, msg->len, hash);
		mp_init(&r);
		mp_init(&s);
		mp_read_unsigned_bin(&r, sgn->ptr, 32);
		mp_read_unsigned_bin(&s, sgn->ptr + 32, 32);
		memcpy(compressed + 1, pk->ptr, 32);
		for (int parity = 0; parity < 2 && stat != 1; parity++) {
			compressed[0] = (parity == 0) ? 0x02 : 0x03;
			wc_ecc_init(&wc_key);
			if (wc_ecc_import_x963_ex(compressed, 33, &wc_key,
						  ECC_SECP256R1) == 0) {
				wc_ecc_verify_hash_ex(&r, &s, hash, 32, &stat,
						      &wc_key);
			}
			wc_ecc_free(&wc_key);
		}
		*result = (stat == 1);
		mp_clear(&r);
		mp_clear(&s);
		return ok;
	}
#endif /* _SUITE_USES_ES256 && HAVE_ECC_VERIFY */
#if _SUITE_USES_P384 && defined(HAVE_ECC_VERIFY)
	if (alg == ES384) {
		/* CCS credentials store only X — try Y=even (0x02), fall back to Y=odd (0x03). */
		ecc_key wc_key;
		mp_int r, s;
		byte hash[48];
		byte compressed[49];
		int stat = 0;
		sha384_hash(msg->ptr, msg->len, hash);
		mp_init(&r);
		mp_init(&s);
		mp_read_unsigned_bin(&r, sgn->ptr, 48);
		mp_read_unsigned_bin(&s, sgn->ptr + 48, 48);
		memcpy(compressed + 1, pk->ptr, 48);
		for (int parity = 0; parity < 2 && stat != 1; parity++) {
			compressed[0] = (parity == 0) ? 0x02 : 0x03;
			wc_ecc_init(&wc_key);
			if (wc_ecc_import_x963_ex(compressed, 49, &wc_key,
						  ECC_SECP384R1) == 0) {
				wc_ecc_verify_hash_ex(&r, &s, hash, 48, &stat,
						      &wc_key);
			}
			wc_ecc_free(&wc_key);
		}
		*result = (stat == 1);
		mp_clear(&r);
		mp_clear(&s);
		return ok;
	}
#endif /* _SUITE_USES_P384 && HAVE_ECC_VERIFY */
#if _SUITE_USES_X448 && defined(HAVE_ED448) && !defined(NO_ED448_VERIFY)
	if (alg == Ed448) {
		ed448_key wc_key;
		int verified = 0;
		wc_ed448_init(&wc_key);
		wc_ed448_import_public(pk->ptr, pk->len, &wc_key);
		wc_ed448_verify_msg(sgn->ptr, sgn->len,
				    msg->ptr, msg->len,
				    &verified, &wc_key, NULL, 0);
		*result = (verified == 1);
		wc_ed448_free(&wc_key);
		return ok;
	}
#endif /* _SUITE_USES_X448 && HAVE_ED448 && !NO_ED448_VERIFY */
	return crypto_operation_not_implemented;
}

enum err WEAK hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
			   struct byte_array *ikm, uint8_t *out)
{
	/*"Note that [RFC5869] specifies that if the salt is not provided,
	it is set to a string of zeros.  For implementation purposes,
	not providing the salt is the same as setting the salt to the empty byte
	string. OSCORE sets the salt default value to empty byte string, which
	is converted to a string of zeroes (see Section 2.2 of [RFC5869])".*/

	/* An empty salt is HashLen zeros, which HMAC's zero padding makes
	 * identical to an empty key. */
	if (alg == SHA_256) {
		hkdf_extract_h(&hash_sha256, salt->ptr, salt->len, ikm->ptr,
			       ikm->len, out);
		return ok;
	}
#if EDHOC_CRYPTO_SUITE == 24
	if (alg == SHA_384) {
		hkdf_extract_h(&hash_sha384, salt->ptr, salt->len, ikm->ptr,
			       ikm->len, out);
		return ok;
	}
#endif
#if EDHOC_CRYPTO_SUITE == 25
	if (alg == SHAKE_256) {
		/* RFC 9528 §4.1.1: EDHOC_Extract(salt, IKM) = KMAC256(salt, IKM, 512, "")
		 * Output length = 64 bytes (512 bits). */
		Kmac kmac;
		uint8_t zero_salt[64] = { 0 };
		const uint8_t *s =
			(salt->ptr && salt->len) ? salt->ptr : zero_salt;
		word32 s_len = (salt->ptr && salt->len) ?
				       (word32)salt->len : 64;
		if (wc_InitKmac(&kmac, WC_KMAC_256, s, s_len,
				NULL, 0, NULL, INVALID_DEVID) != 0)
			return hkdf_failed;
		if (wc_KmacUpdate(&kmac, ikm->ptr, ikm->len) != 0) {
			wc_KmacFree(&kmac);
			return hkdf_failed;
		}
		if (wc_KmacFinal(&kmac, out, 64) != 0) {
			wc_KmacFree(&kmac);
			return hkdf_failed;
		}
		wc_KmacFree(&kmac);
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 25 */
	return crypto_operation_not_implemented;
}

enum err WEAK hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
			  const struct byte_array *info, struct byte_array *out)
{
	if (alg == SHA_256)
		return hkdf_expand_h(&hash_sha256, prk->ptr, prk->len, info->ptr,
				     info->len, out->ptr, out->len) ? hkdf_failed : ok;
#if EDHOC_CRYPTO_SUITE == 24
	if (alg == SHA_384)
		return hkdf_expand_h(&hash_sha384, prk->ptr, prk->len, info->ptr,
				     info->len, out->ptr, out->len) ? hkdf_failed : ok;
#endif
#if EDHOC_CRYPTO_SUITE == 25
	if (alg == SHAKE_256) {
		/* RFC 9528 §4.1.2: EDHOC_Expand(PRK, info, length) = KMAC256(PRK, info, 8*length, "")
		 * KMAC supplies the exact requested output length directly — no expand loop. */
		Kmac kmac;
		if (wc_InitKmac(&kmac, WC_KMAC_256, prk->ptr, prk->len,
				NULL, 0, NULL, INVALID_DEVID) != 0)
			return hkdf_failed;
		if (wc_KmacUpdate(&kmac, info->ptr, info->len) != 0) {
			wc_KmacFree(&kmac);
			return hkdf_failed;
		}
		if (wc_KmacFinal(&kmac, out->ptr, out->len) != 0) {
			wc_KmacFree(&kmac);
			return hkdf_failed;
		}
		wc_KmacFree(&kmac);
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 25 */
	return crypto_operation_not_implemented;
}

enum err WEAK shared_secret_derive(enum ecdh_alg alg,
				   const struct byte_array *sk,
				   const struct byte_array *pk,
				   uint8_t *shared_secret)
{
#if _SUITE_USES_X25519
	if (alg == X25519) {
		uint8_t z = 0;
		if (sk->len != 32 || pk->len != 32)
			return wrong_parameter;
		curve25519_donna(shared_secret, sk->ptr, pk->ptr);
		/* RFC 7748 Section 6.1: an all-zero result means the peer sent a
		 * low-order point; reject it (constant time over the 32 bytes). */
		for (int i = 0; i < 32; i++)
			z |= shared_secret[i];
		return z ? ok : unexpected_result_from_ext_lib;
	}
#endif /* _SUITE_USES_X25519 */
#if _SUITE_USES_P256
	if (alg == P256) {
		ecc_key priv_key, pub_key;
		byte compressed[33];
		word32 secret_len = 32;
		WC_RNG rng;
		compressed[0] = 0x02;
		memcpy(compressed + 1, pk->ptr, 32);
		int ret;
		/* Partial public key validation (RFC 9528 9.2, SP 800-56A
		 * 5.6.2.3.4) needs 0 <= x < p; wolfCrypt would reduce x mod p. */
		static const uint8_t p256[32] = {
			0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		if (sk->len != 32 || pk->len != 32 ||
		    memcmp(pk->ptr, p256, sizeof(p256)) >= 0)
			return wrong_parameter;
		if (wc_ecc_init(&priv_key) != 0 || wc_ecc_init(&pub_key) != 0)
			return unexpected_result_from_ext_lib;
		ret = wc_InitRng(&rng);
		if (ret == 0) ret = wc_ecc_set_rng(&priv_key, &rng);
		if (ret == 0) ret = wc_ecc_import_private_key_ex(
			sk->ptr, sk->len, NULL, 0, &priv_key, ECC_SECP256R1);
		if (ret == 0) ret = wc_ecc_import_x963_ex(
			compressed, 33, &pub_key, ECC_SECP256R1);
		if (ret == 0) ret = wc_ecc_shared_secret(
			&priv_key, &pub_key, shared_secret, &secret_len);
		wc_FreeRng(&rng);
		wc_ecc_free(&priv_key);
		wc_ecc_free(&pub_key);
		return (ret == 0 && secret_len == 32) ? ok :
			unexpected_result_from_ext_lib;
	}
#endif /* _SUITE_USES_P256 */
#if _SUITE_USES_P384
	if (alg == P384) {
		ecc_key priv_key, pub_key;
		byte compressed[49];
		word32 secret_len = 48;
		WC_RNG rng;
		int r384;
		/* 0 <= x < p, as for P-256 above */
		static const uint8_t p384[48] = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
			0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
		if (pk->len != 48 || memcmp(pk->ptr, p384, sizeof(p384)) >= 0)
			return wrong_parameter;
		compressed[0] = 0x02;
		memcpy(compressed + 1, pk->ptr, 48);
		wc_ecc_init(&priv_key);
		wc_ecc_init(&pub_key);
		wc_InitRng(&rng);
		wc_ecc_set_rng(&priv_key, &rng);
		r384 = wc_ecc_import_private_key_ex(sk->ptr, sk->len, NULL, 0,
						    &priv_key, ECC_SECP384R1);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_import_sk)", 0);
			wc_FreeRng(&rng); wc_ecc_free(&priv_key); wc_ecc_free(&pub_key);
			return unexpected_result_from_ext_lib;
		}
		r384 = wc_ecc_import_x963_ex(compressed, 49, &pub_key, ECC_SECP384R1);
		if (r384 != 0) {
			/* Try odd-Y prefix — shared secret X-coord is the same either way */
			compressed[0] = 0x03;
			r384 = wc_ecc_import_x963_ex(compressed, 49, &pub_key, ECC_SECP384R1);
		}
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_import_pk)", 0);
			wc_FreeRng(&rng); wc_ecc_free(&priv_key); wc_ecc_free(&pub_key);
			return unexpected_result_from_ext_lib;
		}
		r384 = wc_ecc_shared_secret(&priv_key, &pub_key,
					    shared_secret, &secret_len);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_ecdh)", 0);
			wc_FreeRng(&rng); wc_ecc_free(&priv_key); wc_ecc_free(&pub_key);
			return unexpected_result_from_ext_lib;
		}
		wc_FreeRng(&rng);
		wc_ecc_free(&priv_key);
		wc_ecc_free(&pub_key);
		return ok;
	}
#endif /* _SUITE_USES_P384 */
#if _SUITE_USES_X448
	if (alg == X448) {
		curve448_key priv_key, pub_key;
		word32 secret_len = 56;
		int ret;
		if (sk->len != 56 || pk->len != 56)
			return wrong_parameter;
		if (wc_curve448_init(&priv_key) != 0 ||
		    wc_curve448_init(&pub_key) != 0)
			return unexpected_result_from_ext_lib;
		ret = wc_curve448_import_private_ex(sk->ptr, sk->len, &priv_key,
						     EC448_LITTLE_ENDIAN);
		if (ret == 0) ret = wc_curve448_import_public_ex(
			pk->ptr, pk->len, &pub_key, EC448_LITTLE_ENDIAN);
		if (ret == 0) ret = wc_curve448_shared_secret_ex(
			&priv_key, &pub_key, shared_secret, &secret_len,
			EC448_LITTLE_ENDIAN);
		wc_curve448_free(&priv_key);
		wc_curve448_free(&pub_key);
		return (ret == 0 && secret_len == 56) ? ok :
			unexpected_result_from_ext_lib;
	}
#endif /* _SUITE_USES_X448 */
	return crypto_operation_not_implemented;
}

enum err WEAK ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
				   struct byte_array *sk, struct byte_array *pk)
{
	(void)seed; /* seed no longer used — callers pre-fill sk->ptr */

	if (alg == X25519) {
		if (sk->len < 32 || pk->len < 32)
			return buffer_to_small;
		/* sk->ptr pre-filled with 32 bytes of CSPRNG output; apply clamping */
		sk->ptr[0] &= 0xf8;
		sk->ptr[31] &= 0x7f;
		sk->ptr[31] |= 0x40;
#if _SUITE_USES_X25519
		{
			static const uint8_t base[32] = { 9 };
			curve25519_donna(pk->ptr, sk->ptr, base);
			pk->len = 32;
			sk->len = 32;
			return ok;
		}
#else
		return unsupported_ecdh_curve;
#endif
	}

#if _SUITE_USES_P256
	if (alg == P256) {
		if (sk->len < 32 || pk->len < 32)
			return buffer_to_small;
		ecc_key key;
		byte pub33[33];
		word32 pub_len = sizeof(pub33);
		word32 sk_len = 32;
		/* sk->ptr is pre-filled with 32 bytes of CSPRNG output by the caller.
		 * wc_ecc_make_key_ex is avoided: sp_ecc_make_key_256 is dead-code-
		 * eliminated by LTO, falling back to the heap-alloc generic path which
		 * fails on bare-metal.  Instead, import the private key and derive the
		 * public key via wc_ecc_make_pub, which uses sp_ecc_mulmod_base_256. */
		int ret = wc_ecc_init(&key);
		if (ret == 0) ret = wc_ecc_import_private_key_ex(
			sk->ptr, 32, NULL, 0, &key, ECC_SECP256R1);
		if (ret == 0) ret = wc_ecc_make_pub(&key, NULL);
		if (ret == 0) ret = ecc_even_y(&key, p256n, 32, pub33, &pub_len);
		if (ret == 0) ret = wc_ecc_export_private_only(&key, sk->ptr,
							 &sk_len);
		sk->len = (uint32_t)sk_len;
		if (ret != 0 || pub_len != 33) {
			wc_ecc_free(&key);
			return unexpected_result_from_ext_lib;
		}
		memcpy(pk->ptr, pub33 + 1, 32);
		pk->len = 32;
		wc_ecc_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_P256 */
#if _SUITE_USES_P384
	if (alg == P384) {
		/* sk->ptr pre-filled with 48 bytes of CSPRNG output by caller. */
		ecc_key key;
		byte pub97[97];
		word32 pub_len = sizeof(pub97);
		word32 sk_len = 48;
		int r384;
		wc_ecc_init(&key);
		r384 = wc_ecc_import_private_key_ex(sk->ptr, 48, NULL, 0,
						    &key, ECC_SECP384R1);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_keygen_import)", 0);
			wc_ecc_free(&key);
			return unexpected_result_from_ext_lib;
		}
		r384 = wc_ecc_make_pub(&key, NULL);
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_make_pub)", 0);
			wc_ecc_free(&key);
			return unexpected_result_from_ext_lib;
		}
		r384 = ecc_even_y(&key, p384n, 48, pub97, &pub_len);
		wc_ecc_export_private_only(&key, sk->ptr, &sk_len);
		sk->len = (uint32_t)sk_len;
		if (r384 != 0) {
			handle_external_runtime_error(r384, "crypto_wrapper.c(p384_export_pub)", 0);
			wc_ecc_free(&key);
			return unexpected_result_from_ext_lib;
		}
		memcpy(pk->ptr, pub97 + 1, 48);
		pk->len = 48;
		wc_ecc_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_P384 */
#if _SUITE_USES_X448
	if (alg == X448) {
		if (sk->len < 56 || pk->len < 56)
			return buffer_to_small;
		/* sk->ptr pre-filled with 56 bytes of CSPRNG output by caller.
		 * Apply RFC 7748 §5 clamping so the keygen result matches what
		 * wc_curve448_import_private_ex produces during shared-secret derive. */
		sk->ptr[0]  &= 0xfc;
		sk->ptr[55] |= 0x80;
		curve448_key key;
		word32 pk_len = 56;
		int ret = wc_curve448_init(&key);
		if (ret == 0) ret = wc_curve448_import_private_ex(
			sk->ptr, 56, &key, EC448_LITTLE_ENDIAN);
		if (ret == 0) ret = wc_curve448_export_public_ex(
			&key, pk->ptr, &pk_len, EC448_LITTLE_ENDIAN);
		if (ret != 0 || pk_len != 56) {
			wc_curve448_free(&key);
			return unexpected_result_from_ext_lib;
		}
		sk->len = 56;
		pk->len = (uint32_t)pk_len;
		wc_curve448_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_X448 */
	return unsupported_ecdh_curve;
}

enum err WEAK sign_key_gen(enum sign_alg alg, const uint8_t *seed,
			   struct byte_array *sk, struct byte_array *pk)
{

#if _SUITE_USES_ED25519
	if (alg == EdDSA) {
		/* sk = seed || public key (64 bytes), pk = public key. Monocypher
		 * wipes the seed it is given, so hand it a copy. */
		uint8_t s32[32];
		memcpy(s32, seed, 32);
		crypto_ed25519_key_pair(sk->ptr, pk->ptr, s32);
		sk->len = 64;
		pk->len = 32;
		return ok;
	}
#endif /* _SUITE_USES_ED25519 */
#if _SUITE_USES_ES256
	if (alg == ES256) {
		ecc_key key;
		byte pub33[33];
		word32 pub_len = sizeof(pub33);
		word32 sk_len = 32;
		wc_ecc_init(&key);
		wc_ecc_import_private_key_ex(seed, 32, NULL, 0,
					     &key, ECC_SECP256R1);
		wc_ecc_make_pub(&key, NULL);
		ecc_even_y(&key, p256n, 32, pub33, &pub_len);
		wc_ecc_export_private_only(&key, sk->ptr, &sk_len);
		sk->len = (uint32_t)sk_len;
		memcpy(pk->ptr, pub33 + 1, 32);
		pk->len = 32;
		wc_ecc_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_ES256 */
#if _SUITE_USES_P384
	if (alg == ES384) {
		ecc_key key;
		byte pub97[97];
		word32 pub_len = sizeof(pub97);
		word32 sk_len = 48;
		wc_ecc_init(&key);
		wc_ecc_import_private_key_ex(seed, 48, NULL, 0,
					     &key, ECC_SECP384R1);
		wc_ecc_make_pub(&key, NULL);
		ecc_even_y(&key, p384n, 48, pub97, &pub_len);
		wc_ecc_export_private_only(&key, sk->ptr, &sk_len);
		sk->len = (uint32_t)sk_len;
		memcpy(pk->ptr, pub97 + 1, 48);
		pk->len = 48;
		wc_ecc_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_P384 */
#if _SUITE_USES_X448 && defined(HAVE_ED448)
	if (alg == Ed448) {
		ed448_key key;
		word32 pk_len = 57;
		wc_ed448_init(&key);
		wc_ed448_import_private_only(seed, 57, &key);
		wc_ed448_make_public(&key, pk->ptr, pk_len);
		memcpy(sk->ptr, seed, 57);
		sk->len = 57;
		pk->len = (uint32_t)pk_len;
		wc_ed448_free(&key);
		return ok;
	}
#endif /* _SUITE_USES_X448 && HAVE_ED448 */
	return crypto_operation_not_implemented;
}

enum err WEAK hash(enum hash_alg alg, const struct byte_array *in,
		   struct byte_array *out)
{
	if (alg == SHA_256) {
		sha256_hash(in->ptr, in->len, out->ptr);
		out->len = SHA256_LEN;
		return ok;
	}
#if EDHOC_CRYPTO_SUITE == 24
	if (alg == SHA_384) {
		sha384_hash(in->ptr, in->len, out->ptr);
		out->len = SHA384_LEN;
		return ok;
	}
#endif
#if EDHOC_CRYPTO_SUITE == 25
	if (alg == SHAKE_256) {
		wc_Shake256Hash(in->ptr, in->len, out->ptr, 64);
		out->len = 64;
		return ok;
	}
#endif /* EDHOC_CRYPTO_SUITE == 25 */
	return crypto_operation_not_implemented;
}
