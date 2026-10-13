/*
 * authkem_initiator.c — EDHOC Method-5 initiator, authkem-01 five-message flow.
 * draft-ietf-lake-authkem-edhoc-01, cipher suite TBD2 of
 * draft-ietf-lake-pqsuites-01.
 *
 * Message flow (initiator side):
 *   tx(msg1) -> rx(msg2) -> tx(msg3) -> rx(msg4_KEM) -> tx(msg5_KEM)
 *
 * Context field mapping (reuses struct edhoc_initiator_context):
 *   x        = ephemeral KEM decapsulation key, generated here
 *   g_x      = ephemeral KEM encapsulation key: set here to point into x,
 *              which already holds it (FIPS 203: dk = dk_PKE || ek || H(ek) || z)
 *   i / g_i  = initiator static KEM key pair (authentication)
 *   id_cred_i / cred_i = initiator credential
 *
 * The responder's static KEM key is not known in advance: it arrives as
 * ID_CRED_R inside message 2 and is resolved against cred_r_array. That is
 * what forces the extra round trip.
 *
 * RAM. On a 64 kB scratchpad the stack peak is the KEM decapsulation of
 * message_2 and message_4_KEM, ~13 kB inside ML-KEM itself, so whatever this
 * file keeps live underneath it decides whether the image fits:
 *  - each decapsulation runs in its own small noinline frame and the work after
 *    it in another, so no post-processing buffer sits under the KEM;
 *  - KEM ciphertexts and AEAD ciphertexts are read from and written to the
 *    message buffer in place (authkem_msg_kem_split / authkem_msg_kem_open);
 *  - CRED_R and pk_R are views of the caller's credential list, not copies;
 *  - transcript hashes and MACs are streamed (th.c, authkem_mac), so the
 *    ~1.7 kB TH input and ~1 kB MAC context are never assembled;
 *  - the static and ephemeral secret keys are used where they are.
 *
 * EAD_4 is taken from message 4 when present; EAD_5 is supplied by the
 * initiator context.
 */
#include <string.h>
#include "secure_wipe.h"
#include "common/try_cleanup.h"

#include "edhoc.h"
#include "edhoc_internal.h"

#include "edhoc/authkem_messages.h"
#include "edhoc/authkem_plaintext.h"
#include "edhoc/edhoc_error_msg.h"
#include "edhoc/associated_data_encode.h"
#include "edhoc/buffer_sizes.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"
#include "edhoc/prk.h"
#include "edhoc/retrieve_cred.h"
#include "edhoc/runtime_context.h"
#include "edhoc/suites.h"
#include "edhoc/th.h"

#include "common/crypto_wrapper.h"
#include "common/memcpy_s.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

/* Offset of ek inside an ML-KEM decapsulation key (FIPS 203 Algorithm 16):
 * dk = dk_PKE || ek || H(ek) || z, with H(ek) and z 32 bytes each. */
#define MLKEM_DK_EK_OFFSET (KEM_SK_SIZE - KEM_PK_SIZE - 64)

/* TIMING=1: compute time of each message step, see perf.h. */
#ifdef TIMING_BREAKDOWN
#include "perf.h"
#else
#define PERF_TIME(label, stmt) stmt
#endif

/* Fixed-length compare for MAC verification, without an early exit. */
static enum err mac_equal(const struct byte_array *a,
			  const struct byte_array *b)
{
	if (a->len != b->len)
		return mac_authentication_failed;
	uint8_t diff = 0;
	for (uint32_t i = 0; i < a->len; i++)
		diff = (uint8_t)(diff | (a->ptr[i] ^ b->ptr[i]));
	return diff ? mac_authentication_failed : ok;
}

/* -------------------------------------------------------------------------
 * Ephemeral key pair. The public key is not kept separately: g_x is pointed
 * at the copy inside the decapsulation key. The scratch public key exists only
 * for the key generation call, in a frame released before message 2.
 * ------------------------------------------------------------------------- */
__attribute__((noinline))
static enum err authkem_gen_eph_keypair(struct edhoc_initiator_context *c,
					struct runtime_context *rc)
{
	enum err r = ok;

	BYTE_ARRAY_NEW_C(pk_eph, KEM_PK_SIZE, KEM_PK_SIZE);
	TRY_CLEANUP(ephemeral_kem_key_gen(rc->suite.edhoc_ecdh, &c->x, &pk_eph));
	if (c->x.len != KEM_SK_SIZE ||
	    memcmp(c->x.ptr + MLKEM_DK_EK_OFFSET, pk_eph.ptr, KEM_PK_SIZE))
		FAIL_CLEANUP(unexpected_result_from_ext_lib);
	c->g_x.ptr = c->x.ptr + MLKEM_DK_EK_OFFSET;
	c->g_x.len = KEM_PK_SIZE;
cleanup:
	return r;
}

/* -------------------------------------------------------------------------
 * message_1: (METHOD, SUITES_I, pk_eph, C_I, ?EAD_1), sent in plaintext.
 * Section 5.1.2.
 * ------------------------------------------------------------------------- */
/* noinline: LTO otherwise inlines every message stage into
 * edhoc_*_run_authkem, so the local buffers of all five stages live in one
 * stack frame at once instead of being released between messages. */
__attribute__((noinline))
static enum err authkem_msg1_gen(const struct edhoc_initiator_context *c,
				 struct runtime_context *rc)
{
	int32_t method = (int32_t)c->method;

	rc->msg.len = sizeof(rc->msg_buf);
	TRY(authkem_msg1_encode(method, &c->suites_i, &c->g_x, &c->c_i,
				&c->ead_1, &rc->msg));
	/* H(message_1) feeds TH_2. */
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
	return ok;
}

/* -------------------------------------------------------------------------
 * message_2: (ct_eph_CIPHERTEXT_2). Section 5.2.3.
 * ------------------------------------------------------------------------- */
/* ss_eph = KEM.Decapsulate(ct_eph, sk_eph), ct_eph read in place. */
__attribute__((noinline))
static enum err authkem_msg2_decap(const struct edhoc_initiator_context *c,
				   struct runtime_context *rc,
				   struct byte_array *ss_eph)
{
	struct byte_array ct_eph, ctxt2;

	TRY(authkem_msg_kem_split(&rc->msg, KEM_CT_SIZE, &ct_eph, &ctxt2));
	return kem_decapsulate(rc->suite.edhoc_ecdh, &ct_eph, &c->x, ss_eph);
}

/* TH_2 and PRK_2e, undo the KEYSTREAM_2 XOR, decode PLAINTEXT_2, resolve
 * CRED_R and pk_R (views of cred_r_array). */
__attribute__((noinline))
static enum err authkem_msg2_process(struct runtime_context *rc,
				     struct cred_array *cred_r_array,
				     struct byte_array *ss_eph,
				     uint8_t prk_2e[PRK_SIZE],
				     struct byte_array *th2,
				     struct byte_array *c_r_out,
				     struct byte_array *id_cred_r_out,
				     struct byte_array *cred_r,
				     struct byte_array *pk_r,
				     struct byte_array *ptxt2)
{
	struct byte_array ct_eph, ctxt2;

	TRY(authkem_msg_kem_split(&rc->msg, KEM_CT_SIZE, &ct_eph, &ctxt2));
	if (ctxt2.len > ptxt2->len)
		return cbor_decoding_error;

	/* TH_2 = H(H(message_1), ct_eph) -- sections 5.2.2, 5.2.3. */
	TRY(authkem_th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &ct_eph,
				  th2));

	/* PRK_2e = EDHOC_Extract(TH_2, ss_eph) -- section 4.1.1.1. */
	TRY(authkem_prk_extract(rc->suite, 0, th2, &NULL_ARRAY, ss_eph, prk_2e,
				true));

	/* PLAINTEXT_2 = CIPHERTEXT_2 XOR KEYSTREAM_2: the keystream is derived
	 * into the plaintext buffer and the ciphertext XORed in place. */
	struct byte_array prk_2e_ba = BYTE_ARRAY_INIT(prk_2e, PRK_SIZE);
	ptxt2->len = ctxt2.len;
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &prk_2e_ba, KEYSTREAM_2, th2, ptxt2));
	for (uint32_t i = 0; i < ctxt2.len; i++)
		ptxt2->ptr[i] ^= ctxt2.ptr[i];

	/* PLAINTEXT_2 = (C_R, ID_CRED_R, ?EAD_2). */
	BYTE_ARRAY_NEW(ead2, EAD_SIZE + 8, EAD_SIZE + 8);
	TRY(authkem_plaintext2_decode(ptxt2, c_r_out, id_cred_r_out, &ead2));
	if (ead2.len) {
		TRY(_memcpy_s(rc->ead.ptr, rc->ead.len, ead2.ptr, ead2.len));
		rc->ead.len = ead2.len;
	} else {
		rc->ead.len = 0;
	}

	/* CRED_R and the Responder's static KEM key -- section 5.2.3 step 9. */
	return authkem_cred_lookup(cred_r_array, id_cred_r_out, cred_r, pk_r);
}

/* -------------------------------------------------------------------------
 * message_3: (ct_R_CIPHERTEXT_3). Encapsulate to the responder's static key,
 * derive TH_3 and PRK_3e2m, encrypt PLAINTEXT_3. Sections 5.2.3, 5.3.2.
 * ------------------------------------------------------------------------- */
__attribute__((noinline))
static enum err authkem_msg3_gen(const struct edhoc_initiator_context *c,
				 struct runtime_context *rc,
				 const uint8_t prk_2e[PRK_SIZE],
				 struct byte_array *th2,
				 struct byte_array *ptxt2,
				 const struct byte_array *cred_r,
				 const struct byte_array *pk_r,
				 uint8_t prk_3e2m[PRK_SIZE],
				 struct byte_array *th3,
				 struct byte_array *ptxt3)
{
	enum err r = ok;
	uint32_t tag_len = get_aead_mac_len(rc->suite.edhoc_aead);
	struct byte_array ct_R, ctxt3;

	/* PLAINTEXT_3 = (C_I, ID_CRED_I, ?EAD_3); its length fixes the layout
	 * of the message, so it is encoded first. */
	TRY_CLEANUP(authkem_plaintext3_encode(&c->c_i, &c->id_cred_i, &c->ead_3,
					      ptxt3));

	/* message_3 = ( ct_R_CIPHERTEXT_3 : bstr ), filled in place. */
	rc->msg.len = sizeof(rc->msg_buf);
	TRY_CLEANUP(authkem_msg_kem_open(&rc->msg, KEM_CT_SIZE,
					 ptxt3->len + tag_len, &ct_R, &ctxt3));

	/* ss_R, ct_R = KEM.Encapsulate(pk_R) -- section 4.1.1.2. */
	BYTE_ARRAY_NEW_C(ss_R, KEM_SECRET_SIZE, KEM_SECRET_SIZE);
	TRY_CLEANUP(kem_encapsulate(rc->suite.edhoc_ecdh, pk_r, &ct_R, &ss_R));

	/* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R, ct_R) -- section 5.3.3. */
	TRY_CLEANUP(authkem_th_calculate(rc->suite.edhoc_hash, th2, ptxt2, cred_r,
					 &ct_R, th3));

	/* SALT_3e2m = EDHOC_KDF(PRK_2e, 1, TH_3); PRK_3e2m =
	 * EDHOC_Extract(SALT_3e2m, ss_R). TH_3 per section 4.1.2 and Figure 3,
	 * "the latest available transcript hash"; the KDF table in the same
	 * section still shows TH_2, a leftover from -00. */
	struct byte_array prk_2e_ba = BYTE_ARRAY_INIT((uint8_t *)prk_2e, PRK_SIZE);
	TRY_CLEANUP(authkem_prk_extract(rc->suite, SALT_3e2m, th3, &prk_2e_ba,
					&ss_R, prk_3e2m, false));

	/* K_3 / IV_3 from PRK_3e2m with TH_3 -- section 4.1.2. */
	struct byte_array prk_3e2m_ba = BYTE_ARRAY_INIT(prk_3e2m, PRK_SIZE);
	BYTE_ARRAY_NEW_C(k3, 32, get_aead_key_len(rc->suite.edhoc_aead));
	BYTE_ARRAY_NEW_C(iv3, AEAD_IV_SIZE, get_aead_iv_len(rc->suite.edhoc_aead));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_3e2m_ba, K_3, th3, &k3));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_3e2m_ba, IV_3, th3, &iv3));

	/* COSE_Encrypt0, protected h'', external_aad TH_3, ciphertext and tag
	 * written straight into the message. */
	BYTE_ARRAY_NEW_C(aad3, AAD_SIZE, AAD_SIZE);
	TRY_CLEANUP(associated_data_encode(th3, &aad3));
	struct byte_array ct3 = { .ptr = ctxt3.ptr, .len = ptxt3->len };
	struct byte_array tag3 = { .ptr = ctxt3.ptr + ptxt3->len, .len = tag_len };
	TRY_CLEANUP(aead(ENCRYPT, ptxt3, &k3, &iv3, &aad3, &ct3, &tag3));

cleanup:
	edhoc_wipe(ss_R_buf, sizeof(ss_R_buf));
	edhoc_wipe(k3_buf, sizeof(k3_buf));
	edhoc_wipe(iv3_buf, sizeof(iv3_buf));
	return r;
}

/* -------------------------------------------------------------------------
 * message_4_KEM: (ct_I_CIPHERTEXT_4). Section 5.4.3.
 * ------------------------------------------------------------------------- */
/* ss_I = KEM.Decapsulate(ct_I, sk_I), ct_I read in place. */
__attribute__((noinline))
static enum err authkem_msg4_decap(const struct edhoc_initiator_context *c,
				   struct runtime_context *rc,
				   struct byte_array *ss_I)
{
	struct byte_array ct_I, ctxt4;

	TRY(authkem_msg_kem_split(&rc->msg, KEM_CT_SIZE, &ct_I, &ctxt4));
	return kem_decapsulate(rc->suite.edhoc_ecdh, &ct_I, &c->i, ss_I);
}

/* TH_4, PRK_4e3m, decrypt PLAINTEXT_4, verify MAC_2. */
__attribute__((noinline))
static enum err authkem_msg4_process(const struct edhoc_initiator_context *c,
				     struct runtime_context *rc,
				     struct byte_array *ss_I,
				     const uint8_t prk_3e2m[PRK_SIZE],
				     struct byte_array *th3,
				     struct byte_array *ptxt3,
				     struct byte_array *c_r,
				     struct byte_array *id_cred_r,
				     const struct byte_array *cred_r,
				     uint8_t prk_4e3m[PRK_SIZE],
				     struct byte_array *th4,
				     struct byte_array *ptxt4)
{
	enum err r = ok;
	uint32_t mac_len = rc->suite.edhoc_mac_len_static_dh;
	uint32_t tag_len = get_aead_mac_len(rc->suite.edhoc_aead);
	struct byte_array ct_I, ctxt4;

	TRY_CLEANUP(authkem_msg_kem_split(&rc->msg, KEM_CT_SIZE, &ct_I, &ctxt4));
	if (ctxt4.len < tag_len || ctxt4.len - tag_len > ptxt4->len)
		FAIL_CLEANUP(cbor_decoding_error);

	/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I, ct_I) -- section 5.4.2. */
	TRY_CLEANUP(authkem_th_calculate(rc->suite.edhoc_hash, th3, ptxt3,
					 &c->cred_i, &ct_I, th4));

	/* SALT_4e3m = EDHOC_KDF(PRK_3e2m, 5, TH_4); PRK_4e3m =
	 * EDHOC_Extract(SALT_4e3m, ss_I) -- section 4.1.1.3. */
	struct byte_array prk_3e2m_ba = BYTE_ARRAY_INIT((uint8_t *)prk_3e2m, PRK_SIZE);
	TRY_CLEANUP(authkem_prk_extract(rc->suite, SALT_4e3m, th4, &prk_3e2m_ba,
					ss_I, prk_4e3m, false));

	/* K_4 / IV_4 from PRK_4e3m with TH_4 -- section 4.1.2. */
	struct byte_array prk_4e3m_ba = BYTE_ARRAY_INIT(prk_4e3m, PRK_SIZE);
	BYTE_ARRAY_NEW_C(k4, 32, get_aead_key_len(rc->suite.edhoc_aead));
	BYTE_ARRAY_NEW_C(iv4, AEAD_IV_SIZE, get_aead_iv_len(rc->suite.edhoc_aead));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, K_4, th4, &k4));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, IV_4, th4, &iv4));

	BYTE_ARRAY_NEW_C(aad4, AAD_SIZE, AAD_SIZE);
	TRY_CLEANUP(associated_data_encode(th4, &aad4));
	ptxt4->len = ctxt4.len - tag_len;
	struct byte_array tag4 = { .ptr = ctxt4.ptr + ptxt4->len, .len = tag_len };
	TRY_CLEANUP(aead(DECRYPT, &ctxt4, &k4, &iv4, &aad4, ptxt4, &tag4));

	/* PLAINTEXT_4 = (MAC_2, ?EAD_4). */
	BYTE_ARRAY_NEW_C(mac_2_recv, MAC_SIZE, MAC_SIZE);
	BYTE_ARRAY_NEW_C(ead4, EAD_SIZE + 8, EAD_SIZE + 8);
	TRY_CLEANUP(authkem_plaintext45_decode(ptxt4, &mac_2_recv, &ead4));
	if (ead4.len) {
		TRY_CLEANUP(_memcpy_s(rc->ead.ptr, rc->ead.len, ead4.ptr, ead4.len));
		rc->ead.len = ead4.len;
	} else {
		rc->ead.len = 0;
	}

	/* MAC_2 = EDHOC_KDF(PRK_3e2m, 2, context_2, mac_length_2) with
	 * context_2 = << C_R, ID_CRED_R, TH_4, CRED_R, ?EAD_4 >> -- 5.4.2. */
	BYTE_ARRAY_NEW_C(mac_2_calc, MAC_SIZE, mac_len);
	TRY_CLEANUP(authkem_mac(rc->suite.edhoc_hash, &prk_3e2m_ba, MAC_2, c_r,
				id_cred_r, th4, cred_r, &ead4, &mac_2_calc));
	PRINT_ARRAY("authkem I MAC_2 recv", mac_2_recv.ptr, mac_2_recv.len);
	PRINT_ARRAY("authkem I MAC_2 calc", mac_2_calc.ptr, mac_2_calc.len);
	TRY_CLEANUP(mac_equal(&mac_2_recv, &mac_2_calc));
	PRINT_MSG("authkem I MAC_2 OK\n");

cleanup:
	edhoc_wipe(k4_buf, sizeof(k4_buf));
	edhoc_wipe(iv4_buf, sizeof(iv4_buf));
	return r;
}

/* -------------------------------------------------------------------------
 * message_5_KEM: (CIPHERTEXT_5). TH_5, MAC_3 over context_3, encrypted under
 * K_5 / IV_5; then PRK_out. Section 5.5.2.
 * ------------------------------------------------------------------------- */
__attribute__((noinline))
static enum err authkem_msg5_gen(const struct edhoc_initiator_context *c,
				 struct runtime_context *rc,
				 const uint8_t prk_4e3m[PRK_SIZE],
				 struct byte_array *th4,
				 struct byte_array *ptxt4,
				 struct byte_array *prk_out)
{
	enum err r = ok;
	uint32_t mac_len = rc->suite.edhoc_mac_len_static_dh;
	uint32_t tag_len = get_aead_mac_len(rc->suite.edhoc_aead);
	struct byte_array ctxt5, none;

	/* TH_5 = H(TH_4, PLAINTEXT_4) -- no ciphertext and no credential. */
	BYTE_ARRAY_NEW_C(th5, HASH_SIZE, HASH_SIZE);
	TRY_CLEANUP(authkem_th_calculate(rc->suite.edhoc_hash, th4, ptxt4, NULL,
					 NULL, &th5));

	/* MAC_3 = EDHOC_KDF(PRK_4e3m, 6, context_3, mac_length_3) with
	 * context_3 = << C_I, ID_CRED_I, TH_5, CRED_I, ?EAD_5 >>. */
	struct byte_array prk_4e3m_ba = BYTE_ARRAY_INIT((uint8_t *)prk_4e3m, PRK_SIZE);
	BYTE_ARRAY_NEW_C(mac_3, MAC_SIZE, mac_len);
	TRY_CLEANUP(authkem_mac(rc->suite.edhoc_hash, &prk_4e3m_ba, MAC_3, &c->c_i,
				&c->id_cred_i, &th5, &c->cred_i, &c->ead_5,
				&mac_3));

	/* PLAINTEXT_5 = (MAC_3, ?EAD_5). */
	BYTE_ARRAY_NEW_C(ptxt5, AUTHKEM_PLAINTEXT5_SIZE, AUTHKEM_PLAINTEXT5_SIZE);
	TRY_CLEANUP(authkem_plaintext45_encode(&mac_3, &c->ead_5, &ptxt5));

	/* K_5 / IV_5 = EDHOC_KDF(PRK_4e3m, 11 / 12, TH_5) -- section 4.1.2. */
	BYTE_ARRAY_NEW_C(k5, 32, get_aead_key_len(rc->suite.edhoc_aead));
	BYTE_ARRAY_NEW_C(iv5, AEAD_IV_SIZE, get_aead_iv_len(rc->suite.edhoc_aead));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, K_5, &th5, &k5));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, IV_5, &th5, &iv5));

	BYTE_ARRAY_NEW_C(aad5, AAD_SIZE, AAD_SIZE);
	TRY_CLEANUP(associated_data_encode(&th5, &aad5));
	rc->msg.len = sizeof(rc->msg_buf);
	TRY_CLEANUP(authkem_msg_kem_open(&rc->msg, 0, ptxt5.len + tag_len, &none,
					 &ctxt5));
	struct byte_array ct5 = { .ptr = ctxt5.ptr, .len = ptxt5.len };
	struct byte_array tag5 = { .ptr = ctxt5.ptr + ptxt5.len, .len = tag_len };
	TRY_CLEANUP(aead(ENCRYPT, &ptxt5, &k5, &iv5, &aad5, &ct5, &tag5));

	/* PRK_out = EDHOC_KDF(PRK_4e3m, 7, TH_5, hash_length) -- 4.1.3. */
	prk_out->len = get_hash_len(rc->suite.edhoc_hash);
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, PRK_out, &th5,
			      prk_out));
	PRINT_ARRAY("authkem I PRK_out", prk_out->ptr, prk_out->len);

cleanup:
	edhoc_wipe(mac_3_buf, sizeof(mac_3_buf));
	edhoc_wipe(k5_buf, sizeof(k5_buf));
	edhoc_wipe(iv5_buf, sizeof(iv5_buf));
	return r;
}

/* Build and transmit an RFC 9528 error after the peer exchange has begun.
 * An initiator has no suites_r value to include, so its local failures map to
 * either Unknown Credential or an Unspecified Error.
 *
 * noinline: the MSG_MAX_SIZE buffer must not join the frame of the run
 * function, which stays live underneath every KEM call. */
__attribute__((noinline))
static enum err send_error(
	const struct edhoc_initiator_context *c, struct byte_array *err_msg,
	enum err internal,
	enum err (*tx)(void *sock, struct byte_array *data))
{
	int wire = edhoc_map_to_wire_err_code(internal);
	uint8_t buf[MSG_MAX_SIZE];
	uint32_t buf_len = 0;
	enum err r;

	/* Wrong Selected Cipher Suite is only generated while a responder
	 * processes message_1 and requires SUITES_R as ERR_INFO. */
	if (wire == EDHOC_ERR_CODE_WRONG_CIPHER_SUITE)
		wire = EDHOC_ERR_CODE_UNSPECIFIED;

	if (wire == EDHOC_ERR_CODE_UNKNOWN_CRED) {
		r = edhoc_build_error_message(buf, sizeof(buf), wire, NULL, 0,
					      NULL, 0, &buf_len);
	} else {
		const char *diag = "EDHOC initiator processing error";
		r = edhoc_build_error_message(buf, sizeof(buf), wire, diag, 0,
					      NULL, 0, &buf_len);
	}
	if (r != ok)
		return internal;

	struct byte_array out = { .ptr = buf, .len = buf_len };
	(void)tx(c->sock, &out);
	if (err_msg && err_msg->ptr && err_msg->len >= buf_len) {
		memcpy(err_msg->ptr, buf, buf_len);
		err_msg->len = buf_len;
	}
	return internal;
}

static void store_received_error(const struct byte_array *msg,
				 struct byte_array *err_msg)
{
	if (!err_msg || !err_msg->ptr || err_msg->len < msg->len)
		return;
	memcpy(err_msg->ptr, msg->ptr, msg->len);
	err_msg->len = msg->len;
}

/* -------------------------------------------------------------------------
 * Public entry point
 * ------------------------------------------------------------------------- */
enum err edhoc_initiator_run_authkem(
	struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *c_r_bytes, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24))
{

	enum err r = ok;
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);
	enum err step;

	/* A suite byte holds the label as a signed 8-bit value, so the
	 * private-use labels -24..-21 survive the round trip. */
	TRY_CLEANUP(get_suite((enum suite_label)(int8_t)c->suites_i.ptr[c->suites_i.len - 1],
			      &rc.suite));

	/* Generate the ephemeral ML-KEM key pair; the decapsulation key stays
	 * in c->x for message 2. */
	TRY_CLEANUP(authkem_gen_eph_keypair(c, &rc));

	uint8_t prk_2e[PRK_SIZE] = { 0 };
	uint8_t prk_3e2m[PRK_SIZE] = { 0 };
	uint8_t prk_4e3m[PRK_SIZE] = { 0 };
	BYTE_ARRAY_NEW_C(ss, KEM_SECRET_SIZE, KEM_SECRET_SIZE); /* ss_eph, then ss_I */
	BYTE_ARRAY_NEW_C(th2, HASH_SIZE, HASH_SIZE);
	BYTE_ARRAY_NEW_C(th3, HASH_SIZE, HASH_SIZE);
	BYTE_ARRAY_NEW_C(th4, HASH_SIZE, HASH_SIZE);
	BYTE_ARRAY_NEW_C(id_cred_r, ID_CRED_R_SIZE, ID_CRED_R_SIZE);
	struct byte_array cred_r = NULL_ARRAY, pk_r = NULL_ARRAY;
	BYTE_ARRAY_NEW_C(ptxt2, AUTHKEM_PLAINTEXT2_SIZE, AUTHKEM_PLAINTEXT2_SIZE);
	BYTE_ARRAY_NEW_C(ptxt3, AUTHKEM_PLAINTEXT3_SIZE, AUTHKEM_PLAINTEXT3_SIZE);
	BYTE_ARRAY_NEW_C(ptxt4, AUTHKEM_PLAINTEXT4_SIZE, AUTHKEM_PLAINTEXT4_SIZE);

	/* tx(message_1) */
	PERF_TIME("msg1_build       ", TRY_CLEANUP(authkem_msg1_gen(c, &rc)));
	TRY_CLEANUP(tx(c->sock, &rc.msg));

	/* rx(message_2) */
	rc.msg.len = sizeof(rc.msg_buf);
	TRY_CLEANUP(rx(c->sock, &rc.msg));
	if (edhoc_is_error_message(rc.msg.ptr, rc.msg.len)) {
		store_received_error(&rc.msg, err_msg);
		FAIL_CLEANUP(error_message_received);
	}
	PERF_TIME("msg2_process     ", {
		step = authkem_msg2_decap(c, &rc, &ss);
		if (step == ok)
			step = authkem_msg2_process(&rc, cred_r_array, &ss, prk_2e,
						    &th2, c_r_bytes, &id_cred_r,
						    &cred_r, &pk_r, &ptxt2);
		/* Section 5.2.3 step 8: the application validates ID_CRED_R
		 * before the Initiator sends its own credential in message_3. */
		if (step == ok && c->id_cred_check)
			step = c->id_cred_check(c->params_id_cred_check, &id_cred_r);
	});
	edhoc_wipe(ss_buf, sizeof(ss_buf));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	step = ead_process(c->params_ead_process, &rc.ead);
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}

	/* tx(message_3) */
	PERF_TIME("msg3_build       ",
		  step = authkem_msg3_gen(c, &rc, prk_2e, &th2, &ptxt2, &cred_r,
					  &pk_r, prk_3e2m, &th3, &ptxt3));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	TRY_CLEANUP(tx(c->sock, &rc.msg));

	/* rx(message_4_KEM): authenticates the Responder. */
	rc.msg.len = sizeof(rc.msg_buf);
	TRY_CLEANUP(rx(c->sock, &rc.msg));
	if (edhoc_is_error_message(rc.msg.ptr, rc.msg.len)) {
		store_received_error(&rc.msg, err_msg);
		FAIL_CLEANUP(error_message_received);
	}
	ss.len = KEM_SECRET_SIZE;
	PERF_TIME("msg4_process     ", {
		step = authkem_msg4_decap(c, &rc, &ss);
		if (step == ok)
			step = authkem_msg4_process(c, &rc, &ss, prk_3e2m, &th3,
						    &ptxt3, c_r_bytes, &id_cred_r,
						    &cred_r, prk_4e3m, &th4,
						    &ptxt4);
	});
	edhoc_wipe(ss_buf, sizeof(ss_buf));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	step = ead_process(c->params_ead_process, &rc.ead);
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}

	/* tx(message_5_KEM): authenticates the Initiator; yields PRK_out. */
	PERF_TIME("msg5_build       ",
		  step = authkem_msg5_gen(c, &rc, prk_4e3m, &th4, &ptxt4, prk_out));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	TRY_CLEANUP(tx(c->sock, &rc.msg));

	/* Only PRK_out, the caller's output, should survive the handshake.
	 * Reached on every path, including the send_error and
	 * error_message_received exits, so a failed run leaves no more key
	 * material behind than a successful one. The ephemeral decapsulation
	 * key in c->x is the caller's buffer, so the caller wipes that one. */
cleanup:
	edhoc_wipe(prk_2e, sizeof(prk_2e));
	edhoc_wipe(prk_3e2m, sizeof(prk_3e2m));
	edhoc_wipe(prk_4e3m, sizeof(prk_4e3m));
	edhoc_wipe(ss_buf, sizeof(ss_buf));
	return r;
}
