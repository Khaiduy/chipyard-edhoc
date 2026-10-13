/*
 * authkem_responder.c — EDHOC Method-5 responder, authkem-01 five-message flow.
 * draft-ietf-lake-authkem-edhoc-01, cipher suite TBD2 of
 * draft-ietf-lake-pqsuites-01.
 *
 * Message flow (responder side):
 *   rx(msg1) -> tx(msg2) -> rx(msg3) -> tx(msg4_KEM) -> rx(msg5_KEM)
 *
 * Context field mapping (reuses struct edhoc_responder_context):
 *   g_r / r  = responder static KEM pk / sk (authentication)
 *   id_cred_r / cred_r = responder credential
 *
 * The responder generates no ephemeral key pair of its own: it encapsulates
 * to the initiator's pk_eph from message 1. It cannot authenticate until
 * message 3 delivers ct_R, which is why MAC_2 travels in message 4.
 *
 * RAM: the same layout as authkem_initiator.c -- the decapsulation of
 * message_3 runs in its own small frame with the work after it in another,
 * ciphertexts are read and written in place in the message buffer, CRED_I
 * and pk_I are views of the caller's credential list, and transcript hashes
 * and MACs are streamed.
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
#include "cbor.h"
#include "common/memcpy_s.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

#ifdef TIMING_BREAKDOWN
#include "perf.h"
#else
#define PERF_TIME(label, stmt) stmt
#endif

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
 * message_1: decode and check METHOD and SUITES_I. Section 5.1.3.
 * pk_eph is returned as a view into the message buffer: it is consumed by
 * the encapsulation in message_2 before that buffer is reused.
 * ------------------------------------------------------------------------- */
/* noinline: LTO otherwise inlines every message stage into
 * edhoc_*_run_authkem, so the local buffers of all five stages live in one
 * stack frame at once instead of being released between messages. */
__attribute__((noinline))
static enum err authkem_msg1_process(struct edhoc_responder_context *c,
				     struct runtime_context *rc,
				     struct byte_array *pk_eph_out,
				     struct byte_array *c_i_out)
{
	int32_t method = 0;
	BYTE_ARRAY_NEW(suites_i, SUITES_I_SIZE, SUITES_I_SIZE);
	BYTE_ARRAY_NEW(ead1, EAD_SIZE + 8, EAD_SIZE + 8);
	TRY(authkem_msg1_decode(&rc->msg, &method, &suites_i, pk_eph_out, c_i_out,
				&ead1));
	if (ead1.len) {
		TRY(_memcpy_s(rc->ead.ptr, rc->ead.len, ead1.ptr, ead1.len));
		rc->ead.len = ead1.len;
	} else {
		rc->ead.len = 0;
	}

	if (method != INITIATOR_KEM_RESPONDER_KEM)
		return wrong_parameter;

	uint8_t suite = suites_i.ptr[suites_i.len - 1];
	/* The selected suite must be one this responder supports. */
	bool supported = false;
	for (uint32_t i = 0; i < c->suites_r.len; i++)
		if (c->suites_r.ptr[i] == suite)
			supported = true;
	if (!supported)
		return unsupported_cipher_suite;
	for (uint32_t i = 0; i + 1 < suites_i.len; i++)
		for (uint32_t j = 0; j < c->suites_r.len; j++)
			if (suites_i.ptr[i] == c->suites_r.ptr[j])
				return unsupported_cipher_suite;

	/* Suite bytes are signed (private-use labels are -24..-21). */
	TRY(get_suite((enum suite_label)(int8_t)suite, &rc->suite));

	/* H(message_1) feeds TH_2. */
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
	return ok;
}

/* -------------------------------------------------------------------------
 * message_2: (ct_eph_CIPHERTEXT_2). Encapsulate to pk_eph, derive TH_2 and
 * PRK_2e, XOR-encrypt PLAINTEXT_2. Sections 5.2.1, 5.2.2.
 *
 * ct_eph is staged in this frame rather than written straight into the
 * message: pk_eph is still being read from that same buffer. This is the
 * encapsulation, not the decapsulation, so it is not the deepest point.
 * ------------------------------------------------------------------------- */
__attribute__((noinline))
static enum err authkem_msg2_gen(struct edhoc_responder_context *c,
				 struct runtime_context *rc,
				 const struct byte_array *pk_eph,
				 uint8_t prk_2e[PRK_SIZE],
				 struct byte_array *th2,
				 struct byte_array *ptxt2)
{
	enum err r = ok;
	struct byte_array ct_view, ctxt2;

	/* ss_eph, ct_eph = KEM.Encapsulate(pk_eph) -- section 4.1.1.1. */
	BYTE_ARRAY_NEW_C(ss_eph, KEM_SECRET_SIZE, KEM_SECRET_SIZE);
	BYTE_ARRAY_NEW_C(ct_eph, KEM_CT_SIZE, KEM_CT_SIZE);
	TRY_CLEANUP(kem_encapsulate(rc->suite.edhoc_ecdh, pk_eph, &ct_eph, &ss_eph));

	/* TH_2 = H(H(message_1), ct_eph) -- section 5.2.2. */
	TRY_CLEANUP(authkem_th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash,
					  &ct_eph, th2));

	/* PRK_2e = EDHOC_Extract(TH_2, ss_eph) -- section 4.1.1.1. */
	TRY_CLEANUP(authkem_prk_extract(rc->suite, 0, th2, &NULL_ARRAY, &ss_eph,
					prk_2e, true));

	/* PLAINTEXT_2 = (C_R, ID_CRED_R, ?EAD_2). MAC_2 is not computed yet:
	 * ct_R has not arrived, so the responder cannot authenticate. */
	TRY_CLEANUP(authkem_plaintext2_encode(&c->c_r, &c->id_cred_r, &c->ead_2,
					      ptxt2));

	/* message_2 = ( ct_eph_CIPHERTEXT_2 : bstr ); pk_eph is not read after
	 * this point, so the message buffer can be overwritten. */
	rc->msg.len = sizeof(rc->msg_buf);
	TRY_CLEANUP(authkem_msg_kem_open(&rc->msg, KEM_CT_SIZE, ptxt2->len,
					 &ct_view, &ctxt2));
	memcpy(ct_view.ptr, ct_eph.ptr, KEM_CT_SIZE);

	/* CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2, the keystream derived
	 * straight into the message and the plaintext XORed in place. */
	struct byte_array prk_2e_ba = BYTE_ARRAY_INIT(prk_2e, PRK_SIZE);
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_2e_ba, KEYSTREAM_2, th2,
			      &ctxt2));
	for (uint32_t i = 0; i < ptxt2->len; i++)
		ctxt2.ptr[i] ^= ptxt2->ptr[i];

cleanup:
	edhoc_wipe(ss_eph_buf, sizeof(ss_eph_buf));
	return r;
}

/* -------------------------------------------------------------------------
 * message_3: (ct_R_CIPHERTEXT_3). Section 5.3.3.
 * ------------------------------------------------------------------------- */
/* ss_R = KEM.Decapsulate(ct_R, sk_R), ct_R read in place. */
__attribute__((noinline))
static enum err authkem_msg3_decap(struct edhoc_responder_context *c,
				   struct runtime_context *rc,
				   struct byte_array *ss_R)
{
	struct byte_array ct_R, ctxt3;

	TRY(authkem_msg_kem_split(&rc->msg, KEM_CT_SIZE, &ct_R, &ctxt3));
	return kem_decapsulate(rc->suite.edhoc_ecdh, &ct_R, &c->r, ss_R);
}

/* TH_3, PRK_3e2m, decrypt PLAINTEXT_3, resolve CRED_I and pk_I (views). */
__attribute__((noinline))
static enum err authkem_msg3_process(struct edhoc_responder_context *c,
				     struct runtime_context *rc,
				     struct cred_array *cred_i_array,
				     struct byte_array *ss_R,
				     const uint8_t prk_2e[PRK_SIZE],
				     struct byte_array *th2,
				     struct byte_array *ptxt2,
				     uint8_t prk_3e2m[PRK_SIZE],
				     struct byte_array *th3,
				     struct byte_array *c_i_out,
				     struct byte_array *id_cred_i_out,
				     struct byte_array *cred_i,
				     struct byte_array *pk_i,
				     struct byte_array *ptxt3)
{
	enum err r = ok;
	uint32_t tag_len = get_aead_mac_len(rc->suite.edhoc_aead);
	struct byte_array ct_R, ctxt3;

	TRY_CLEANUP(authkem_msg_kem_split(&rc->msg, KEM_CT_SIZE, &ct_R, &ctxt3));
	if (ctxt3.len < tag_len || ctxt3.len - tag_len > ptxt3->len)
		FAIL_CLEANUP(cbor_decoding_error);

	/* TH_3 = H(TH_2, PLAINTEXT_2, CRED_R, ct_R) -- section 5.3.3. */
	TRY_CLEANUP(authkem_th_calculate(rc->suite.edhoc_hash, th2, ptxt2,
					 &c->cred_r, &ct_R, th3));

	/* SALT_3e2m = EDHOC_KDF(PRK_2e, 1, TH_3); PRK_3e2m =
	 * EDHOC_Extract(SALT_3e2m, ss_R). TH_3 as in authkem_initiator.c. */
	struct byte_array prk_2e_ba = BYTE_ARRAY_INIT((uint8_t *)prk_2e, PRK_SIZE);
	TRY_CLEANUP(authkem_prk_extract(rc->suite, SALT_3e2m, th3, &prk_2e_ba,
					ss_R, prk_3e2m, false));

	/* K_3 / IV_3, then decrypt CIPHERTEXT_3 with external_aad = TH_3. */
	struct byte_array prk_3e2m_ba = BYTE_ARRAY_INIT(prk_3e2m, PRK_SIZE);
	BYTE_ARRAY_NEW_C(k3, 32, get_aead_key_len(rc->suite.edhoc_aead));
	BYTE_ARRAY_NEW_C(iv3, AEAD_IV_SIZE, get_aead_iv_len(rc->suite.edhoc_aead));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_3e2m_ba, K_3, th3, &k3));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_3e2m_ba, IV_3, th3, &iv3));

	BYTE_ARRAY_NEW_C(aad3, AAD_SIZE, AAD_SIZE);
	TRY_CLEANUP(associated_data_encode(th3, &aad3));
	ptxt3->len = ctxt3.len - tag_len;
	struct byte_array tag3 = { .ptr = ctxt3.ptr + ptxt3->len, .len = tag_len };
	TRY_CLEANUP(aead(DECRYPT, &ctxt3, &k3, &iv3, &aad3, ptxt3, &tag3));

	/* PLAINTEXT_3 = (C_I, ID_CRED_I, ?EAD_3). */
	BYTE_ARRAY_NEW_C(ead3, EAD_SIZE + 8, EAD_SIZE + 8);
	TRY_CLEANUP(authkem_plaintext3_decode(ptxt3, c_i_out, id_cred_i_out, &ead3));
	if (ead3.len) {
		TRY_CLEANUP(_memcpy_s(rc->ead.ptr, rc->ead.len, ead3.ptr, ead3.len));
		rc->ead.len = ead3.len;
	} else {
		rc->ead.len = 0;
	}

	/* ID_CRED_I to the application, then CRED_I and the Initiator's static
	 * KEM key -- section 5.3.3 steps 8 and 9. */
	if (c->id_cred_check)
		TRY_CLEANUP(c->id_cred_check(c->params_id_cred_check, id_cred_i_out));
	TRY_CLEANUP(authkem_cred_lookup(cred_i_array, id_cred_i_out, cred_i, pk_i));

cleanup:
	edhoc_wipe(k3_buf, sizeof(k3_buf));
	edhoc_wipe(iv3_buf, sizeof(iv3_buf));
	return r;
}

/* -------------------------------------------------------------------------
 * message_4_KEM: (ct_I_CIPHERTEXT_4). Encapsulate to pk_I straight into the
 * message, derive TH_4 and PRK_4e3m, emit MAC_2. Section 5.4.2.
 * ------------------------------------------------------------------------- */
__attribute__((noinline))
static enum err authkem_msg4_gen(struct edhoc_responder_context *c,
				 struct runtime_context *rc,
				 const uint8_t prk_3e2m[PRK_SIZE],
				 struct byte_array *th3,
				 struct byte_array *ptxt3,
				 const struct byte_array *cred_i,
				 const struct byte_array *pk_i,
				 uint8_t prk_4e3m[PRK_SIZE],
				 struct byte_array *th4,
				 struct byte_array *ptxt4)
{
	enum err r = ok;
	uint32_t mac_len = rc->suite.edhoc_mac_len_static_dh;
	uint32_t tag_len = get_aead_mac_len(rc->suite.edhoc_aead);
	struct byte_array ct_I, ctxt4;

	/* PLAINTEXT_4 = (MAC_2, ?EAD_4) has a known length before MAC_2 is
	 * known: a bstr of mac_len bytes followed by EAD_4. */
	uint8_t h[9];
	uint32_t ptxt4_len = cbor_head(h, 2, mac_len) + mac_len + c->ead_4.len;

	/* message_4_KEM = ( ct_I_CIPHERTEXT_4 : bstr ), filled in place. */
	rc->msg.len = sizeof(rc->msg_buf);
	TRY_CLEANUP(authkem_msg_kem_open(&rc->msg, KEM_CT_SIZE, ptxt4_len + tag_len,
					 &ct_I, &ctxt4));

	/* ss_I, ct_I = KEM.Encapsulate(pk_I) -- section 4.1.1.3. */
	BYTE_ARRAY_NEW_C(ss_I, KEM_SECRET_SIZE, KEM_SECRET_SIZE);
	TRY_CLEANUP(kem_encapsulate(rc->suite.edhoc_ecdh, pk_i, &ct_I, &ss_I));

	/* TH_4 = H(TH_3, PLAINTEXT_3, CRED_I, ct_I) -- section 5.4.2. */
	TRY_CLEANUP(authkem_th_calculate(rc->suite.edhoc_hash, th3, ptxt3, cred_i,
					 &ct_I, th4));

	/* MAC_2 = EDHOC_KDF(PRK_3e2m, 2, context_2, mac_length_2) with
	 * context_2 = << C_R, ID_CRED_R, TH_4, CRED_R, ?EAD_4 >>. */
	struct byte_array prk_3e2m_ba = BYTE_ARRAY_INIT((uint8_t *)prk_3e2m, PRK_SIZE);
	BYTE_ARRAY_NEW_C(mac_2, MAC_SIZE, mac_len);
	TRY_CLEANUP(authkem_mac(rc->suite.edhoc_hash, &prk_3e2m_ba, MAC_2, &c->c_r,
				&c->id_cred_r, th4, &c->cred_r, &c->ead_4,
				&mac_2));

	/* SALT_4e3m = EDHOC_KDF(PRK_3e2m, 5, TH_4); PRK_4e3m =
	 * EDHOC_Extract(SALT_4e3m, ss_I) -- section 4.1.1.3. */
	TRY_CLEANUP(authkem_prk_extract(rc->suite, SALT_4e3m, th4, &prk_3e2m_ba,
					&ss_I, prk_4e3m, false));

	/* K_4 / IV_4 from PRK_4e3m with TH_4 -- section 4.1.2. */
	struct byte_array prk_4e3m_ba = BYTE_ARRAY_INIT(prk_4e3m, PRK_SIZE);
	BYTE_ARRAY_NEW_C(k4, 32, get_aead_key_len(rc->suite.edhoc_aead));
	BYTE_ARRAY_NEW_C(iv4, AEAD_IV_SIZE, get_aead_iv_len(rc->suite.edhoc_aead));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, K_4, th4, &k4));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, IV_4, th4, &iv4));

	TRY_CLEANUP(authkem_plaintext45_encode(&mac_2, &c->ead_4, ptxt4));
	if (ptxt4->len != ptxt4_len)
		FAIL_CLEANUP(unexpected_result_from_ext_lib);

	BYTE_ARRAY_NEW_C(aad4, AAD_SIZE, AAD_SIZE);
	TRY_CLEANUP(associated_data_encode(th4, &aad4));
	struct byte_array ct4 = { .ptr = ctxt4.ptr, .len = ptxt4->len };
	struct byte_array tag4 = { .ptr = ctxt4.ptr + ptxt4->len, .len = tag_len };
	TRY_CLEANUP(aead(ENCRYPT, ptxt4, &k4, &iv4, &aad4, &ct4, &tag4));

cleanup:
	edhoc_wipe(ss_I_buf, sizeof(ss_I_buf));
	edhoc_wipe(mac_2_buf, sizeof(mac_2_buf));
	edhoc_wipe(k4_buf, sizeof(k4_buf));
	edhoc_wipe(iv4_buf, sizeof(iv4_buf));
	return r;
}

/* -------------------------------------------------------------------------
 * message_5_KEM: (CIPHERTEXT_5). Decrypt under K_5 / IV_5, verify MAC_3,
 * then derive PRK_out. Section 5.5.3.
 * ------------------------------------------------------------------------- */
__attribute__((noinline))
static enum err authkem_msg5_process(struct runtime_context *rc,
				     const uint8_t prk_4e3m[PRK_SIZE],
				     struct byte_array *th4,
				     struct byte_array *ptxt4,
				     struct byte_array *c_i,
				     struct byte_array *id_cred_i,
				     const struct byte_array *cred_i,
				     struct byte_array *prk_out)
{
	enum err r = ok;
	uint32_t mac_len = rc->suite.edhoc_mac_len_static_dh;
	uint32_t tag_len = get_aead_mac_len(rc->suite.edhoc_aead);
	struct byte_array none, ctxt5;

	TRY_CLEANUP(authkem_msg_kem_split(&rc->msg, 0, &none, &ctxt5));
	if (ctxt5.len < tag_len || ctxt5.len - tag_len > AUTHKEM_PLAINTEXT5_SIZE)
		FAIL_CLEANUP(cbor_decoding_error);

	/* TH_5 = H(TH_4, PLAINTEXT_4). */
	BYTE_ARRAY_NEW_C(th5, HASH_SIZE, HASH_SIZE);
	TRY_CLEANUP(authkem_th_calculate(rc->suite.edhoc_hash, th4, ptxt4, NULL,
					 NULL, &th5));

	/* K_5 / IV_5 = EDHOC_KDF(PRK_4e3m, 11 / 12, TH_5); external_aad TH_5. */
	struct byte_array prk_4e3m_ba = BYTE_ARRAY_INIT((uint8_t *)prk_4e3m, PRK_SIZE);
	BYTE_ARRAY_NEW_C(k5, 32, get_aead_key_len(rc->suite.edhoc_aead));
	BYTE_ARRAY_NEW_C(iv5, AEAD_IV_SIZE, get_aead_iv_len(rc->suite.edhoc_aead));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, K_5, &th5, &k5));
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, IV_5, &th5, &iv5));

	BYTE_ARRAY_NEW_C(aad5, AAD_SIZE, AAD_SIZE);
	TRY_CLEANUP(associated_data_encode(&th5, &aad5));
	BYTE_ARRAY_NEW_C(ptxt5, AUTHKEM_PLAINTEXT5_SIZE, ctxt5.len - tag_len);
	struct byte_array tag5 = { .ptr = ctxt5.ptr + ptxt5.len, .len = tag_len };
	TRY_CLEANUP(aead(DECRYPT, &ctxt5, &k5, &iv5, &aad5, &ptxt5, &tag5));

	/* PLAINTEXT_5 = (MAC_3, ?EAD_5). */
	BYTE_ARRAY_NEW_C(mac_3_recv, MAC_SIZE, MAC_SIZE);
	BYTE_ARRAY_NEW_C(ead5, EAD_SIZE + 8, EAD_SIZE + 8);
	TRY_CLEANUP(authkem_plaintext45_decode(&ptxt5, &mac_3_recv, &ead5));
	if (ead5.len) {
		TRY_CLEANUP(_memcpy_s(rc->ead.ptr, rc->ead.len, ead5.ptr, ead5.len));
		rc->ead.len = ead5.len;
	} else {
		rc->ead.len = 0;
	}

	/* MAC_3 = EDHOC_KDF(PRK_4e3m, 6, context_3, mac_length_3) with
	 * context_3 = << C_I, ID_CRED_I, TH_5, CRED_I, ?EAD_5 >> -- 5.5.2. */
	BYTE_ARRAY_NEW_C(mac_3_calc, MAC_SIZE, mac_len);
	TRY_CLEANUP(authkem_mac(rc->suite.edhoc_hash, &prk_4e3m_ba, MAC_3, c_i,
				id_cred_i, &th5, cred_i, &ead5, &mac_3_calc));
	PRINT_ARRAY("authkem R MAC_3 recv", mac_3_recv.ptr, mac_3_recv.len);
	PRINT_ARRAY("authkem R MAC_3 calc", mac_3_calc.ptr, mac_3_calc.len);
	TRY_CLEANUP(mac_equal(&mac_3_recv, &mac_3_calc));
	PRINT_MSG("authkem R MAC_3 OK\n");

	/* PRK_out = EDHOC_KDF(PRK_4e3m, 7, TH_5, hash_length) -- 4.1.3. */
	prk_out->len = get_hash_len(rc->suite.edhoc_hash);
	TRY_CLEANUP(edhoc_kdf(rc->suite.edhoc_hash, &prk_4e3m_ba, PRK_out, &th5,
			      prk_out));
	PRINT_ARRAY("authkem R PRK_out", prk_out->ptr, prk_out->len);

cleanup:
	edhoc_wipe(k5_buf, sizeof(k5_buf));
	edhoc_wipe(iv5_buf, sizeof(iv5_buf));
	edhoc_wipe(mac_3_recv_buf, sizeof(mac_3_recv_buf));
	edhoc_wipe(mac_3_calc_buf, sizeof(mac_3_calc_buf));
	return r;
}

/* Encode SUITES_R as the int-or-array CBOR value required as ERR_INFO for
 * Wrong Selected Cipher Suite (RFC 9528 Section 6). Suite bytes are signed. */
static uint32_t encode_suites_cbor(uint8_t *buf, uint32_t cap,
				   const struct byte_array *suites)
{
	if (cap < 1 || !suites || suites->len == 0)
		return 0;

	uint32_t pos = 0;
	if (suites->len > 1) {
		if (suites->len <= 23) {
			buf[pos++] = 0x80 | (uint8_t)suites->len;
		} else if (suites->len <= 0xff) {
			if (cap < 2)
				return 0;
			buf[pos++] = 0x98;
			buf[pos++] = (uint8_t)suites->len;
		} else {
			return 0;
		}
	}

	for (uint32_t i = 0; i < suites->len; i++) {
		int32_t suite = (int8_t)suites->ptr[i];
		uint8_t h[9];
		uint32_t n = suite >= 0 ? cbor_head(h, 0, (uint64_t)suite)
					: cbor_head(h, 1, (uint64_t)(-1 - suite));
		if (pos + n > cap)
			return 0;
		memcpy(buf + pos, h, n);
		pos += n;
	}
	return pos;
}

/* noinline: keeps the MSG_MAX_SIZE buffer out of the run frame, which stays
 * live underneath every KEM call. */
__attribute__((noinline))
static enum err send_error(
	struct edhoc_responder_context *c, struct byte_array *err_msg,
	enum err internal,
	enum err (*tx)(void *sock, struct byte_array *data))
{
	int wire = edhoc_map_to_wire_err_code(internal);
	uint8_t buf[MSG_MAX_SIZE];
	uint32_t buf_len = 0;
	enum err r;

	if (wire == EDHOC_ERR_CODE_WRONG_CIPHER_SUITE) {
		uint8_t info[2 * 255 + 2];
		uint32_t info_len = encode_suites_cbor(info, sizeof(info),
						       &c->suites_r);
		if (info_len == 0)
			return internal;
		r = edhoc_build_error_message(buf, sizeof(buf), wire, NULL, 0,
					      info, info_len, &buf_len);
	} else if (wire == EDHOC_ERR_CODE_UNKNOWN_CRED) {
		r = edhoc_build_error_message(buf, sizeof(buf), wire, NULL, 0,
					      NULL, 0, &buf_len);
	} else {
		const char *diag = "EDHOC responder processing error";
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
enum err edhoc_responder_run_authkem(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13))
{
	enum err r = ok;
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);
	enum err step;

	uint8_t prk_2e[PRK_SIZE] = { 0 };
	uint8_t prk_3e2m[PRK_SIZE] = { 0 };
	uint8_t prk_4e3m[PRK_SIZE] = { 0 };
	BYTE_ARRAY_NEW_C(ss_R, KEM_SECRET_SIZE, KEM_SECRET_SIZE);
	BYTE_ARRAY_NEW_C(th2, HASH_SIZE, HASH_SIZE);
	BYTE_ARRAY_NEW_C(th3, HASH_SIZE, HASH_SIZE);
	BYTE_ARRAY_NEW_C(th4, HASH_SIZE, HASH_SIZE);
	struct byte_array pk_eph = NULL_ARRAY;
	BYTE_ARRAY_NEW_C(c_i, C_I_SIZE + 8, C_I_SIZE + 8);
	BYTE_ARRAY_NEW_C(id_cred_i, ID_CRED_I_SIZE, ID_CRED_I_SIZE);
	struct byte_array cred_i = NULL_ARRAY, pk_i = NULL_ARRAY;
	BYTE_ARRAY_NEW_C(ptxt2, AUTHKEM_PLAINTEXT2_SIZE, AUTHKEM_PLAINTEXT2_SIZE);
	BYTE_ARRAY_NEW_C(ptxt3, AUTHKEM_PLAINTEXT3_SIZE, AUTHKEM_PLAINTEXT3_SIZE);
	BYTE_ARRAY_NEW_C(ptxt4, AUTHKEM_PLAINTEXT4_SIZE, AUTHKEM_PLAINTEXT4_SIZE);

	/* rx(message_1) */
	rc.msg.len = sizeof(rc.msg_buf);
	TRY_CLEANUP(rx(c->sock, &rc.msg));
	PERF_TIME("msg1_process     ",
		  step = authkem_msg1_process(c, &rc, &pk_eph, &c_i));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	step = ead_process(c->params_ead_process, &rc.ead);
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}

	/* tx(message_2) */
	PERF_TIME("msg2_build       ",
		  step = authkem_msg2_gen(c, &rc, &pk_eph, prk_2e, &th2, &ptxt2));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	TRY_CLEANUP(tx(c->sock, &rc.msg));

	/* rx(message_3) */
	rc.msg.len = sizeof(rc.msg_buf);
	TRY_CLEANUP(rx(c->sock, &rc.msg));
	if (edhoc_is_error_message(rc.msg.ptr, rc.msg.len)) {
		store_received_error(&rc.msg, err_msg);
		FAIL_CLEANUP(error_message_received);
	}
	PERF_TIME("msg3_process     ", {
		step = authkem_msg3_decap(c, &rc, &ss_R);
		if (step == ok)
			step = authkem_msg3_process(c, &rc, cred_i_array, &ss_R,
						    prk_2e, &th2, &ptxt2, prk_3e2m,
						    &th3, &c_i, &id_cred_i,
						    &cred_i, &pk_i, &ptxt3);
	});
	edhoc_wipe(ss_R_buf, sizeof(ss_R_buf));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	step = ead_process(c->params_ead_process, &rc.ead);
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}

	/* tx(message_4_KEM): carries MAC_2, authenticating the Responder. */
	PERF_TIME("msg4_build       ",
		  step = authkem_msg4_gen(c, &rc, prk_3e2m, &th3, &ptxt3, &cred_i,
					  &pk_i, prk_4e3m, &th4, &ptxt4));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	TRY_CLEANUP(tx(c->sock, &rc.msg));

	/* rx(message_5_KEM): authenticates the Initiator and yields PRK_out. */
	rc.msg.len = sizeof(rc.msg_buf);
	TRY_CLEANUP(rx(c->sock, &rc.msg));
	if (edhoc_is_error_message(rc.msg.ptr, rc.msg.len)) {
		store_received_error(&rc.msg, err_msg);
		FAIL_CLEANUP(error_message_received);
	}
	PERF_TIME("msg5_process     ",
		  step = authkem_msg5_process(&rc, prk_4e3m, &th4, &ptxt4, &c_i,
					      &id_cred_i, &cred_i, prk_out));
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}
	step = ead_process(c->params_ead_process, &rc.ead);
	if (step != ok) {
		r = send_error(c, err_msg, step, tx);
		goto cleanup;
	}

	/* Only PRK_out, the caller's output, should survive the handshake.
	 * Reached on every path, including the send_error and
	 * error_message_received exits. */
cleanup:
	edhoc_wipe(prk_2e, sizeof(prk_2e));
	edhoc_wipe(prk_3e2m, sizeof(prk_3e2m));
	edhoc_wipe(prk_4e3m, sizeof(prk_4e3m));
	edhoc_wipe(ss_R_buf, sizeof(ss_R_buf));
	return r;
}
