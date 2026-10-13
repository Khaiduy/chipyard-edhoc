/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdbool.h>
#include <string.h>
#include "secure_wipe.h"
#include "common/try_cleanup.h"
#include "edhoc_internal.h"

#ifdef TIMING_BREAKDOWN
#include "perf.h"
#else
#define PERF_TIME(label, stmt) stmt
#endif

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "edhoc/buffer_sizes.h"
#include "edhoc/edhoc_error_msg.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/messages.h"
#include "edhoc/okm.h"
#include "edhoc/plaintext.h"
#include "edhoc/prk.h"
#include "edhoc/retrieve_cred.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/suites.h"
#include "edhoc/th.h"
#include "edhoc/txrx_wrapper.h"
#include "edhoc/ciphertext.h"
#include "edhoc/runtime_context.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"
#include "edhoc/ead.h"

#include "cbor.h"

/** 
 * @brief   			Parses message 2.
 * @param c 			Initiator context.
 * @param[in] msg2 		Message 2. 
 * @param[out] g_y		G_Y ephemeral public key of the responder.
 * @param[out] ciphertext2	Ciphertext 2.
 * @retval			Ok or error code.
 */
static inline enum err msg2_parse(struct byte_array *msg2,
				  struct byte_array *g_y,
				  struct byte_array *ciphertext2)
{
	BYTE_ARRAY_NEW(g_y_ciphertext_2, G_Y_CIPHERTEXT_2, G_Y_CIPHERTEXT_2);
	TRY(decode_bstr(msg2, &g_y_ciphertext_2));

	TRY(_memcpy_s(g_y->ptr, g_y->len, g_y_ciphertext_2.ptr, g_y->len));
	PRINT_ARRAY("g_y", g_y->ptr, g_y->len);

	TRY(_memcpy_s(ciphertext2->ptr, ciphertext2->len,
		      g_y_ciphertext_2.ptr + g_y->len,
		      g_y_ciphertext_2.len - g_y->len));

	ciphertext2->len = g_y_ciphertext_2.len - g_y->len;
	PRINT_ARRAY("ciphertext2", ciphertext2->ptr, ciphertext2->len);

	return ok;
}

enum err msg1_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc)
{
	/* message_1 = ( METHOD : int, SUITES_I : suite / [ 2* suite ],
	 *               G_X : bstr, C_I : bstr / -24..23, ? EAD_1 ) */
	struct cbor_w w;

	cbor_w_init(&w, rc->msg.ptr, rc->msg.len);
	cbor_put_int(&w, c->method);
	if (c->suites_i.len == 1) {
		cbor_put_int(&w, c->suites_i.ptr[0]);
	} else {
		cbor_put_head(&w, CBOR_ARRAY, c->suites_i.len);
		for (uint32_t i = 0; i < c->suites_i.len; i++)
			cbor_put_int(&w, c->suites_i.ptr[i]);
	}
	cbor_put_bstr(&w, c->g_x.ptr, c->g_x.len);
	PRINT_ARRAY("C_I", c->c_i.ptr, c->c_i.len);
	if (c_x_is_encoded_int(&c->c_i))
		cbor_put_raw(&w, c->c_i.ptr, 1);
	else
		cbor_put_bstr(&w, c->c_i.ptr, c->c_i.len);
	/* RFC 9528: EAD_1 is a CBOR sequence appended verbatim, not a bstr. */
	TRY(ead_validate(&c->ead_1));
	cbor_put_raw(&w, c->ead_1.ptr, c->ead_1.len);
	if (w.err)
		return cbor_encoding_error;
	rc->msg.len = w.len;

	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	TRY(get_suite((enum suite_label)c->suites_i.ptr[c->suites_i.len - 1],
		      &rc->suite));
	/* Calculate hash of msg1 for TH2. */
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
	return ok;
}

static enum err msg2_process(const struct edhoc_initiator_context *c,
			     struct runtime_context *rc,
			     struct cred_array *cred_r_array,
			     struct byte_array *c_r, bool static_dh_i,
			     bool static_dh_r, struct byte_array *th3,
			     struct byte_array *PRK_3e2m)
{
	enum err r = ok;

	BYTE_ARRAY_NEW_C(g_y, G_Y_SIZE, get_ecdh_pk_len(rc->suite.edhoc_ecdh));
	uint32_t ciphertext_len = rc->msg.len - g_y.len;
	ciphertext_len -= BSTR_ENCODING_OVERHEAD(ciphertext_len);
	BYTE_ARRAY_NEW_C(ciphertext, CIPHERTEXT2_SIZE, ciphertext_len);
	BYTE_ARRAY_NEW_C(plaintext, PLAINTEXT2_SIZE, ciphertext.len);
	PRINT_ARRAY("message_2 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	/*parse the message*/
	TRY_CLEANUP(msg2_parse(&rc->msg, &g_y, &ciphertext));

	/*calculate the DH shared secret*/
	BYTE_ARRAY_NEW_C(g_xy, ECDH_SECRET_SIZE, ECDH_SECRET_SIZE);

	TRY_CLEANUP(shared_secret_derive(rc->suite.edhoc_ecdh, &c->x, &g_y, g_xy.ptr));
	PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy.ptr, g_xy.len);

	/*calculate th2*/
	BYTE_ARRAY_NEW_C(th2, HASH_SIZE, get_hash_len(rc->suite.edhoc_hash));

	TRY_CLEANUP(th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &g_y, &th2));

	/*calculate PRK_2e*/
	BYTE_ARRAY_NEW_C(PRK_2e, PRK_SIZE, PRK_SIZE);
	TRY_CLEANUP(hkdf_extract(rc->suite.edhoc_hash, &th2, &g_xy, PRK_2e.ptr));
	PRINT_ARRAY("PRK_2e", PRK_2e.ptr, PRK_2e.len);

	BYTE_ARRAY_NEW_C(sign_or_mac, SIG_OR_MAC_SIZE, SIG_OR_MAC_SIZE);
	BYTE_ARRAY_NEW_C(id_cred_r, ID_CRED_R_SIZE, ID_CRED_R_SIZE);

	plaintext.len = ciphertext.len;
	TRY_CLEANUP(check_buffer_size(PLAINTEXT2_SIZE, plaintext.len));

	TRY_CLEANUP(ciphertext_decrypt_split(CIPHERTEXT2, &rc->suite, c_r, &id_cred_r,
				     &sign_or_mac, &rc->ead, &PRK_2e, &th2,
				     &ciphertext, &plaintext));

	/*check the authenticity of the responder*/
	if (c->id_cred_check)
		TRY_CLEANUP(c->id_cred_check(c->params_id_cred_check, &id_cred_r));
	BYTE_ARRAY_NEW_C(cred_r, CRED_R_SIZE, CRED_R_SIZE);
	BYTE_ARRAY_NEW_C(pk, PK_SIZE, PK_SIZE);
	BYTE_ARRAY_NEW_C(g_r, G_R_SIZE, G_R_SIZE);
	TRY_CLEANUP(retrieve_cred(static_dh_r, cred_r_array, &id_cred_r, &cred_r, &pk,
			  &g_r));
	PRINT_ARRAY("CRED_R", cred_r.ptr, cred_r.len);
	PRINT_ARRAY("pk", pk.ptr, pk.len);
	PRINT_ARRAY("g_r", g_r.ptr, g_r.len);

	/*derive prk_3e2m*/
	TRY_CLEANUP(prk_derive(static_dh_r, rc->suite, SALT_3e2m, &th2, &PRK_2e, &g_r,
		       &c->x, PRK_3e2m->ptr));
	PRINT_ARRAY("prk_3e2m", PRK_3e2m->ptr, PRK_3e2m->len);

	TRY_CLEANUP(signature_or_mac(VERIFY, static_dh_r, &rc->suite, NULL, &pk,
			     PRK_3e2m, c_r, &th2, &id_cred_r, &cred_r, &rc->ead,
			     MAC_2, &sign_or_mac));

	TRY_CLEANUP(th34_calculate(rc->suite.edhoc_hash, &th2, &plaintext, &cred_r,
			   th3));

	/*derive prk_4e3m*/
	TRY_CLEANUP(prk_derive(static_dh_i, rc->suite, SALT_4e3m, th3, PRK_3e2m, &g_y,
		       &c->i, rc->prk_4e3m.ptr));
	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m.ptr, rc->prk_4e3m.len);

		/* the ECDH shared secret and PRK_2e die with this frame */
cleanup:
	edhoc_wipe(g_xy_buf, sizeof(g_xy_buf));
	edhoc_wipe(PRK_2e_buf, sizeof(PRK_2e_buf));
	return r;
}

static enum err msg3_only_gen(const struct edhoc_initiator_context *c,
			      struct runtime_context *rc, bool static_dh_i,
			      struct byte_array *th3,
			      struct byte_array *PRK_3e2m,
			      struct byte_array *prk_out)
{
	BYTE_ARRAY_NEW(plaintext, PLAINTEXT3_SIZE,
		       c->id_cred_i.len + AS_BSTR_SIZE(SIG_OR_MAC_SIZE) +
			       c->ead_3.len);
	BYTE_ARRAY_NEW(ciphertext, CIPHERTEXT3_SIZE,
		       AS_BSTR_SIZE(plaintext.len) +
			       get_aead_mac_len(rc->suite.edhoc_aead));
	/*calculate Signature_or_MAC_3*/
	BYTE_ARRAY_NEW(sign_or_mac_3, SIG_OR_MAC_SIZE, SIG_OR_MAC_SIZE);
	TRY(signature_or_mac(GENERATE, static_dh_i, &rc->suite, &c->sk_i,
			     &c->pk_i, &rc->prk_4e3m, &NULL_ARRAY, th3,
			     &c->id_cred_i, &c->cred_i, &c->ead_3, MAC_3,
			     &sign_or_mac_3));

	/*create plaintext3 and ciphertext3*/
	TRY(ciphertext_gen(CIPHERTEXT3, &rc->suite, &NULL_ARRAY, &c->id_cred_i,
			   &sign_or_mac_3, &c->ead_3, PRK_3e2m, th3,
			   &ciphertext, &plaintext));

	/*massage 3 create and send*/
	rc->msg.len = sizeof(rc->msg_buf);
	TRY(encode_bstr(&ciphertext, &rc->msg));
	PRINT_ARRAY("msg3", rc->msg.ptr, rc->msg.len);

	/*TH4*/
	TRY(th34_calculate(rc->suite.edhoc_hash, th3, &plaintext, &c->cred_i,
			   &rc->th4));

	/*PRK_out*/
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &rc->prk_4e3m, PRK_out, &rc->th4,
		      prk_out));
	return ok;
}

enum err msg3_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc, struct cred_array *cred_r_array,
		  struct byte_array *c_r, struct byte_array *prk_out)
{
	enum err r = ok;

	bool static_dh_i = false, static_dh_r = false;
	authentication_type_get(c->method, &static_dh_i, &static_dh_r);
	BYTE_ARRAY_NEW_C(th3, HASH_SIZE, HASH_SIZE);
	BYTE_ARRAY_NEW_C(PRK_3e2m, PRK_SIZE, PRK_SIZE);

	/*process message 2*/
	PERF_TIME("msg2_process     ",
		  TRY_CLEANUP(msg2_process(c, rc, cred_r_array, c_r, static_dh_i,
					   static_dh_r, &th3, &PRK_3e2m)));

	/*generate message 3*/
	PERF_TIME("msg3_build       ",
		  TRY_CLEANUP(msg3_only_gen(c, rc, static_dh_i, &th3, &PRK_3e2m,
					    prk_out)));
		/* PRK_3e2m dies with this frame; PRK_out is the caller's output */
cleanup:
	edhoc_wipe(PRK_3e2m_buf, sizeof(PRK_3e2m_buf));
	return r;
}

#ifdef MESSAGE_4
enum err msg4_process(struct runtime_context *rc)
{
	PRINT_ARRAY("message4 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	BYTE_ARRAY_NEW(ciphertext4, CIPHERTEXT4_SIZE, CIPHERTEXT4_SIZE);
	TRY(decode_bstr(&rc->msg, &ciphertext4));
	PRINT_ARRAY("ciphertext_4", ciphertext4.ptr, ciphertext4.len);

	BYTE_ARRAY_NEW(plaintext4,
		       PLAINTEXT4_SIZE + get_aead_mac_len(rc->suite.edhoc_aead),
		       ciphertext4.len);
	TRY(ciphertext_decrypt_split(CIPHERTEXT4, &rc->suite, NULL, &NULL_ARRAY,
				     &NULL_ARRAY, &rc->ead, &rc->prk_4e3m,
				     &rc->th4, &ciphertext4, &plaintext4));
	return ok;
}
#endif // MESSAGE_4

/* Initiator-side RFC 9528 error reporting. Wrong Selected Cipher Suite is a
 * responder-only error because its ERR_INFO must carry SUITES_R. */
static enum err send_error(
	const struct edhoc_initiator_context *c, struct byte_array *err_msg,
	enum err internal,
	enum err (*tx)(void *sock, struct byte_array *data))
{
	uint8_t buf[MSG_MAX_SIZE];
	uint32_t buf_len = 0;
	int wire = edhoc_map_to_wire_err_code(internal);
	enum err build_result;

	if (wire == EDHOC_ERR_CODE_WRONG_CIPHER_SUITE)
		wire = EDHOC_ERR_CODE_UNSPECIFIED;
	if (wire == EDHOC_ERR_CODE_UNKNOWN_CRED) {
		build_result = edhoc_build_error_message(
			buf, sizeof(buf), wire, NULL, 0, NULL, 0, &buf_len);
	} else {
		const char *diag = "EDHOC initiator processing error";
		build_result = edhoc_build_error_message(
			buf, sizeof(buf), EDHOC_ERR_CODE_UNSPECIFIED, diag, 0,
			NULL, 0, &buf_len);
	}
	if (build_result != ok)
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

enum err edhoc_initiator_run_extended(
	const struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *c_r_bytes, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24))
{
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);
	enum err r;

	/*create and send message 1 — local failure, nothing to report on wire */
	PERF_TIME("msg1_build       ", r = msg1_gen(c, &rc));
	if (r != ok) goto cleanup;
	r = tx(c->sock, &rc.msg);
	if (r != ok) goto cleanup;

	/*receive message 2 — may be a wire-format error from responder */
	PRINT_MSG("waiting to receive message 2...\n");
	rc.msg.len = sizeof(rc.msg_buf);
	r = rx(c->sock, &rc.msg);
	if (r != ok) goto cleanup;
	if (edhoc_is_error_message(rc.msg.ptr, rc.msg.len)) {
		store_received_error(&rc.msg, err_msg);
		r = error_message_received;
		goto cleanup;
	}

	/*create and send message 3 — process incoming, then build outgoing */
	r = msg3_gen(c, &rc, cred_r_array, c_r_bytes, prk_out);
	if (r != ok)
		{ r = send_error(c, err_msg, r, tx); goto cleanup; }
	r = ead_process(c->params_ead_process, &rc.ead);
	if (r != ok)
		{ r = send_error(c, err_msg, r, tx); goto cleanup; }
	r = tx(c->sock, &rc.msg);
	if (r != ok) goto cleanup;

	/*receive message 4 — may be a wire-format error from responder */
#ifdef MESSAGE_4
	PRINT_MSG("waiting to receive message 4...\n");
	rc.msg.len = sizeof(rc.msg_buf);
	r = rx(c->sock, &rc.msg);
	if (r != ok) goto cleanup;
	if (edhoc_is_error_message(rc.msg.ptr, rc.msg.len)) {
		store_received_error(&rc.msg, err_msg);
		r = error_message_received;
		goto cleanup;
	}
	r = msg4_process(&rc);
	if (r != ok)
		{ r = send_error(c, err_msg, r, tx); goto cleanup; }
	r = ead_process(c->params_ead_process, &rc.ead);
	if (r != ok)
		{ r = send_error(c, err_msg, r, tx); goto cleanup; }
#endif // MESSAGE_4
	r = ok;
	goto cleanup;

cleanup:
	/* The runtime context carries PRK_4e3m and the transcript hashes for the
	 * whole exchange. Wiping it here covers every exit, including the
	 * send_error and error_message_received paths -- a failed run should
	 * not leave more key material behind than a successful one. */
	edhoc_wipe(&rc, sizeof(rc));
	return r;
}

enum err edhoc_initiator_run(
	const struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24))
{
	BYTE_ARRAY_NEW(c_r, C_R_SIZE, C_R_SIZE);

	return edhoc_initiator_run_extended(c, cred_r_array, err_msg, &c_r,
					    prk_out, tx, rx, ead_process);
}
