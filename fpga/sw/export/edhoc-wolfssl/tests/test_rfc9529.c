/*
 * test_rfc9529.c - the library against the RFC 9529 traces.
 *
 *   make rfc9529-test        host: Trace 1 with suite 0, Trace 2 with suite 2
 *   make rfc9529-images      build/rfc9529_s{0,2}.elf for the board (console
 *                            at 57600 baud, load with ../common/board/run_one.sh)
 *
 * Each role runs alone with the trace's keys, ephemeral keys and connection
 * identifiers. Every message it sends must equal the trace byte for byte; the
 * peer's messages are fed from the trace. PRK_out, PRK_exporter and the OSCORE
 * master secret / salt must then equal the trace as well.
 *
 *   Trace 1 (EDHOC_CRYPTO_SUITE 0): METHOD 0, EdDSA, x5t credentials.
 *   Trace 2 (EDHOC_CRYPTO_SUITE 2): METHOD 3, P-256 static DH, kid + CCS,
 *     including the negotiation: the responder answers the trace's first
 *     message_1 (suite 6) with the trace's error message, then completes the
 *     handshake on the second message_1 (suites [6, 2]). The initiator, built
 *     for suite 2 only, starts from the second message_1.
 *
 * The ID_CRED_x each role receives must reach the application (RFC 9528
 * 3.5) as the trace's ID_CRED_x, and an application that refuses it must stop
 * the handshake.
 *
 * Invalid traces (Section 4): each malformed message_1 goes to a responder,
 * each malformed message_2 / PLAINTEXT_2 to an initiator that has sent the
 * Trace 2 message_1. The role must fail before sending its next handshake
 * message (an EDHOC error message is allowed). 4.2.4 (X25519) runs with
 * Trace 1, 4.2.1 (P-384) in a suite 24 build, the rest with Trace 2.
 */
#include <string.h>
#include "edhoc.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"
#include "rfc9529_vectors.h"

#ifdef __riscv
#include "kprintf.h"
#include "test_init.h"
#define say kprintf
#else
#include <stdio.h>
#define say printf
void kprintf(const char *fmt, ...) { (void)fmt; }
void kputc(char c) { (void)c; }
#endif

#define LEN(a) ((uint32_t)sizeof(a))
#define BA(a) ((struct byte_array){ .ptr = (uint8_t *)(a), .len = LEN(a) })

/* RNG hooks the library and wolfCrypt link against. Key material is fixed by
 * the trace, so nothing here may draw randomness that reaches the wire. */
int default_CSPRNG(uint8_t *d, unsigned int n) { memset(d, 0x5a, n); return 1; }
void csprng_add_entropy(const uint8_t *d, uint32_t n) { (void)d; (void)n; }
int csprng_generate_block(unsigned char *o, unsigned int n) { memset(o, 0x5a, n); return 0; }

static int fails;

static void check(const char *role, const char *what, const uint8_t *got,
		  uint32_t got_len, const uint8_t *want, uint32_t want_len)
{
	int ok = got_len == want_len && memcmp(got, want, want_len) == 0;

	say("  %s %s: %s\r\n", role, what, ok ? "PASS" : "FAIL");
	if (ok)
		return;
	fails++;
	say("    got  (%u B):", (unsigned)got_len);
	for (uint32_t i = 0; i < got_len; i++)
		say(" %02x", got[i]);
	say("\r\n    want (%u B):", (unsigned)want_len);
	for (uint32_t i = 0; i < want_len; i++)
		say(" %02x", want[i]);
	say("\r\n");
}

/* The trace as seen by one role: what it must send, what it receives. */
struct script {
	const char *role;
	const struct byte_array *tx, *rx;
	const char *const *tx_name;
	int ntx, nrx, itx, irx;
	int reject;      /* past the expected tx, only an error message is fine */
	int progressed;  /* reject mode: sent a further handshake message */
};
static struct script *cur;

static enum err tx_fn(void *sock, struct byte_array *d)
{
	(void)sock;
	if (cur->itx >= cur->ntx && cur->reject) {
		/* message_2 / message_3 are bstrs; an error message starts with
		 * its ERR_CODE int. */
		if (d->len && (d->ptr[0] & 0xe0) == 0x40)
			cur->progressed = 1;
		return ok;
	}
	if (cur->itx >= cur->ntx) {
		say("  %s sent an unexpected message: FAIL\r\n", cur->role);
		fails++;
		return ok;
	}
	check(cur->role, cur->tx_name[cur->itx], d->ptr, d->len,
	      cur->tx[cur->itx].ptr, cur->tx[cur->itx].len);
	cur->itx++;
	return ok;
}

static enum err rx_fn(void *sock, struct byte_array *d)
{
	(void)sock;
	if (cur->irx >= cur->nrx || d->len < cur->rx[cur->irx].len)
		return buffer_to_small;
	memcpy(d->ptr, cur->rx[cur->irx].ptr, cur->rx[cur->irx].len);
	d->len = cur->rx[cur->irx].len;
	cur->irx++;
	return ok;
}

static enum err no_ead(void *p, struct byte_array *e) { (void)p; (void)e; return ok; }

/* PRK_out, then the exporter outputs OSCORE derives from it (RFC 9528 A.1). */
static void check_keys(const char *role, enum err r, struct byte_array *prk_out,
		       const uint8_t *want_out, const uint8_t *want_exp,
		       const uint8_t *want_secret, const uint8_t *want_salt)
{
	uint8_t exp[32], secret[16], salt[8];
	struct byte_array e = { .ptr = exp, .len = sizeof(exp) };
	struct byte_array s = { .ptr = secret, .len = sizeof(secret) };
	struct byte_array t = { .ptr = salt, .len = sizeof(salt) };

	if (r != ok) {
		say("  %s handshake: FAIL (err %d)\r\n", role, r);
		fails++;
		return;
	}
	check(role, "PRK_out", prk_out->ptr, prk_out->len, want_out, 32);
	if (prk_out2exporter(SHA_256, prk_out, &e) != ok ||
	    edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &e, &s) != ok ||
	    edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &e, &t) != ok) {
		say("  %s exporter: FAIL\r\n", role);
		fails++;
		return;
	}
	check(role, "PRK_exporter", exp, sizeof(exp), want_exp, 32);
	check(role, "OSCORE master secret", secret, sizeof(secret), want_secret, 16);
	check(role, "OSCORE master salt", salt, sizeof(salt), want_salt, 8);
}

static enum err run_initiator(const struct edhoc_initiator_context *c,
			      struct other_party_cred *peer, struct byte_array *prk)
{
	static uint8_t err_buf[64];
	struct byte_array err_msg = { .ptr = err_buf, .len = sizeof(err_buf) };
	struct cred_array creds = { .len = 1, .ptr = peer };

	return edhoc_initiator_run(c, &creds, &err_msg, prk, tx_fn, rx_fn, no_ead);
}

static enum err run_responder(struct edhoc_responder_context *c,
			      struct other_party_cred *peer, struct byte_array *prk)
{
	static uint8_t err_buf[64];
	struct byte_array err_msg = { .ptr = err_buf, .len = sizeof(err_buf) };
	struct cred_array creds = { .len = 1, .ptr = peer };

	return edhoc_responder_run(c, &creds, &err_msg, prk, tx_fn, rx_fn, no_ead);
}

/* Section 4: the receiving role must stop, and for the reason the case is
 * about: want is the error that check returns (oscore_edhoc_error.h). */
static void expect_reject(const char *name, struct script *s, enum err r,
			  enum err want)
{
	int rejected = r == want && !s->progressed;

	say("  invalid %s rejected: %s (err %d, want %d)\r\n", name,
	    rejected ? "PASS" : "FAIL", r, want);
	if (!rejected)
		fails++;
}

struct invalid {
	const char *name;
	struct byte_array msg;
	enum err want;
};

static void reject_message_1(struct edhoc_responder_context *cr,
			     struct other_party_cred *peer,
			     const struct invalid *v, int n)
{
	uint8_t prk_buf[32];
	struct byte_array prk;
	struct script s;

	for (int i = 0; i < n; i++) {
		prk = (struct byte_array){ .ptr = prk_buf, .len = sizeof(prk_buf) };
		s = (struct script){ "responder", NULL, &v[i].msg, NULL, 0, 1, 0, 0, 1, 0 };
		cur = &s;
		expect_reject(v[i].name, &s, run_responder(cr, peer, &prk),
			      v[i].want);
	}
}

/* ID_CRED callbacks: record what the library hands the application, or
 * refuse it. */
static uint8_t seen_buf[32];
static uint32_t seen_len;

static enum err id_cred_record(void *params, const struct byte_array *id_cred)
{
	(void)params;
	seen_len = id_cred->len <= sizeof(seen_buf) ? id_cred->len : 0;
	memcpy(seen_buf, id_cred->ptr, seen_len);
	return ok;
}

static enum err id_cred_refuse(void *params, const struct byte_array *id_cred)
{
	(void)params;
	(void)id_cred;
	return credential_not_found;
}

#if EDHOC_CRYPTO_SUITE == 0
#define TRACE "Trace 1 (RFC 9529 Section 2): METHOD 0, suite 0, x5t"
static const char *const i_names[] = { "message_1", "message_3" };
static const char *const r_names[] = { "message_2", "message_4" };

static void trace(void)
{
	static const uint8_t suites[] = { 0 };
	uint8_t prk_buf[32];
	struct byte_array prk = { .ptr = prk_buf, .len = sizeof(prk_buf) };
	const struct byte_array i_tx[] = { BA(T1_MESSAGE_1), BA(T1_MESSAGE_3) };
	const struct byte_array r_tx[] = { BA(T1_MESSAGE_2), BA(T1_MESSAGE_4) };
	struct other_party_cred peer;
	struct script s;

	struct edhoc_initiator_context ci = {
		.c_i = BA(T1_C_I), .method = INITIATOR_SK_RESPONDER_SK,
		.suites_i = BA(suites), .x = BA(T1_X), .g_x = BA(T1_G_X),
		.sk_i = BA(T1_SK_I), .pk_i = BA(T1_PK_I),
		.id_cred_i = BA(T1_ID_CRED_I), .cred_i = BA(T1_CRED_I),
		.id_cred_check = id_cred_record,
	};
	peer = (struct other_party_cred){ .id_cred = BA(T1_ID_CRED_R),
		.cred = BA(T1_CRED_R), .pk = BA(T1_PK_R) };
	s = (struct script){ "initiator", i_tx, r_tx, i_names, 2, 2, 0, 0 };
	cur = &s;
	seen_len = 0;
	check_keys("initiator", run_initiator(&ci, &peer, &prk), &prk,
		   T1_PRK_OUT, T1_PRK_EXPORTER, T1_OSCORE_SECRET, T1_OSCORE_SALT);
	check("initiator", "ID_CRED_R to application", seen_buf, seen_len,
	      T1_ID_CRED_R, LEN(T1_ID_CRED_R));

	struct edhoc_responder_context cr = {
		.c_r = BA(T1_C_R), .suites_r = BA(suites),
		.y = BA(T1_Y), .g_y = BA(T1_G_Y),
		.sk_r = BA(T1_SK_R), .pk_r = BA(T1_PK_R),
		.id_cred_r = BA(T1_ID_CRED_R), .cred_r = BA(T1_CRED_R),
		.id_cred_check = id_cred_record,
	};
	peer = (struct other_party_cred){ .id_cred = BA(T1_ID_CRED_I),
		.cred = BA(T1_CRED_I), .pk = BA(T1_PK_I) };
	prk.len = sizeof(prk_buf);
	s = (struct script){ "responder", r_tx, i_tx, r_names, 2, 2, 0, 0 };
	cur = &s;
	seen_len = 0;
	check_keys("responder", run_responder(&cr, &peer, &prk), &prk,
		   T1_PRK_OUT, T1_PRK_EXPORTER, T1_OSCORE_SECRET, T1_OSCORE_SALT);
	check("responder", "ID_CRED_I to application", seen_buf, seen_len,
	      T1_ID_CRED_I, LEN(T1_ID_CRED_I));

	static const struct invalid m1[] = {
		{ "4.2.4 X25519 low-order G_X", BA(INV_4_2_4),
		  unexpected_result_from_ext_lib },
	};
	reject_message_1(&cr, &peer, m1, 1);
}

#elif EDHOC_CRYPTO_SUITE == 2
#define TRACE "Trace 2 (RFC 9529 Section 3): METHOD 3, suite 2, kid"
static const char *const i_names[] = { "message_1", "message_3" };
static const char *const r_names[] = { "message_2", "message_4" };
static const char *const e_names[] = { "error (suite 6)" };

static void trace(void)
{
	static const uint8_t suites_i[] = { 6, 2 };
	static const uint8_t suites_r[] = { 2 };
	uint8_t prk_buf[32];
	struct byte_array prk = { .ptr = prk_buf, .len = sizeof(prk_buf) };
	const struct byte_array i_tx[] = { BA(T2_MESSAGE_1), BA(T2_MESSAGE_3) };
	const struct byte_array r_tx[] = { BA(T2_MESSAGE_2), BA(T2_MESSAGE_4) };
	const struct byte_array first_m1[] = { BA(T2_MESSAGE_1_FIRST) };
	const struct byte_array error[] = { BA(T2_ERROR) };
	struct other_party_cred peer;
	struct script s;

	struct edhoc_initiator_context ci = {
		.c_i = BA(T2_C_I), .method = INITIATOR_SDHK_RESPONDER_SDHK,
		.suites_i = BA(suites_i), .x = BA(T2_X), .g_x = BA(T2_G_X),
		.i = BA(T2_SK_I), .g_i = BA(T2_G_I),
		.id_cred_i = BA(T2_ID_CRED_I), .cred_i = BA(T2_CRED_I),
		.id_cred_check = id_cred_record,
	};
	peer = (struct other_party_cred){ .id_cred = BA(T2_ID_CRED_R),
		.cred = BA(T2_CRED_R), .g = BA(T2_G_R) };
	s = (struct script){ "initiator", i_tx, r_tx, i_names, 2, 2, 0, 0 };
	cur = &s;
	seen_len = 0;
	check_keys("initiator", run_initiator(&ci, &peer, &prk), &prk,
		   T2_PRK_OUT, T2_PRK_EXPORTER, T2_OSCORE_SECRET, T2_OSCORE_SALT);
	/* Sent compact as 0x32, handed over as { 4: h'32' }. */
	check("initiator", "ID_CRED_R to application", seen_buf, seen_len,
	      T2_ID_CRED_R, LEN(T2_ID_CRED_R));

	/* An application that refuses ID_CRED_R stops the Initiator before
	 * message_3; an error message may go out instead. */
	ci.id_cred_check = id_cred_refuse;
	prk.len = sizeof(prk_buf);
	s = (struct script){ "initiator", i_tx, r_tx, i_names, 1, 1, 0, 0, 1, 0 };
	cur = &s;
	expect_reject("message_2, ID_CRED_R refused by application", &s,
		      run_initiator(&ci, &peer, &prk), credential_not_found);
	ci.id_cred_check = NULL;

	struct edhoc_responder_context cr = {
		.c_r = BA(T2_C_R), .suites_r = BA(suites_r),
		.y = BA(T2_Y), .g_y = BA(T2_G_Y),
		.r = BA(T2_SK_R), .g_r = BA(T2_G_R),
		.id_cred_r = BA(T2_ID_CRED_R), .cred_r = BA(T2_CRED_R),
		.id_cred_check = id_cred_record,
	};
	peer = (struct other_party_cred){ .id_cred = BA(T2_ID_CRED_I),
		.cred = BA(T2_CRED_I), .g = BA(T2_G_I) };

	/* Negotiation: suite 6 alone must be refused with the trace's error. */
	s = (struct script){ "responder", error, first_m1, e_names, 1, 1, 0, 0 };
	cur = &s;
	if (run_responder(&cr, &peer, &prk) == ok) {
		say("  responder accepted suite 6: FAIL\r\n");
		fails++;
	} else if (s.itx != 1) {
		say("  responder sent no error: FAIL\r\n");
		fails++;
	}

	prk.len = sizeof(prk_buf);
	s = (struct script){ "responder", r_tx, i_tx, r_names, 2, 2, 0, 0 };
	cur = &s;
	seen_len = 0;
	check_keys("responder", run_responder(&cr, &peer, &prk), &prk,
		   T2_PRK_OUT, T2_PRK_EXPORTER, T2_OSCORE_SECRET, T2_OSCORE_SALT);
	check("responder", "ID_CRED_I to application", seen_buf, seen_len,
	      T2_ID_CRED_I, LEN(T2_ID_CRED_I));

	static const struct invalid m1[] = {
		{ "4.1.1 message_1 as array", BA(INV_4_1_1), cbor_decoding_error },
		{ "4.1.2 C_I as bstr", BA(INV_4_1_2), cbor_decoding_error },
		{ "4.1.3 SUITES_I as array", BA(INV_4_1_3), cbor_decoding_error },
		{ "4.1.4 G_X as tstr", BA(INV_4_1_4), cbor_decoding_error },
		{ "4.2.2 G_X x >= p", BA(INV_4_2_2), wrong_parameter },
		{ "4.2.3 G_X not on P-256", BA(INV_4_2_3), unexpected_result_from_ext_lib },
		{ "4.2.6 G_X 31 bytes", BA(INV_4_2_6), wrong_parameter },
		{ "4.3.1 METHOD long encoding", BA(INV_4_3_1), cbor_decoding_error },
		{ "4.3.2 SUITES_I indefinite", BA(INV_4_3_2), cbor_decoding_error },
	};
	reject_message_1(&cr, &peer, m1, (int)(sizeof(m1) / sizeof(m1[0])));

	/* Not in RFC 9529: RFC 9528 3.8, an unrecognized critical EAD item
	 * (label -1, 0x20) after the trace's message_1 must abort. */
	uint8_t m1_ead[sizeof(T2_MESSAGE_1) + 1];
	memcpy(m1_ead, T2_MESSAGE_1, sizeof(T2_MESSAGE_1));
	m1_ead[sizeof(T2_MESSAGE_1)] = 0x20;
	const struct invalid ead1[] = {
		{ "RFC 9528 3.8 critical EAD_1", { .ptr = m1_ead, .len = sizeof(m1_ead) },
		  ead_critical_unsupported },
	};
	reject_message_1(&cr, &peer, ead1, 1);

	/* message_2 cases: the initiator sends the Trace 2 message_1, then gets
	 * the invalid message_2. PLAINTEXT_2 cases are encrypted the way a
	 * responder would, with KEYSTREAM_2 = EDHOC_KDF(PRK_2e, 0, TH_2, len);
	 * the trace's own PLAINTEXT_2 checks that construction. */
	static const struct {
		const char *name;
		const uint8_t *pt;
		uint32_t len;
		enum err want;
	} pt2[] = {
		{ "trace PLAINTEXT_2 (self-check)", T2_PLAINTEXT_2, LEN(T2_PLAINTEXT_2), ok },
		{ "4.1.6 ID_CRED_R as map", INV_4_1_6, LEN(INV_4_1_6), cbor_decoding_error },
		{ "4.1.7 ID_CRED_R as bstr", INV_4_1_7, LEN(INV_4_1_7), cbor_decoding_error },
		{ "4.2.5 MAC_2 too short", INV_4_2_5, LEN(INV_4_2_5), mac_authentication_failed },
	};
	uint8_t m2[64], ks[32];
	struct byte_array m2_ba;

	peer = (struct other_party_cred){ .id_cred = BA(T2_ID_CRED_R),
		.cred = BA(T2_CRED_R), .g = BA(T2_G_R) };
	m2_ba = BA(INV_4_1_5);
	prk.len = sizeof(prk_buf);
	s = (struct script){ "initiator", i_tx, &m2_ba, i_names, 1, 1, 0, 0, 1, 0 };
	cur = &s;
	expect_reject("4.1.5 message_2 extra element", &s,
		      run_initiator(&ci, &peer, &prk), cbor_decoding_error);
	for (unsigned i = 0; i < sizeof(pt2) / sizeof(pt2[0]); i++) {
		struct byte_array prk_2e = BA(T2_PRK_2E), th_2 = BA(T2_TH_2);
		struct byte_array k = { .ptr = ks, .len = pt2[i].len };

		edhoc_kdf(SHA_256, &prk_2e, KEYSTREAM_2, &th_2, &k);
		m2[0] = 0x58;
		m2[1] = (uint8_t)(32 + pt2[i].len);
		memcpy(m2 + 2, T2_G_Y, 32);
		for (uint32_t j = 0; j < pt2[i].len; j++)
			m2[34 + j] = pt2[i].pt[j] ^ ks[j];
		m2_ba = (struct byte_array){ .ptr = m2, .len = 34 + pt2[i].len };
		if (i == 0) {
			check("initiator", "message_2 rebuilt from PLAINTEXT_2",
			      m2, m2_ba.len, T2_MESSAGE_2, LEN(T2_MESSAGE_2));
			continue;
		}
		prk.len = sizeof(prk_buf);
		s = (struct script){ "initiator", i_tx, &m2_ba, i_names, 1, 1, 0, 0, 1, 0 };
		cur = &s;
		expect_reject(pt2[i].name, &s, run_initiator(&ci, &peer, &prk),
			      pt2[i].want);
	}
}

#elif EDHOC_CRYPTO_SUITE == 24
#define TRACE "RFC 9529 Section 4.2.1: P-384 G_X of the wrong length (suite 24)"

/* No trace uses suite 24; this build exists so 4.2.1 reaches the P-384
 * length check instead of failing suite selection. The message offers
 * [2, 24] and this responder supports only 24, so selection succeeds and the
 * 32-byte G_X must be refused. The responder's own keys are never used. */
static void trace(void)
{
	static const uint8_t suites_r[] = { 24 };
	static const uint8_t c_r[] = { 0x27 };
	static const uint8_t y[48], g_y[48];
	struct edhoc_responder_context cr = {
		.c_r = BA(c_r), .suites_r = BA(suites_r),
		.y = BA(y), .g_y = BA(g_y),
	};
	struct other_party_cred peer = { 0 };
	static const struct invalid m1[] = {
		{ "4.2.1 G_X 32 bytes for P-384", BA(INV_4_2_1), wrong_parameter },
	};

	reject_message_1(&cr, &peer, m1, 1);
}

#else
#error "RFC 9529 is tested with cipher suites 0, 2 (traces) and 24 (4.2.1)"
#endif

int main(void)
{
#ifdef __riscv
	test_console_init();
#endif
	say("\r\n%s\r\n", TRACE);
	trace();
	say("RFC9529 TEST suite %d: %s (%d failures)\r\n", EDHOC_CRYPTO_SUITE,
	    fails ? "FAIL" : "PASS", fails);
#ifdef __riscv
	while (1)
		;
#endif
	return fails != 0;
}
