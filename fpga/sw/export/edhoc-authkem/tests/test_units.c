/* Host unit tests for the AuthKEM library, built per suite (make unit-test
 * SUITE=TBD1|TBD2|TBD3) from the same sources and defines as the firmware:
 *   - fail-closed algorithm selection: get_suite() serves exactly the suite
 *     this image is built for, and the KEM wrappers refuse any other KEM;
 *   - ML-KEM round trips, with the provisioned demo key pairs too, and the
 *     FIPS 203 encapsulation-key check;
 *   - the message, plaintext and error-message codecs.
 * The full handshake is covered by tests/test_loopback.c. */
#include <stdio.h>
#include <string.h>

#include "edhoc.h"
#include "authkem_cred.h"
#include "authkem_test_keys.h"
#include "common/crypto_wrapper.h"
#include "edhoc/authkem_messages.h"
#include "edhoc/authkem_plaintext.h"
#include "edhoc/edhoc_error_msg.h"

/* Deterministic stand-in for the firmware CSPRNG (rdcycle/CLINT). */
static uint64_t rng = 0x243F6A8885A308D3ull;
int default_CSPRNG(uint8_t *dest, unsigned int size)
{
	for (unsigned int i = 0; i < size; i++) {
		rng ^= rng << 13;
		rng ^= rng >> 7;
		rng ^= rng << 17;
		dest[i] = (uint8_t)(rng >> 24);
	}
	return 1;
}
void kprintf(const char *fmt, ...) { (void)fmt; }

static int failures;

static void check(const char *what, int pass)
{
	printf("%-56s %s\n", what, pass ? "PASS" : "FAIL");
	failures += !pass;
}

#define BA(buf) { .ptr = (buf), .len = sizeof(buf) }

static void test_suite_gate(void)
{
	struct suite s;
	int others_refused = 1;

	check("get_suite(own suite) accepted",
	      get_suite((enum suite_label)(int8_t)AUTHKEM_SUITE_BYTE, &s) == ok);
	for (int l = -128; l <= 127; l++)
		if (l != (int8_t)AUTHKEM_SUITE_BYTE &&
		    get_suite((enum suite_label)l, &s) != unsupported_cipher_suite)
			others_refused = 0;
	check("get_suite(every other label in -128..127) refused",
	      others_refused);
}

static void test_kem(void)
{
	struct suite s;
	uint8_t skb[KEM_SK_SIZE], pkb[KEM_PK_SIZE], ctb[KEM_CT_SIZE];
	uint8_t ss1b[KEM_SECRET_SIZE], ss2b[KEM_SECRET_SIZE];
	struct byte_array sk = BA(skb), pk = BA(pkb), ct = BA(ctb);
	struct byte_array ss1 = BA(ss1b), ss2 = BA(ss2b);
	enum ecdh_alg other;

	get_suite((enum suite_label)(int8_t)AUTHKEM_SUITE_BYTE, &s);
	other = s.edhoc_ecdh == ML_KEM_512 ? ML_KEM_1024 : ML_KEM_512;
	check("key_gen/encap/decap refuse the other ML-KEM",
	      ephemeral_kem_key_gen(other, &sk, &pk) == unsupported_ecdh_curve &&
		      kem_encapsulate(other, &pk, &ct, &ss1) == unsupported_ecdh_curve &&
		      kem_decapsulate(other, &ct, &sk, &ss2) == unsupported_ecdh_curve);

	check("ephemeral key pair, encap/decap agree",
	      ephemeral_kem_key_gen(s.edhoc_ecdh, &sk, &pk) == ok &&
		      kem_encapsulate(s.edhoc_ecdh, &pk, &ct, &ss1) == ok &&
		      kem_decapsulate(s.edhoc_ecdh, &ct, &sk, &ss2) == ok &&
		      !memcmp(ss1b, ss2b, sizeof(ss1b)));

	/* The provisioned demo key pairs pass FIPS 203 validation and agree. */
	const struct byte_array ipk = { .ptr = (uint8_t *)INIT_PK, .len = sizeof(INIT_PK) };
	const struct byte_array isk = { .ptr = (uint8_t *)INIT_SK, .len = sizeof(INIT_SK) };
	const struct byte_array rpk = { .ptr = (uint8_t *)RESP_PK, .len = sizeof(RESP_PK) };
	const struct byte_array rsk = { .ptr = (uint8_t *)RESP_SK, .len = sizeof(RESP_SK) };
	ct.len = sizeof(ctb); ss1.len = ss2.len = sizeof(ss1b);
	int ok_i = kem_encapsulate(s.edhoc_ecdh, &ipk, &ct, &ss1) == ok &&
		   kem_decapsulate(s.edhoc_ecdh, &ct, &isk, &ss2) == ok &&
		   !memcmp(ss1b, ss2b, sizeof(ss1b));
	ct.len = sizeof(ctb); ss1.len = ss2.len = sizeof(ss1b);
	int ok_r = kem_encapsulate(s.edhoc_ecdh, &rpk, &ct, &ss1) == ok &&
		   kem_decapsulate(s.edhoc_ecdh, &ct, &rsk, &ss2) == ok &&
		   !memcmp(ss1b, ss2b, sizeof(ss1b));
	check("demo key pairs (initiator, responder) round trip", ok_i && ok_r);

	/* FIPS 203 7.2: an encapsulation key with out-of-range coefficients is
	 * refused. */
	memset(pkb, 0xff, sizeof(pkb));
	pk.len = sizeof(pkb); ct.len = sizeof(ctb); ss1.len = sizeof(ss1b);
	check("invalid encapsulation key refused",
	      kem_encapsulate(s.edhoc_ecdh, &pk, &ct, &ss1) != ok);
}

static void test_codecs(void)
{
	uint8_t pk[KEM_PK_SIZE] = { 0 };
	uint8_t cred[AUTHKEM_CRED_SIZE(sizeof(pk))];
	check("CCS credential layout",
	      authkem_build_ccs(cred, sizeof(cred), pk, sizeof(pk)) == sizeof(cred) &&
		      cred[0] == 0xa1 && cred[1] == 8 && cred[2] == 0xa1 &&
		      cred[3] == 1 && cred[4] == 0xa3);

	/* message_1 with a suite list, an int C_I and EAD round trips. */
	uint8_t suites_raw[] = { 7, AUTHKEM_SUITE_BYTE }, eph_raw[KEM_PK_SIZE] = { 0 };
	uint8_t ci_raw[] = { 0x2d }, ead_raw[] = { 0x01, 0x41, 0x78 };
	uint8_t msg_raw[MSG_MAX_SIZE + 8];
	struct byte_array suites = BA(suites_raw), eph = BA(eph_raw);
	struct byte_array ci = BA(ci_raw), ead = BA(ead_raw), msg = BA(msg_raw);
	int32_t method = 0;
	uint8_t s_out[4], c_out[4], e_out[8];
	struct byte_array suites_out = BA(s_out), eph_out = { 0 };
	struct byte_array ci_out = BA(c_out), ead_out = BA(e_out);
	check("message_1 encode/decode",
	      authkem_msg1_encode(5, &suites, &eph, &ci, &ead, &msg) == ok &&
		      authkem_msg1_decode(&msg, &method, &suites_out, &eph_out,
					  &ci_out, &ead_out) == ok &&
		      method == 5 && suites_out.len == 2 &&
		      suites_out.ptr[1] == AUTHKEM_SUITE_BYTE &&
		      eph_out.len == sizeof(eph_raw) && ci_out.len == 1 &&
		      ci_out.ptr[0] == 0x2d && ead_out.len == sizeof(ead_raw) &&
		      !memcmp(e_out, ead_raw, sizeof(ead_raw)));

	/* PLAINTEXT_2: { 4: h'aa' } travels as the bare kid and comes back as
	 * the map. */
	uint8_t id_raw[] = { 0xa1, 0x04, 0x41, 0xaa }, pt_raw[32];
	uint8_t ci2_raw[4], id2_raw[8], ead2_raw[8];
	struct byte_array id = BA(id_raw), pt = BA(pt_raw);
	struct byte_array ci2 = BA(ci2_raw), id2 = BA(id2_raw), ead2 = BA(ead2_raw);
	check("PLAINTEXT_2 encode/decode (compact kid)",
	      authkem_plaintext2_encode(&ci, &id, &ead, &pt) == ok &&
		      pt.len == 1 + 2 + sizeof(ead_raw) &&
		      authkem_plaintext2_decode(&pt, &ci2, &id2, &ead2) == ok &&
		      id2.len == sizeof(id_raw) && !memcmp(id2_raw, id_raw, sizeof(id_raw)));

	/* RFC 9528 3.3.2 / 3.5.3.2 encodings: a compact int kid is the byte
	 * string of its own encoding; non-canonical forms are refused. */
	static const struct {
		const char *name;
		uint8_t pt[6];
		uint32_t len;
		int accept;
	} enc[] = {
		{ "PLAINTEXT_2 int kid 01 -> { 4: h'01' }", { 0x27, 0x01 }, 2, 1 },
		{ "PLAINTEXT_2 kid h'01' as bstr refused", { 0x27, 0x41, 0x01 }, 3, 0 },
		{ "PLAINTEXT_2 { 4: h'32' } map refused", { 0x27, 0xa1, 0x04, 0x41, 0x32 }, 5, 0 },
		{ "PLAINTEXT_2 kid 24 (two-byte int) refused", { 0x27, 0x18, 0x18 }, 3, 0 },
		{ "PLAINTEXT_2 C_R h'27' as bstr refused", { 0x41, 0x27, 0x01 }, 3, 0 },
		{ "PLAINTEXT_2 C_R 24 (two-byte int) refused", { 0x18, 0x18, 0x01 }, 3, 0 },
	};
	for (unsigned i = 0; i < sizeof(enc) / sizeof(enc[0]); i++) {
		struct byte_array p = { .ptr = (uint8_t *)enc[i].pt, .len = enc[i].len };

		ci2.len = sizeof(ci2_raw); id2.len = sizeof(id2_raw); ead2.len = sizeof(ead2_raw);
		enum err r = authkem_plaintext2_decode(&p, &ci2, &id2, &ead2);
		check(enc[i].name, enc[i].accept ?
		      r == ok && id2.len == 4 && !memcmp(id2_raw, "\xa1\x04\x41\x01", 4) :
		      r != ok);
	}

	/* Hostile nesting in ID_CRED is refused, not recursed into. */
	uint8_t deep[40];
	memset(deep, 0x81, sizeof(deep));
	deep[0] = 0x2d;
	struct byte_array bad = BA(deep);
	ci2.len = sizeof(ci2_raw); id2.len = sizeof(id2_raw); ead2.len = sizeof(ead2_raw);
	check("PLAINTEXT_2 with deeply nested ID_CRED refused",
	      authkem_plaintext2_decode(&bad, &ci2, &id2, &ead2) != ok);

	/* Error messages, RFC 9528 section 6. */
	uint8_t out[64];
	uint32_t n = 0;
	static const uint8_t suites_r[] = { 0x82, 0x07, 0x18, 0x18 };
	int e1 = edhoc_build_error_message(out, sizeof(out), EDHOC_ERR_CODE_UNSPECIFIED,
					   "oops", 4, NULL, 0, &n) == ok &&
		 n == 6 && !memcmp(out, "\x01\x64oops", 6) &&
		 edhoc_is_error_message(out, n);
	int e2 = edhoc_build_error_message(out, sizeof(out),
					   EDHOC_ERR_CODE_WRONG_CIPHER_SUITE, NULL, 0,
					   suites_r, sizeof(suites_r), &n) == ok &&
		 n == 5 && out[0] == 0x02 && !memcmp(out + 1, suites_r, 4);
	int e3 = edhoc_build_error_message(out, sizeof(out), EDHOC_ERR_CODE_UNKNOWN_CRED,
					   NULL, 0, NULL, 0, &n) == ok &&
		 n == 2 && out[0] == 0x03 && out[1] == 0xf5;
	check("error messages (codes 1, 2, 3)", e1 && e2 && e3);
	check("internal error -> wire code",
	      edhoc_map_to_wire_err_code(credential_not_found) == EDHOC_ERR_CODE_UNKNOWN_CRED &&
		      edhoc_map_to_wire_err_code(unsupported_cipher_suite) ==
			      EDHOC_ERR_CODE_WRONG_CIPHER_SUITE);
}

int main(void)
{
	test_suite_gate();
	test_kem();
	test_codecs();
	printf("unit tests (suite byte %d): %s\n", (int8_t)AUTHKEM_SUITE_BYTE,
	       failures ? "FAIL" : "PASS");
	return failures != 0;
}
