/*
 * crypto_mlkem.c — ML-KEM (FIPS 203) test across all three parameter sets.
 *
 * Covers requirement B6's "ML-KEM full levels 512/768/1024".
 *
 * The implementation under test is mlkem-native (FIPS 203), the same library
 * edhoc-authkem links, built three times as a multi-level library (see
 * mlkem_test in the Makefile).
 *
 * Per level:
 *   1. known-answer test: keypair and encapsulation from fixed seeds must
 *      reproduce the FIPS 203 outputs computed by an independent
 *      implementation (kyber-py 1.2.0, ML_KEM_*._keygen_internal /
 *      _encaps_internal). pk, sk and ct are compared by their FNV-1a-64 hash
 *      to keep the vectors small; the shared secrets are compared in full.
 *   2. decapsulation must return the encapsulated secret
 *   3. implicit rejection: decapsulating a ciphertext with one flipped bit
 *      must return FIPS 203's rejection secret J(z || ct'), also a KAT
 *
 * Seeds: d = 00..1f, z = 20..3f, m = 40..5f.
 */
#include <stdint.h>
#include <string.h>
#include "kprintf.h"
#include "test_init.h"

/* ML-KEM-512 */
#define K512_PK 800
#define K512_SK 1632
#define K512_CT 768
/* ML-KEM-768 */
#define K768_PK 1184
#define K768_SK 2400
#define K768_CT 1088
/* ML-KEM-1024 */
#define K1024_PK 1568
#define K1024_SK 3168
#define K1024_CT 1568

#define SS_BYTES 32

/* mlkem-native multi-level API, namespace prefix "mlk" (Makefile). */
#define MLK_DECL(n)                                                          \
	int mlk##n##_keypair_derand(uint8_t *pk, uint8_t *sk,                \
				    const uint8_t coins[64]);                \
	int mlk##n##_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, \
				const uint8_t coins[32]);                    \
	int mlk##n##_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
MLK_DECL(512)
MLK_DECL(768)
MLK_DECL(1024)

typedef int (*kp_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*enc_fn)(uint8_t *, uint8_t *, const uint8_t *, const uint8_t *);
typedef int (*dec_fn)(uint8_t *, const uint8_t *, const uint8_t *);

struct level {
	const char *name;
	kp_fn kp;
	enc_fn enc;
	dec_fn dec;
	unsigned pk_len, sk_len, ct_len;
	uint64_t pk_fnv, sk_fnv, ct_fnv;
	uint8_t ss[SS_BYTES];   /* encapsulated secret */
	uint8_t rej[SS_BYTES];  /* rejection secret for ct with ct[0] ^= 1 */
};

static const struct level levels[] = {
	{ "ML-KEM-512", mlk512_keypair_derand, mlk512_enc_derand, mlk512_dec,
	  K512_PK, K512_SK, K512_CT,
	  0xe240fca55cc7f339ull, 0x2d3935be7d5c9a27ull, 0x43d358110cb77e39ull,
	  { 0x14,0xca,0xce,0x3e,0x48,0x77,0x1b,0x31,0x66,0x76,0xaf,0xad,0x2c,0xfc,0xfe,0x84,
	    0x88,0xda,0xaa,0x4f,0xad,0x95,0x4e,0x57,0x23,0x6c,0xaa,0x3f,0x24,0xa4,0x2c,0xf7 },
	  { 0x32,0xee,0x1f,0xb3,0xf7,0xbd,0x29,0x15,0x21,0x8e,0x9c,0x1b,0x2d,0x0d,0x2d,0xa8,
	    0x8f,0x0e,0xdc,0xe6,0x80,0x42,0x78,0xba,0xb3,0xa6,0x12,0x3c,0x5b,0xb6,0x4f,0xc4 } },
	{ "ML-KEM-768", mlk768_keypair_derand, mlk768_enc_derand, mlk768_dec,
	  K768_PK, K768_SK, K768_CT,
	  0x174a98e49f77819cull, 0x84526ce8574495edull, 0x7c677826c5a436deull,
	  { 0x9c,0xdd,0xd0,0x89,0xff,0xe7,0x0e,0x39,0x96,0xe7,0x6f,0x7c,0x8d,0x06,0x74,0x6d,
	    0xf3,0x4d,0x07,0xe8,0x65,0x7b,0xc0,0xfc,0xf2,0xbb,0x0e,0x1c,0x30,0x84,0xae,0xa1 },
	  { 0xdc,0xfc,0x80,0xc6,0xdb,0x46,0xff,0x70,0x28,0xe3,0xa4,0x39,0x86,0x51,0xc0,0x63,
	    0xae,0x7a,0x42,0xc1,0x07,0xa6,0xdc,0x8c,0xb0,0x71,0x41,0x86,0x16,0x98,0xab,0x92 } },
	{ "ML-KEM-1024", mlk1024_keypair_derand, mlk1024_enc_derand, mlk1024_dec,
	  K1024_PK, K1024_SK, K1024_CT,
	  0x6fe328f176587753ull, 0x30e8abba7c073e02ull, 0x27278dadd28000acull,
	  { 0x0a,0xd8,0xd1,0xea,0x1b,0x8d,0xd7,0x88,0x97,0x9b,0x43,0x79,0x58,0x12,0x18,0xdf,
	    0x93,0x21,0xbd,0xce,0x55,0x67,0xec,0xa4,0x2a,0xe6,0xbe,0x7d,0x39,0x5f,0x1a,0x54 },
	  { 0x8f,0x2c,0x88,0x08,0x90,0x99,0x6c,0x58,0x7a,0xa5,0x00,0xcf,0x8b,0x6d,0xa0,0x33,
	    0x72,0xde,0x70,0x6a,0x9f,0x96,0x07,0x57,0x44,0xbb,0x09,0x56,0xea,0x6f,0xba,0xac } },
};

/* Buffers sized for the largest level; every level reuses them. */
static uint8_t pk[K1024_PK];
static uint8_t sk[K1024_SK];
static uint8_t ct[K1024_CT];
static uint8_t ss_a[SS_BYTES];
static uint8_t ss_b[SS_BYTES];

static uint64_t fnv1a64(const uint8_t *p, unsigned n)
{
	uint64_t h = 0xcbf29ce484222325ull;

	while (n--)
		h = (h ^ *p++) * 0x100000001b3ull;
	return h;
}

static int check(const char *what, int ok)
{
	kprintf("  %s: %s\r\n", what, ok ? "PASS" : "FAIL");
	return !ok;
}

static int run_level(const struct level *l)
{
	uint8_t coins[64];
	int fails = 0;

	kprintf("\r\n-- %s (pk=%u sk=%u ct=%u) --\r\n",
		l->name, l->pk_len, l->sk_len, l->ct_len);

	for (unsigned i = 0; i < sizeof(coins); i++)
		coins[i] = (uint8_t)i;                    /* d || z */
	if (check("keypair KAT ", l->kp(pk, sk, coins) == 0 &&
			  fnv1a64(pk, l->pk_len) == l->pk_fnv &&
			  fnv1a64(sk, l->sk_len) == l->sk_fnv))
		return fails + 1;

	for (unsigned i = 0; i < 32; i++)
		coins[i] = (uint8_t)(0x40 + i);           /* m */
	fails += check("encaps KAT  ", l->enc(ct, ss_a, pk, coins) == 0 &&
				 fnv1a64(ct, l->ct_len) == l->ct_fnv &&
				 memcmp(ss_a, l->ss, SS_BYTES) == 0);

	fails += check("decaps      ", l->dec(ss_b, ct, sk) == 0 &&
				 memcmp(ss_b, l->ss, SS_BYTES) == 0);

	/* Implicit rejection: ML-KEM does not report an error for a bad
	 * ciphertext, it returns J(z || ct) -- a fixed, known value here. */
	ct[0] ^= 0x01;
	fails += check("reject KAT  ", l->dec(ss_b, ct, sk) == 0 &&
				 memcmp(ss_b, l->rej, SS_BYTES) == 0);
	ct[0] ^= 0x01;

	return fails;
}

int main(void)
{
	int fails = 0;

	test_console_init();

	kprintf("\r\n=== ML-KEM (FIPS 203, mlkem-native) test — levels 512/768/1024 ===\r\n");

	for (unsigned i = 0; i < sizeof(levels) / sizeof(levels[0]); i++)
		fails += run_level(&levels[i]);

	kprintf("\r\nMLKEM TEST: %s (%d failures)\r\n",
		fails ? "FAIL" : "PASS", fails);
	while (1)
		;
	return 0;
}
