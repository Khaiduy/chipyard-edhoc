/* edhoc_app.c - see include/edhoc_app.h. */
#include <string.h>
#include "edhoc_app.h"
#include "edhoc/edhoc_method_type.h"
#include "common/crypto_wrapper.h"
#include "edhoc_cred_builder.h"
#ifdef EDHOC_PROFILE_PRODUCTION
#include "edhoc_provision.h"
/* Provisioning (include/edhoc_provision.h) covers signing keys only. */
#if EDHOC_METHOD != 0
#error "PROFILE=production supports method 0 only: static DH keys are not provisioned"
#endif
#else
#include "edhoc_demo_keys.h"
#endif

extern int default_CSPRNG(uint8_t *dest, unsigned int size);

#define AUTH_SK_MAX (SUITE_SIGN_SK_LEN > SUITE_DH_LEN ? SUITE_SIGN_SK_LEN : SUITE_DH_LEN)
#define AUTH_PK_MAX (SUITE_SIGN_PK_LEN > SUITE_DH_LEN ? SUITE_SIGN_PK_LEN : SUITE_DH_LEN)

/* One party's authentication key -- a signature key pair or a static DH key
 * pair, by method -- and the CCS credential carrying its public key. */
struct party {
	uint8_t sk[AUTH_SK_MAX];
	uint8_t pk[AUTH_PK_MAX];
	uint32_t sk_len, pk_len;
	uint8_t cred[CRED_BUF_MAX];
	uint32_t cred_len;
	uint8_t id_cred[4];     /* { 4: h'kid' } */
};

static struct party party_i, party_r;
static const uint8_t c_i[] = { 0x2d };      /* C_I = -14 */
static const uint8_t c_r[] = { 0x0e };      /* C_R = 14 */
static const uint8_t suites[] = { SUITE_BYTE };

#ifndef EDHOC_PROFILE_PRODUCTION
/* Demo seeds: 32 bytes, zero-padded to the suite's key length. */
static const uint8_t i_sign_seed[] = EDHOC_DEMO_I_SIGN_SEED;
static const uint8_t r_sign_seed[] = EDHOC_DEMO_R_SIGN_SEED;
static const uint8_t i_dh_seed[] = EDHOC_DEMO_I_DH_SEED;
static const uint8_t r_dh_seed[] = EDHOC_DEMO_R_DH_SEED;
#endif

static void party_init(struct party *p, int signs, const uint8_t *seed,
		       const char *name, uint8_t kid)
{
	memset(p, 0, sizeof(*p));
#ifdef EDHOC_PROFILE_PRODUCTION
	/* Method 0 only: own key pair from the key store, peer public key
	 * provisioned (seed is NULL for the own party, non-NULL for the peer). */
	(void)signs;
	if (seed == NULL) {
		memcpy(p->sk, edhoc_device_sign_sk(), SUITE_SIGN_SK_LEN);
		memcpy(p->pk, edhoc_device_sign_pk(), SUITE_SIGN_PK_LEN);
	} else {
		memcpy(p->pk, edhoc_peer_sign_pk(), SUITE_SIGN_PK_LEN);
	}
	p->sk_len = SUITE_SIGN_SK_LEN;
	p->pk_len = SUITE_SIGN_PK_LEN;
	signs = 1;
#else
	memcpy(p->sk, seed, 32);
	if (signs) {
		struct byte_array sk = { .ptr = p->sk, .len = SUITE_SIGN_SK_LEN };
		struct byte_array pk = { .ptr = p->pk, .len = SUITE_SIGN_PK_LEN };
		uint8_t s[SUITE_SIGN_SK_LEN] = { 0 };

		memcpy(s, seed, 32);
		sign_key_gen(SUITE_SIGN_ALG, s, &sk, &pk);
		p->sk_len = SUITE_SIGN_SK_LEN;
		p->pk_len = SUITE_SIGN_PK_LEN;
	} else {
		struct byte_array sk = { .ptr = p->sk, .len = SUITE_DH_LEN };
		struct byte_array pk = { .ptr = p->pk, .len = SUITE_DH_LEN };

		ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &sk, &pk);
		p->sk_len = SUITE_DH_LEN;
		p->pk_len = SUITE_DH_LEN;
	}
#endif
	p->cred_len = build_ccs_credential(p->cred, name, &kid, 1, p->pk,
					   p->pk_len, signs ? SUITE_CRV_SIGN :
							      SUITE_CRV_DH);
	p->id_cred[0] = 0xa1;
	p->id_cred[1] = 0x04;
	p->id_cred[2] = 0x41;   /* kid is a byte string (COSE, RFC 9052) */
	p->id_cred[3] = kid;
}

static void parties_init(int own_is_initiator)
{
#ifdef EDHOC_PROFILE_PRODUCTION
	static const uint8_t peer;
	party_init(&party_i, 1, own_is_initiator ? NULL : &peer, "Init", 0x01);
	party_init(&party_r, 1, own_is_initiator ? &peer : NULL, "Resp", 0x02);
#else
	(void)own_is_initiator;
	party_init(&party_i, APP_I_SIGNS, APP_I_SIGNS ? i_sign_seed : i_dh_seed,
		   "Init", 0x01);
	party_init(&party_r, APP_R_SIGNS, APP_R_SIGNS ? r_sign_seed : r_dh_seed,
		   "Resp", 0x02);
#endif
}

static void peer_entry(struct other_party_cred *e, struct party *p, int signs)
{
	memset(e, 0, sizeof(*e));
	e->id_cred = (struct byte_array){ .ptr = p->id_cred, .len = sizeof(p->id_cred) };
	e->cred = (struct byte_array){ .ptr = p->cred, .len = p->cred_len };
	if (signs)
		e->pk = (struct byte_array){ .ptr = p->pk, .len = p->pk_len };
	else
		e->g = (struct byte_array){ .ptr = p->pk, .len = p->pk_len };
}

void app_ephemeral_key(uint8_t *sk, uint8_t *pk)
{
	struct byte_array s = { .ptr = sk, .len = SUITE_DH_LEN };
	struct byte_array p = { .ptr = pk, .len = SUITE_DH_LEN };

	default_CSPRNG(sk, SUITE_DH_LEN);
	ephemeral_dh_key_gen(SUITE_ECDH_ALG, 0, &s, &p);
}

void app_initiator_ctx(struct edhoc_initiator_context *c,
		       struct other_party_cred *peer, uint8_t *x, uint8_t *g_x)
{
	struct party *p = &party_i;

	parties_init(1);
	memset(c, 0, sizeof(*c));
	c->method = (enum method_type)EDHOC_METHOD;
	c->c_i = (struct byte_array){ .ptr = (uint8_t *)c_i, .len = sizeof(c_i) };
	c->suites_i = (struct byte_array){ .ptr = (uint8_t *)suites, .len = sizeof(suites) };
	c->x = (struct byte_array){ .ptr = x, .len = SUITE_DH_LEN };
	c->g_x = (struct byte_array){ .ptr = g_x, .len = SUITE_DH_LEN };
#if APP_I_SIGNS
	c->sk_i = (struct byte_array){ .ptr = p->sk, .len = p->sk_len };
	c->pk_i = (struct byte_array){ .ptr = p->pk, .len = p->pk_len };
#else
	c->i = (struct byte_array){ .ptr = p->sk, .len = p->sk_len };
	c->g_i = (struct byte_array){ .ptr = p->pk, .len = p->pk_len };
#endif
	c->id_cred_i = (struct byte_array){ .ptr = p->id_cred, .len = sizeof(p->id_cred) };
	c->cred_i = (struct byte_array){ .ptr = p->cred, .len = p->cred_len };
	peer_entry(peer, &party_r, APP_R_SIGNS);
}

void app_responder_ctx(struct edhoc_responder_context *c,
		       struct other_party_cred *peer, uint8_t *y, uint8_t *g_y)
{
	struct party *p = &party_r;

	parties_init(0);
	memset(c, 0, sizeof(*c));
	c->c_r = (struct byte_array){ .ptr = (uint8_t *)c_r, .len = sizeof(c_r) };
	c->suites_r = (struct byte_array){ .ptr = (uint8_t *)suites, .len = sizeof(suites) };
	c->y = (struct byte_array){ .ptr = y, .len = SUITE_DH_LEN };
	c->g_y = (struct byte_array){ .ptr = g_y, .len = SUITE_DH_LEN };
#if APP_R_SIGNS
	c->sk_r = (struct byte_array){ .ptr = p->sk, .len = p->sk_len };
	c->pk_r = (struct byte_array){ .ptr = p->pk, .len = p->pk_len };
#else
	c->r = (struct byte_array){ .ptr = p->sk, .len = p->sk_len };
	c->g_r = (struct byte_array){ .ptr = p->pk, .len = p->pk_len };
#endif
	c->id_cred_r = (struct byte_array){ .ptr = p->id_cred, .len = sizeof(p->id_cred) };
	c->cred_r = (struct byte_array){ .ptr = p->cred, .len = p->cred_len };
	peer_entry(peer, &party_i, APP_I_SIGNS);
}

void app_wipe_keys(void)
{
	volatile uint8_t *v = party_i.sk;
	for (uint32_t n = 0; n < sizeof(party_i.sk); n++)
		v[n] = 0;
	v = party_r.sk;
	for (uint32_t n = 0; n < sizeof(party_r.sk); n++)
		v[n] = 0;
}
