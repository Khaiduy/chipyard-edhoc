/*
 * test_loopback.c - host test: full five-message Method 5 handshake between
 * an Initiator and a Responder thread over an in-memory link.
 *
 * Checks that both sides reach EDHOC OK with the same PRK_out, and writes the
 * transcript (message_1..message_5_KEM, the Initiator's ephemeral secret key
 * and PRK_out) to the file named by argv[1], if any, for the independent
 * reference model in tools/authkem_ref.py.
 */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "edhoc.h"
#include "authkem_test_keys.h"
#include "authkem_cred.h"
#include "authkem_creds.h"
#include "edhoc/suites.h"
#include "edhoc_app_data.h"

/* ---- platform stubs ---------------------------------------------------- */
int default_CSPRNG(uint8_t *dest, unsigned int size)
{
	FILE *f = fopen("/dev/urandom", "rb");
	size_t n = f ? fread(dest, 1, size, f) : 0;
	if (f)
		fclose(f);
	return n == size;
}

void kprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

/* ---- in-memory link ---------------------------------------------------- */
struct q { pthread_mutex_t m; pthread_cond_t c; uint8_t buf[4096]; uint32_t len; int full; };
static struct q to_r = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER };
static struct q to_i = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER };

static uint8_t transcript[5][4096];
static uint32_t transcript_len[5];
static int msg_no;
static pthread_mutex_t tm = PTHREAD_MUTEX_INITIALIZER;

static enum err put(struct q *q, struct byte_array *d)
{
	pthread_mutex_lock(&tm);
	if (msg_no < 5) {
		memcpy(transcript[msg_no], d->ptr, d->len);
		transcript_len[msg_no++] = d->len;
	}
	pthread_mutex_unlock(&tm);
	pthread_mutex_lock(&q->m);
	while (q->full)
		pthread_cond_wait(&q->c, &q->m);
	memcpy(q->buf, d->ptr, d->len);
	q->len = d->len;
	q->full = 1;
	pthread_cond_broadcast(&q->c);
	pthread_mutex_unlock(&q->m);
	return ok;
}

static enum err get(struct q *q, struct byte_array *d)
{
	pthread_mutex_lock(&q->m);
	while (!q->full)
		pthread_cond_wait(&q->c, &q->m);
	enum err r = q->len <= d->len ? ok : buffer_to_small;
	if (r == ok) {
		memcpy(d->ptr, q->buf, q->len);
		d->len = q->len;
	}
	q->full = 0;
	pthread_cond_broadcast(&q->c);
	pthread_mutex_unlock(&q->m);
	return r;
}

static enum err tx_i(void *s, struct byte_array *d) { (void)s; return put(&to_r, d); }
static enum err rx_i(void *s, struct byte_array *d) { (void)s; return get(&to_i, d); }
static enum err tx_r(void *s, struct byte_array *d) { (void)s; return put(&to_i, d); }
static enum err rx_r(void *s, struct byte_array *d) { (void)s; return get(&to_r, d); }
static enum err ead_noop(void *p, struct byte_array *e) { (void)p; (void)e; return ok; }

/* ---- parties ----------------------------------------------------------- */
static const uint8_t suites[] = { AUTHKEM_SUITE_BYTE };
static uint8_t id_cred_i[] = { 0xa1, 0x04, 0x41, 0x01 };
static uint8_t id_cred_r[] = { 0xa1, 0x04, 0x41, 0x02 };
static uint8_t x_eph[KEM_SK_SIZE], g_x[KEM_PK_SIZE];
static uint8_t prk_i[PRK_SIZE], prk_r[PRK_SIZE];
static enum err res_i, res_r;

/* ID_CRED each role hands its application (RFC 9528 3.5); params is where
 * to record it. */
struct seen { uint8_t b[16]; uint32_t n; };
static struct seen seen_by_i, seen_by_r;
static enum err id_cred_record(void *params, const struct byte_array *id_cred)
{
	struct seen *v = params;

	v->n = id_cred->len <= sizeof(v->b) ? id_cred->len : 0;
	memcpy(v->b, id_cred->ptr, v->n);
	return ok;
}

static void *initiator(void *a)
{
	(void)a;
	static const uint8_t c_i[] = { 0x2d };
	static struct other_party_cred cr;
	struct edhoc_initiator_context c;
	memset(&c, 0, sizeof(c));
	c.method = INITIATOR_KEM_RESPONDER_KEM;
	c.suites_i = (struct byte_array){ .ptr = (uint8_t *)suites, .len = sizeof(suites) };
	c.c_i = (struct byte_array){ .ptr = (uint8_t *)c_i, .len = sizeof(c_i) };
	c.id_cred_i = (struct byte_array){ .ptr = id_cred_i, .len = sizeof(id_cred_i) };
	c.cred_i = (struct byte_array){ .ptr = (uint8_t *)CRED_I_CCS, .len = CRED_I_CCS_LEN };
	c.g_x = (struct byte_array){ .ptr = g_x, .len = sizeof(g_x) };
	c.x = (struct byte_array){ .ptr = x_eph, .len = sizeof(x_eph) };
	c.i = (struct byte_array){ .ptr = (uint8_t *)INIT_SK, .len = KEM_SK_SIZE };
	c.id_cred_check = id_cred_record;
	c.params_id_cred_check = &seen_by_i;
	cr.cred = (struct byte_array){ .ptr = (uint8_t *)CRED_R_CCS, .len = CRED_R_CCS_LEN };
	cr.id_cred = (struct byte_array){ .ptr = id_cred_r, .len = sizeof(id_cred_r) };
	cr.g = (struct byte_array){ .ptr = (uint8_t *)CRED_R_PK, .len = KEM_PK_SIZE };
	struct cred_array arr = { .len = 1, .ptr = &cr };
	uint8_t cr_buf[4], err_buf[64];
	struct byte_array c_r = { .ptr = cr_buf, .len = sizeof(cr_buf) };
	struct byte_array err = { .ptr = err_buf, .len = sizeof(err_buf) };
	struct byte_array prk = { .ptr = prk_i, .len = sizeof(prk_i) };
	res_i = edhoc_initiator_run_authkem(&c, &arr, &err, &c_r, &prk, tx_i, rx_i, ead_noop);
	return NULL;
}

static void *responder(void *a)
{
	(void)a;
	static const uint8_t c_r[] = { 0x27 };
	static struct other_party_cred ci;
	struct edhoc_responder_context c;
	memset(&c, 0, sizeof(c));
	c.c_r = (struct byte_array){ .ptr = (uint8_t *)c_r, .len = sizeof(c_r) };
	c.suites_r = (struct byte_array){ .ptr = (uint8_t *)suites, .len = sizeof(suites) };
	c.id_cred_r = (struct byte_array){ .ptr = id_cred_r, .len = sizeof(id_cred_r) };
	c.cred_r = (struct byte_array){ .ptr = (uint8_t *)CRED_R_CCS, .len = CRED_R_CCS_LEN };
	c.r = (struct byte_array){ .ptr = (uint8_t *)RESP_SK, .len = KEM_SK_SIZE };
	c.id_cred_check = id_cred_record;
	c.params_id_cred_check = &seen_by_r;
	ci.cred = (struct byte_array){ .ptr = (uint8_t *)CRED_I_CCS, .len = CRED_I_CCS_LEN };
	ci.id_cred = (struct byte_array){ .ptr = id_cred_i, .len = sizeof(id_cred_i) };
	ci.g = (struct byte_array){ .ptr = (uint8_t *)CRED_I_PK, .len = KEM_PK_SIZE };
	struct cred_array arr = { .len = 1, .ptr = &ci };
	uint8_t err_buf[64];
	struct byte_array err = { .ptr = err_buf, .len = sizeof(err_buf) };
	struct byte_array prk = { .ptr = prk_r, .len = sizeof(prk_r) };
	res_r = edhoc_responder_run_authkem(&c, &arr, &err, &prk, tx_r, rx_r, ead_noop);
	return NULL;
}

static void hex(FILE *f, const char *k, const uint8_t *p, uint32_t n)
{
	fprintf(f, "%s=", k);
	for (uint32_t i = 0; i < n; i++)
		fprintf(f, "%02x", p[i]);
	fprintf(f, "\n");
}

int main(int argc, char **argv)
{
	pthread_t ti, tr;
	pthread_create(&tr, NULL, responder, NULL);
	pthread_create(&ti, NULL, initiator, NULL);
	pthread_join(ti, NULL);
	pthread_join(tr, NULL);

	int pass = res_i == ok && res_r == ok && !memcmp(prk_i, prk_r, sizeof(prk_i));
	int seen = seen_by_i.n == sizeof(id_cred_r) &&
		   !memcmp(seen_by_i.b, id_cred_r, sizeof(id_cred_r)) &&
		   seen_by_r.n == sizeof(id_cred_i) &&
		   !memcmp(seen_by_r.b, id_cred_i, sizeof(id_cred_i));
	printf("loopback: ID_CRED to application %s\n", seen ? "match" : "MISMATCH");
	pass &= seen;

	/* Application key and IV the way app_data_init() derives them: the
	 * EDHOC_Exporter on the suite's EDHOC hash (RFC 9528 Section 4.2.1). */
	struct suite ste;
	uint8_t exp_buf[64], key[32], iv[13];   /* A256GCM: 32/12, AES-CCM: 16/13 */
	struct byte_array prk = { .ptr = prk_i, .len = sizeof(prk_i) };
	struct byte_array exp = { .ptr = exp_buf, .len = 0 };
	struct byte_array k = { .ptr = key, .len = 0 }, n = { .ptr = iv, .len = 0 };
	pass &= get_suite((enum suite_label)(int8_t)suites[0], &ste) == ok;
	exp.len = get_hash_len(ste.edhoc_hash);
	k.len = get_aead_key_len(ste.app_aead);
	n.len = get_aead_iv_len(ste.app_aead);
	pass &= prk_out2exporter(ste.edhoc_hash, &prk, &exp) == ok &&
		edhoc_exporter(ste.edhoc_hash, APP_KEY_LABEL, &exp, &k) == ok &&
		edhoc_exporter(ste.edhoc_hash, APP_IV_LABEL, &exp, &n) == ok;
	printf("loopback: initiator %d responder %d, PRK_out %s\n", res_i, res_r,
	       pass ? "match" : "MISMATCH");
	if (argc > 1) {
		FILE *f = fopen(argv[1], "w");
		for (int i = 0; i < msg_no; i++) {
			char k[8];
			snprintf(k, sizeof(k), "msg%d", i + 1);
			hex(f, k, transcript[i], transcript_len[i]);
		}
		hex(f, "sk_eph", x_eph, sizeof(x_eph));
		hex(f, "prk_out", prk_i, sizeof(prk_i));
		hex(f, "app_key", key, k.len);
		hex(f, "app_iv", iv, n.len);
		fclose(f);
	}
	return pass ? 0 : 1;
}
