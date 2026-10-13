/*
 * test_loopback.c - full RFC 9528 handshake on the host, initiator and
 * responder as two threads exchanging messages through memory, built from the
 * same library, crypto and src/edhoc_app.c as the firmware.
 *
 *   make loopback-test CRYPTO_SUITE=<s> METHOD=<m>
 *
 * Passes when both roles finish and derive the same PRK_out.
 */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edhoc_app.h"

/* Firmware services the library and crypto expect. */
void kprintf(const char *fmt, ...)
{
	va_list ap;

	if (getenv("LOOPBACK_VERBOSE")) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}
void kputc(char c) { if (getenv("LOOPBACK_VERBOSE")) fputc(c, stderr); }

/* Deterministic CSPRNG: this test checks agreement, not randomness. */
static pthread_mutex_t rng_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t rng = 0x243f6a8885a308d3ull;
int default_CSPRNG(uint8_t *d, unsigned int n)
{
	pthread_mutex_lock(&rng_lock);
	while (n--) {
		rng = rng * 6364136223846793005ull + 1442695040888963407ull;
		*d++ = (uint8_t)(rng >> 56);
	}
	pthread_mutex_unlock(&rng_lock);
	return 1;
}
void csprng_add_entropy(const uint8_t *d, uint32_t n) { (void)d; (void)n; }
int csprng_generate_block(unsigned char *o, unsigned int n) { return default_CSPRNG(o, n) == 1 ? 0 : -1; }

/* One message in flight per direction. */
struct chan {
	pthread_mutex_t m;
	pthread_cond_t c;
	uint8_t buf[2048];
	uint32_t len;
	int full;
};
static struct chan to_r = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, {0}, 0, 0 };
static struct chan to_i = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, {0}, 0, 0 };

static enum err put(struct chan *ch, struct byte_array *d)
{
	pthread_mutex_lock(&ch->m);
	while (ch->full)
		pthread_cond_wait(&ch->c, &ch->m);
	memcpy(ch->buf, d->ptr, d->len);
	ch->len = d->len;
	ch->full = 1;
	pthread_cond_broadcast(&ch->c);
	pthread_mutex_unlock(&ch->m);
	return ok;
}

static enum err get(struct chan *ch, struct byte_array *d)
{
	pthread_mutex_lock(&ch->m);
	while (!ch->full)
		pthread_cond_wait(&ch->c, &ch->m);
	if (ch->len > d->len) {
		pthread_mutex_unlock(&ch->m);
		return buffer_to_small;
	}
	memcpy(d->ptr, ch->buf, ch->len);
	d->len = ch->len;
	ch->full = 0;
	pthread_cond_broadcast(&ch->c);
	pthread_mutex_unlock(&ch->m);
	return ok;
}

static enum err tx_i(void *s, struct byte_array *d) { (void)s; return put(&to_r, d); }
static enum err rx_i(void *s, struct byte_array *d) { (void)s; return get(&to_i, d); }
static enum err tx_r(void *s, struct byte_array *d) { (void)s; return put(&to_i, d); }
static enum err rx_r(void *s, struct byte_array *d) { (void)s; return get(&to_r, d); }
static enum err no_ead(void *p, struct byte_array *e) { (void)p; (void)e; return ok; }

static uint8_t prk_i[SUITE_PRK_LEN], prk_r[SUITE_PRK_LEN];
static enum err res_i = -1, res_r = -1;

/* Both contexts are built before the threads start: they share the demo
 * identities, which app_*_ctx() (re)derive. */
static struct edhoc_initiator_context ci;
static struct edhoc_responder_context cr;
static struct other_party_cred peer_r, peer_i;
static uint8_t x[SUITE_DH_LEN], g_x[SUITE_DH_LEN], y[SUITE_DH_LEN], g_y[SUITE_DH_LEN];

static void *initiator(void *arg)
{
	static uint8_t err[64];
	struct cred_array creds = { .len = 1, .ptr = &peer_r };
	struct byte_array prk = { .ptr = prk_i, .len = sizeof(prk_i) };
	struct byte_array e = { .ptr = err, .len = sizeof(err) };

	(void)arg;
	res_i = edhoc_initiator_run(&ci, &creds, &e, &prk, tx_i, rx_i, no_ead);
	return NULL;
}

static void *responder(void *arg)
{
	static uint8_t err[64];
	struct cred_array creds = { .len = 1, .ptr = &peer_i };
	struct byte_array prk = { .ptr = prk_r, .len = sizeof(prk_r) };
	struct byte_array e = { .ptr = err, .len = sizeof(err) };

	(void)arg;
	res_r = edhoc_responder_run(&cr, &creds, &e, &prk, tx_r, rx_r, no_ead);
	return NULL;
}

int main(void)
{
	pthread_t ti, tr;

	app_ephemeral_key(x, g_x);
	app_ephemeral_key(y, g_y);
	app_initiator_ctx(&ci, &peer_r, x, g_x);
	app_responder_ctx(&cr, &peer_i, y, g_y);
	pthread_create(&tr, NULL, responder, NULL);
	pthread_create(&ti, NULL, initiator, NULL);
	pthread_join(ti, NULL);
	pthread_join(tr, NULL);
	int pass = res_i == ok && res_r == ok &&
		   memcmp(prk_i, prk_r, sizeof(prk_i)) == 0;
	printf("loopback suite %d method %d: initiator %d responder %d, PRK_out %s -> %s\n",
	       EDHOC_CRYPTO_SUITE, EDHOC_METHOD, res_i, res_r,
	       memcmp(prk_i, prk_r, sizeof(prk_i)) ? "differ" : "match",
	       pass ? "PASS" : "FAIL");
	return pass ? 0 : 1;
}
