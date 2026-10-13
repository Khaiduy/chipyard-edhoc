/*
 * edhoc_responder.c - EDHOC responder board program for one method
 * (-DEDHOC_METHOD, see include/edhoc_app.h) and one cipher suite
 * (-DEDHOC_CRYPTO_SUITE).
 */
#include <string.h>
#include "edhoc_app.h"
#include "edhoc_board.h"
#include "edhoc_transport.h"
#include "kprintf.h"
#include "perf.h"
#include "secure_wipe.h"

extern void csprng_add_entropy(const uint8_t *data, uint32_t len);

static struct edhoc_responder_context ctx;
static struct other_party_cred peer;
static uint8_t eph_sk[SUITE_DH_LEN], eph_pk[SUITE_DH_LEN];
static uint8_t prk_out_buf[SUITE_PRK_LEN], err_msg_buf[64];

int main(void)
{
	static const uint8_t role[] = "responder";
	struct cred_array peers = { .len = 1, .ptr = &peer };
	struct byte_array prk_out = { .ptr = prk_out_buf, .len = sizeof(prk_out_buf) };
	struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };

	board_init(1);
	/* Make the two boards' CSPRNG states differ even if their timing
	 * entropy happens to match. */
	csprng_add_entropy(role, sizeof(role));

	uint64_t t = read_cycles();
	app_ephemeral_key(eph_sk, eph_pk);
	perf_step("keygen           ", read_cycles() - t);
	app_responder_ctx(&ctx, &peer, eph_sk, eph_pk);

	kprintf("EDHOC running...\r\n");
	uint64_t t0 = read_cycles();
	enum err r = edhoc_responder_run(&ctx, &peers, &err_msg, &prk_out,
			tx_responder, rx_responder, ead_process);
	uint64_t t1 = read_cycles();
	if (r != ok) {
		kprintf("EDHOC FAIL: %d\r\n", r);
		while (1)
			;
	}
	kprintf("EDHOC OK!\r\n");
	board_report(t0, t1);
	board_app_data(&prk_out, 0);

	app_wipe_keys();
	edhoc_wipe(eph_sk, sizeof(eph_sk));
	edhoc_wipe(prk_out_buf, sizeof(prk_out_buf));
	transport_idle();
}
