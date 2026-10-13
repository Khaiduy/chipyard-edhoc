/* EDHOC Responder - Board B - Method 5 AUTHKEM
 * (draft-ietf-lake-authkem-edhoc-01, ML-KEM-512, no signatures)
 *
 * Cipher suite draft-ietf-lake-pqsuites-01 TBD2 (private-use label -24 until
 * assigned): A256GCM, SHAKE256, EDHOC MAC length 16, ML-KEM-512, ML-DSA-44,
 * application AEAD A256GCM, application hash SHA-256.
 *
 * Message flow (five messages):
 *   rx(msg1) -> tx(msg2) -> rx(msg3) -> tx(msg4_KEM) -> rx(msg5_KEM)
 *   PRK_out available once msg5 is verified.
 */
#include <string.h>
#include <stdint.h>
#include "kprintf.h"
#include "stack_probe.h"
#include "uart.h"
#include "edhoc.h"
#include "edhoc_transport.h"
#include "perf.h"

extern volatile uint64_t g_uart_cycles;
#include "edhoc_app_data.h"
#include "common/print_util.h"
#ifdef EDHOC_PROFILE_PRODUCTION
#include "authkem_provision.h"
#else
#include "authkem_test_keys.h"
#endif
#include "authkem_cred.h"
#include "authkem_creds.h"   /* generated: CRED_I_CCS / CRED_R_CCS in .rodata */
#include "uart.h"

extern int  default_CSPRNG(uint8_t *dest, unsigned int size);
extern void csprng_add_entropy(const uint8_t *data, uint32_t len);

/* KEM_SK_SIZE / KEM_PK_SIZE / PRK_SIZE come from edhoc/buffer_sizes.h */

/* Responder static KEM key pair — replace with provisioned keys */
/* Constants in .rodata; see the matching note in edhoc_initiator_authkem.c.
 * Credentials are generated at build time (tools/gen_ccs.c) and the raw
 * public keys are read from inside them, so nothing is stored twice and
 * nothing is rebuilt into .bss at boot. The casts drop const only for
 * struct byte_array's non-const ptr -- the library only reads them. */
#ifdef EDHOC_PROFILE_PRODUCTION
/* Supplied by PROVISION_SRC; no default exists, so a missing implementation
 * is a link error. See include/authkem_provision.h. */
#define AUTHKEM_OWN_STATIC_SK() authkem_device_static_sk()
#else
#define AUTHKEM_OWN_STATIC_SK() RESP_SK
#endif
static uint8_t *r_sk;
static uint8_t *const g_i_init   = (uint8_t *)CRED_I_PK;
static uint8_t *const cred_r_buf = (uint8_t *)CRED_R_CCS;
static uint8_t *const cred_i_buf = (uint8_t *)CRED_I_CCS;
static const uint32_t cred_r_len = CRED_R_CCS_LEN;
static const uint32_t cred_i_len = CRED_I_CCS_LEN;

static const uint8_t c_r_val[]  = {0x27};
static const uint8_t suites_r[] = { AUTHKEM_SUITE_BYTE };   /* pqsuites TBD2 or TBD3 */

static uint8_t id_cred_r_buf[] = {0xa1, 0x04, 0x41, 0x02};
static uint8_t id_cred_i_buf[] = {0xa1, 0x04, 0x41, 0x01};

static uint8_t prk_out_buf[PRK_SIZE];
static uint8_t err_msg_buf[64];

static enum err ead_noop(void *p, struct byte_array *ead)
{
    (void)p; (void)ead; return ok;
}

#define EDHOC_UART_BAUD 57600u
#define EDHOC_UART_DIV  (PERF_CPU_HZ / EDHOC_UART_BAUD)

int main(void)
{
    /* UART init. Divisor derived from PERF_CPU_HZ so it tracks the bitstream
     * clock; SiFive UART gives baud = f_pbus / (div + 1). */
    REG32(uart, UART_REG_DIV) = EDHOC_UART_DIV;
    REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_DIV) = EDHOC_UART_DIV;
    REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
    REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;

    /* Startup settle -- see the matching comment in the wolfCrypt apps. These
     * images are JTAG-loaded with halt/resume and never a reset, so loading the
     * peer board glitches bytes onto UART1. The responder must not be scanning
     * while that happens, or it consumes the glitch AND message_1 as one bogus
     * frame; EDHOC never retransmits, so the handshake then hangs. */
    for (volatile uint32_t _s = 0; _s < 40000000; _s++) { (void)_s; }

    kprintf("=== EDHOC Method 5 AUTHKEM (draft-ietf-lake-authkem-edhoc-01, pqsuites TBD%d) Responder (ML-KEM-%d) ===\r\n",
            AUTHKEM_PQ_SUITE, MLK_CONFIG_PARAMETER_SET);

    /* Drain UART1 before the protocol starts.
     *
     * These images are loaded over JTAG onto boards that are never power
     * cycled, so the link still holds bytes from the previous session. The
     * transport's frame-sync scan skips stale bytes, but old traffic contains
     * the same 0xED 0xC0 preamble, so it can lock onto a stale frame and hand
     * the decoder garbage -- which surfaces as cbor_decoding_error (120)
     * before the initiator has even sent message_1.
     *
     * Read until the line has been quiet for a while, then start. */
    {
        /* Sizing matters here. Each poll is an uncached MMIO read, roughly 20
         * cycles, so the budget below is tens of milliseconds at 50 MHz -- long
         * enough to clear a stale FIFO, and far shorter than the seconds it
         * takes before a real message_1 can arrive. An over-long drain would
         * swallow message_1 itself and then wait forever for it. */
        uint32_t quiet = 0;
        uint32_t budget = 100000;       /* ~40 ms  */
        uint32_t dropped = 0;

        while (quiet < 2000 && budget-- > 0) {   /* ~2 byte times of silence */
            if (uart1_getc() >= 0) {
                quiet = 0;
                dropped++;
            } else {
                quiet++;
            }
        }
        kprintf("resp: link idle (dropped %u stale bytes)\r\n",
                (unsigned)dropped);
    }

    volatile uint64_t t_start = read_cycles();
    volatile uint32_t seed = (uint32_t)(t_start & 0xFFFFFFFF);
    csprng_add_entropy((const uint8_t *)&seed, sizeof(seed));


    r_sk = (uint8_t *)AUTHKEM_OWN_STATIC_SK();

    struct edhoc_responder_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.c_r       = (struct byte_array){ .ptr = (uint8_t *)c_r_val,  .len = sizeof(c_r_val) };
    ctx.suites_r  = (struct byte_array){ .ptr = (uint8_t *)suites_r, .len = sizeof(suites_r) };
    ctx.id_cred_r = (struct byte_array){ .ptr = id_cred_r_buf,        .len = sizeof(id_cred_r_buf) };
    ctx.cred_r    = (struct byte_array){ .ptr = cred_r_buf,           .len = cred_r_len };
    ctx.r         = (struct byte_array){ .ptr = r_sk,                 .len = KEM_SK_SIZE };
    ctx.sock      = NULL;
    ctx.params_ead_process = NULL;

    static struct other_party_cred cred_i_entry;
    cred_i_entry.cred.ptr    = cred_i_buf;
    cred_i_entry.cred.len    = cred_i_len;
    cred_i_entry.id_cred.ptr = id_cred_i_buf;
    cred_i_entry.id_cred.len = sizeof(id_cred_i_buf);
    cred_i_entry.g.ptr       = g_i_init;
    cred_i_entry.g.len       = KEM_PK_SIZE;
    struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i_entry };

    struct byte_array prk_out = { .ptr = prk_out_buf, .len = sizeof(prk_out_buf) };
    struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };

    /* Link accounting starts at zero for the measured region. */

    g_uart_cycles = 0;

    volatile uint64_t t0 = read_cycles();
    enum err result = edhoc_responder_run_authkem(
        &ctx, &cred_i_array, &err_msg, &prk_out,
        tx_responder, rx_responder, ead_noop);
    volatile uint64_t t1 = read_cycles();

    if (result != ok) {
        kprintf("EDHOC FAIL: %d\r\n", result);
        while (1);
    }

/* Always on: this is three prints using counters that are read anyway.
 * TIMING=1 additionally enables the library's per-stage TIME_STEP macros,
 * whose extra locals in the handshake frame overflow the stack on this
 * 64 kB target -- so the summary must not depend on it. */
	{
		/* Requirement A5 asks for the cost of the handshake itself. The
		 * transport is a 57600-baud UART with a software pacing loop, so
		 * wall time is dominated by the link, not the protocol. Report the
		 * link separately and subtract it: "compute" is the pure
		 * cryptographic + CBOR work. */
		uint64_t total = t1 - t0;
		uint64_t link  = g_uart_cycles;
		uint64_t comp  = (total > link) ? (total - link) : 0;

		perf_step("handshake_total  ", total);
		perf_step("handshake_link   ", link);
		perf_step("handshake_compute", comp);
#ifdef TIMING_BREAKDOWN
		perf_marks_print();    /* compute time of each message step */
#endif
	}

	/* Peak stack depth reached by this run, measured from the canary crt0
	 * painted over the reservation. This is the number STACK_SIZE must be
	 * derived from; headroom 0 means the mark hit the bottom and the stack
	 * may already have run into .bss. */
	kprintf("STACK peak %u B, reserve %u B, free %u B, headroom %u%s\r\n",
		(unsigned)stack_highwater(), (unsigned)stack_reserve(),
		(unsigned)stack_free_region(), (unsigned)stack_headroom(),
		stack_overran_reserve() ? "  OVERRAN-RESERVE" : "");
	kprintf("STACK canary-left %u B\r\n", (unsigned)stack_canary_bytes());

#ifdef DEBUG_PRINT
    /* The session secret: DEBUG=1 builds only (run_pair.sh compares the two). */
    kprintf("-----------------------\r\n");
    kprintf("PRK_out (%u bytes):\r\n  ", (unsigned)prk_out.len);
    for (uint32_t i = 0; i < prk_out.len; i++)
        kprintf("%02X ", prk_out.ptr[i]);
    kprintf("\r\n");

    uint8_t xor = 0;
    for (uint32_t i = 0; i < prk_out.len; i++) xor ^= prk_out.ptr[i];
    kprintf("[xor:0x%02X]\r\n", xor);
#endif

    /* "EDHOC OK" is the loader's completion marker — print it LAST. */
    kprintf("EDHOC OK!\r\n");

    /*========================================================================
     * APPLICATION DATA OVER THE EDHOC SHARED SECRET
     *
     * Suite-independent: app_data_init() reads the AEAD, its key/IV/tag sizes
     * and the hash from get_suite() at run time, so this block does not change
     * if the negotiated suite changes.
     *========================================================================*/
    {
        static struct app_chan app_ch;
        enum err app_res = app_data_init(&app_ch, (enum suite_label)(int8_t)suites_r[0],
                                         &prk_out, 0);

        if (app_res != ok) {
            kprintf("APP init FAIL: %d\r\n", app_res);
            while (1);
        }
        app_res = app_data_run_responder(&app_ch, tx_responder, rx_responder, NULL);
        if (app_res != ok)
            kprintf("APP DATA FAIL: %d\r\n", app_res);
    }

    transport_idle();
}
