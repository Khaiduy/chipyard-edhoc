/* EDHOC Initiator - Board A - Method 5 AUTHKEM (ML-KEM-512, no signatures)
 *
 * draft-ietf-lake-authkem-edhoc-01 (the WG document), NOT the 3-message IKR
 * variant (removed from this export in 2026-10). The two are not configurations of one
 * state machine: transcript hashes, KDF label space and PRK chain differ.
 *
 *   Both parties authenticate with static ML-KEM-512 key pairs.
 *   Credentials are CCS by kid, so no X.509 and therefore no ML-DSA.
 *   Cipher suite draft-ietf-lake-pqsuites-01 TBD2 (private-use label -24
 *   until assigned): A256GCM, SHAKE256, MAC 16, ML-KEM-512, ML-DSA-44,
 *   A256GCM, SHA-256.
 *
 * Message flow (5 messages):
 *   tx(msg1) -> rx(msg2) -> tx(msg3) -> rx(msg4_KEM) -> tx(msg5_KEM)
 *
 * Unlike IKR, the initiator does NOT need the responder's static KEM public
 * key up front: authkem-01 carries it via ID_CRED_R in message_2.
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

extern void csprng_add_entropy(const uint8_t *data, uint32_t len);

/* KEM_SK_SIZE / KEM_PK_SIZE / PRK_SIZE come from edhoc/buffer_sizes.h */

/* Ephemeral key buffer (generated fresh per session via CSPRNG) */
/* The ephemeral ML-KEM decapsulation key lives in main()'s frame, not .bss.
 * There is no separate public-key buffer: an ML-KEM decapsulation key
 * contains the encapsulation key (FIPS 203: dk = dk_PKE || ek || H(ek) || z),
 * and the library points ctx.g_x into x_eph when it generates the pair.
 *
 * Lifetime: authkem_gen_eph_keypair() writes x_eph before message_1; it is
 * read for message_1 and once more to decapsulate ct_eph in message_2, and
 * main() never returns, so the frame outlives every use.
 *
 * Why the frame rather than .bss, on a target this tight: .bss is subtracted
 * from the RAM available for the stack, so 2,432 B of .bss costs 2,432 B of
 * reservation. On the stack it cost only 1,712 B of measured peak -- GCC
 * reuses frame slots -- and the reservation scales at 1.25x the peak, so the
 * net is +264 B of slack against the linker ASSERT. Measured on hardware,
 * both ways; the arithmetic alone predicts the opposite answer. */

/* Initiator static KEM key pair (demo keys from authkem_test_keys.h) */
/* Static authentication material. All of it is constant, so all of it lives
 * in .rodata: the copies these used to keep in .bss cost 3,232 B for the keys
 * plus 1,628 B for the two credentials, on a 64 kB scratchpad whose measured
 * stack peak leaves little to spare.
 *
 * The credentials are generated at build time (tools/gen_ccs.c) and the raw
 * public keys are read from inside them -- a CCS is a 14-byte CBOR prefix
 * followed by the key -- so neither key is stored twice.
 *
 * The casts drop const only to satisfy struct byte_array's non-const ptr; the
 * EDHOC library only reads these. */
#ifdef EDHOC_PROFILE_PRODUCTION
/* Supplied by PROVISION_SRC; no default exists, so a missing implementation
 * is a link error. Ideally this never returns a readable key at all -- see
 * include/authkem_provision.h. */
#define AUTHKEM_OWN_STATIC_SK() authkem_device_static_sk()
#else
#define AUTHKEM_OWN_STATIC_SK() INIT_SK
#endif
static uint8_t *i_sk;
static uint8_t *const g_r_resp = (uint8_t *)CRED_R_PK;
static uint8_t *const cred_i_buf = (uint8_t *)CRED_I_CCS;
static uint8_t *const cred_r_buf = (uint8_t *)CRED_R_CCS;
static const uint32_t cred_i_len = CRED_I_CCS_LEN;
static const uint32_t cred_r_len = CRED_R_CCS_LEN;

static const uint8_t c_i_val[]  = {0x2d};
static const uint8_t suites_i[] = { AUTHKEM_SUITE_BYTE };   /* pqsuites TBD2 or TBD3 */

static uint8_t id_cred_i_buf[] = {0xa1, 0x04, 0x41, 0x01};
static uint8_t id_cred_r_buf[] = {0xa1, 0x04, 0x41, 0x02};

static uint8_t prk_out_buf[PRK_SIZE];
static uint8_t c_r_buf[4];
static uint8_t err_msg_buf[64];

static enum err ead_noop(void *p, struct byte_array *ead)
{
    (void)p; (void)ead; return ok;
}

/* Diagnostic trap handler: print mcause/mepc then halt (no mret loop). */
__attribute__((aligned(4))) void m5_trap(void)
{
    uint32_t mcause, mepc, mtval;
    __asm__ volatile("csrr %0, mcause" : "=r"(mcause));
    __asm__ volatile("csrr %0, mepc"   : "=r"(mepc));
    __asm__ volatile("csrr %0, mtval"  : "=r"(mtval));
    kprintf("\r\n!!! TRAP mcause=0x%lx mepc=0x%lx mtval=0x%lx !!!\r\n",
            (unsigned long)mcause, (unsigned long)mepc, (unsigned long)mtval);
    while (1);
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
    for (volatile uint32_t _s = 0; _s < 90000000; _s++) { (void)_s; }

    /* Install diagnostic trap handler (overrides openocd's mtvec). */
    __asm__ volatile("csrw mtvec, %0" :: "r"((uint32_t)(uintptr_t)m5_trap));

    kprintf("=== EDHOC Method 5 AUTHKEM (draft-ietf-lake-authkem-edhoc-01, pqsuites TBD%d) Initiator (ML-KEM-%d) ===\r\n",
            AUTHKEM_PQ_SUITE, MLK_CONFIG_PARAMETER_SET);

    volatile uint64_t t_start = read_cycles();

    /* Seed CSPRNG from cycle counter */
    volatile uint32_t seed = (uint32_t)(t_start & 0xFFFFFFFF);
    csprng_add_entropy((const uint8_t *)&seed, sizeof(seed));


    uint8_t x_eph[KEM_SK_SIZE];

    /* authkem_gen_eph_keypair() copies c->x in as seed material before
     * overwriting it. The current ML-KEM backend ignores that input and draws
     * its own coins from the CSPRNG, but in .bss this was zero-initialised
     * and on the stack it would be whatever the frame held -- so zero it
     * rather than rely on the backend continuing to ignore it. */
    memset(x_eph, 0, sizeof(x_eph));

    i_sk = (uint8_t *)AUTHKEM_OWN_STATIC_SK();

    struct edhoc_initiator_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.method    = INITIATOR_KEM_RESPONDER_KEM;
    ctx.suites_i  = (struct byte_array){ .ptr = (uint8_t *)suites_i, .len = sizeof(suites_i) };
    ctx.c_i       = (struct byte_array){ .ptr = (uint8_t *)c_i_val,  .len = sizeof(c_i_val) };
    ctx.id_cred_i = (struct byte_array){ .ptr = id_cred_i_buf,        .len = sizeof(id_cred_i_buf) };
    ctx.cred_i    = (struct byte_array){ .ptr = cred_i_buf,           .len = cred_i_len };
    /* ctx.g_x is set by the library to point into x_eph (see above). */
    ctx.x         = (struct byte_array){ .ptr = x_eph,                .len = KEM_SK_SIZE };
    ctx.i         = (struct byte_array){ .ptr = i_sk,                 .len = KEM_SK_SIZE };
    /* Left empty on purpose: authkem-01 learns the responder's static KEM
     * key from ID_CRED_R in message_2 (see draft section 4.2.3). */
    ctx.sock      = NULL;
    ctx.params_ead_process = NULL;

    static struct other_party_cred cred_r_entry;
    cred_r_entry.cred.ptr    = cred_r_buf;
    cred_r_entry.cred.len    = cred_r_len;
    cred_r_entry.id_cred.ptr = id_cred_r_buf;
    cred_r_entry.id_cred.len = sizeof(id_cred_r_buf);
    cred_r_entry.g.ptr       = g_r_resp;
    cred_r_entry.g.len       = KEM_PK_SIZE;
    struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r_entry };

    struct byte_array prk_out = { .ptr = prk_out_buf, .len = sizeof(prk_out_buf) };
    struct byte_array c_r     = { .ptr = c_r_buf,     .len = sizeof(c_r_buf) };
    struct byte_array err_msg = { .ptr = err_msg_buf, .len = sizeof(err_msg_buf) };
    kprintf("init: keys loaded, starting handshake...\r\n");

    /* Link accounting starts at zero for the measured region. */

    g_uart_cycles = 0;

    volatile uint64_t t0 = read_cycles();
    enum err result = edhoc_initiator_run_authkem(
        &ctx, &cred_r_array, &err_msg, &c_r, &prk_out,
        tx_initiator, rx_initiator, ead_noop);
    volatile uint64_t t1 = read_cycles();
    kprintf("init: handshake returned %d\r\n", result);

    if (result != ok) {        kprintf("EDHOC FAIL: %d\r\n", result);
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

    /* "EDHOC OK" is the loader's completion marker — print it LAST so the
     * full timing + PRK_out output is captured before the loader stops. */
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
        enum err app_res = app_data_init(&app_ch, (enum suite_label)(int8_t)suites_i[0],
                                         &prk_out, 1);

        if (app_res != ok) {
            kprintf("APP init FAIL: %d\r\n", app_res);
            while (1);
        }
        app_res = app_data_run_initiator(&app_ch, tx_initiator, rx_initiator, NULL);
        if (app_res != ok)
            kprintf("APP DATA FAIL: %d\r\n", app_res);
    }

    transport_idle();
}
