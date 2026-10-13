#include "edhoc_transport.h"
#include "kprintf.h"
#include "stack_probe.h"

/* Accumulates cycles spent inside transport (UART or radio TX/RX, including waits and
 * inter-byte delays). Subtract from edhoc_*_run total to get COMPUTE-ONLY. */
volatile uint64_t g_uart_cycles = 0;

/* Cycle sampling for the transport accounting uses read_cycles() from
 * edhoc_transport.h. A local 32-bit rdcycle was used here previously; it
 * wraps every 2^32 cycles (57.3 s at 75 MHz), which a single long receive
 * wait can exceed, corrupting g_uart_cycles and hence
 * handshake_compute = handshake_total - handshake_link. */
#define _rdc() read_cycles()

enum err ead_process(void *params, struct byte_array *ead) {
    (void)params;
    (void)ead;
    return ok;
}

#ifdef EDHOC_TRANSPORT_RF
#include "edhoc_rf_link.h"

/* TRANSPORT=rf: messages go over the MRF24J40 radio on PMOD JC
 * (src/edhoc_rf_link.c) instead of the UART1 framing below. The radio is
 * brought up on the first call, in the role of the caller. */
static int rf_up(int initiator)
{
    static int state;               /* 0 not yet, 1 up, -1 not answering */

    if (state == 0) {
        state = rf_link_init(initiator) ? -1 : 1;
        if (state < 0)
            kprintf("[RF] MRF24J40 on PMOD JC not answering\r\n");
    }
    return state > 0;
}

static enum err frame_send(struct byte_array *data, int initiator)
{
    if (!rf_up(initiator) || rf_link_send(data->ptr, data->len))
        return transport_deinitialized;
    return ok;
}

static enum err frame_recv(struct byte_array *data, const char *tag, int initiator)
{
    int32_t n;

    (void)tag;
    if (!rf_up(initiator))
        return transport_deinitialized;
    n = rf_link_recv(data->ptr, data->len);
    if (n == -2)
        return buffer_to_small;
    if (n < 0)
        return transport_deinitialized;
    data->len = (uint32_t)n;
    return ok;
}

#else /* UART1 on PMOD JB */

/* Frame preamble. The RX side scans for it to align to a real frame start,
 * skipping stale bytes left in the FIFO by the loader's double-boot. */
#define FRAME_SYNC0 0xED
#define FRAME_SYNC1 0xC0

/* Frame: SYNC0 SYNC1 LEN_HI LEN_LO PAYLOAD[LEN] CKSUM
 *
 * The receiver sits in its sync scan for seconds before the peer board is
 * loaded, and halting/resuming that board over JTAG glitches bytes onto the
 * line. Without validation the scan latches onto that garbage, reads a bogus
 * length and swallows the real message as payload -- seen as intermittent
 * cbor_decode_message_1 failures (EXT_ERR 10) on ~half the runs of some suites.
 * A bad length or checksum makes the receiver drop what it has and resume
 * scanning, so a spurious frame costs nothing.
 */
static uint8_t frame_cksum(uint32_t len, const uint8_t *p)
{
    uint8_t c = (uint8_t)((len >> 8) & 0xFF);
    c = (uint8_t)(c + (uint8_t)(len & 0xFF));
    for (uint32_t i = 0; i < len; i++)
        c = (uint8_t)(c + p[i]);
    return c;
}

/* Flow control. The receiver polls UART1 and its RX FIFO holds only a few
 * bytes, but between frames it is busy (AEAD, SD writes), so a sender that
 * just transmits loses bytes. While a receiver waits for a frame it sends
 * FRAME_READY every READY_EVERY_CYC; the sender drops what is already
 * queued (stale READYs), waits for a fresh one, then sends the whole frame
 * at line rate. */
#define FRAME_READY     0xA5
#define READY_EVERY_CYC (PERF_CPU_HZ / 5000)        /* 0.2 ms */
#define READY_WAIT_CYC  (300ull * PERF_CPU_HZ)      /* 5 min, as the radio */

static enum err frame_send(struct byte_array *data, int initiator)
{
    uint64_t end = read_cycles() + READY_WAIT_CYC;

    (void)initiator;
    while (uart1_getc() >= 0)
        ;
    while (uart1_getc() != FRAME_READY)
        if (read_cycles() > end)
            return transport_deinitialized;
    uart1_putc(FRAME_SYNC0);
    uart1_putc(FRAME_SYNC1);
    uart1_putc((data->len >> 8) & 0xFF);
    uart1_putc(data->len & 0xFF);
    for (uint32_t i = 0; i < data->len; i++)
        uart1_putc(data->ptr[i]);
    uart1_putc(frame_cksum(data->len, data->ptr));
    return ok;
}

static enum err frame_recv(struct byte_array *data, const char *tag, int initiator)
{
    (void)initiator;
    uint32_t cap = data->len;
    int attempts = 8;               /* bounded resyncs, then give up */

    while (attempts-- > 0) {
        int c, got_s0 = 0, timeout;
        uint32_t len = 0, i;
        uint8_t want;

        uint64_t ready_at = 0;

        timeout = 1000000000;
        while (timeout-- > 0) {
            if (!got_s0 && read_cycles() >= ready_at) {
                uart1_putc(FRAME_READY);
                ready_at = read_cycles() + READY_EVERY_CYC;
            }
            if ((c = uart1_getc()) < 0) continue;
            if (got_s0 && c == FRAME_SYNC1) break;
            got_s0 = (c == FRAME_SYNC0);
        }
        if (timeout <= 0) { (void)tag; return transport_deinitialized; }

        timeout = 10000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) return transport_deinitialized;
        len = (uint32_t)c << 8;
        timeout = 10000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) return transport_deinitialized;
        len |= (uint32_t)c;

        if (len == 0 || len > cap) {
#ifdef DEBUG_PRINT
            kprintf("[%s] bad len %u cap %u, resync\r\n", tag, (unsigned)len, (unsigned)cap);
#endif
            continue;
        }

        for (i = 0; i < len; i++) {
            timeout = 10000000;
            while ((c = uart1_getc()) < 0 && timeout-- > 0);
            if (c < 0) return transport_deinitialized;
            data->ptr[i] = (uint8_t)c;
        }

        timeout = 10000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) return transport_deinitialized;

        want = frame_cksum(len, data->ptr);
        if ((uint8_t)c != want) {
#ifdef DEBUG_PRINT
            kprintf("[%s] cksum %x want %x, resync\r\n", tag, (unsigned)(c & 0xFF), (unsigned)want);
#endif
            continue;
        }

        data->len = len;
#ifdef DEBUG_PRINT
        kprintf("[%s] got %u bytes\r\n", tag, (unsigned)len);
#endif
        return ok;
    }
    return transport_deinitialized;
}

#endif /* EDHOC_TRANSPORT_RF */

/* The peer repeats its last frame until our radio acknowledges it. That can
 * fail although we already hold the frame, and a radio with an unread frame
 * in its FIFO was seen to acknowledge nothing, so a board that just stopped
 * would leave the peer repeating until RF_SEND_TIMEOUT_MS. Keep reading. */
void transport_idle(void)
{
    /* The STACK line after the handshake cannot see the application step
     * (file transfer, SD writes); this one covers the whole run. */
    kprintf("STACK whole run: peak %u B, reserve %u B%s\r\n",
            (unsigned)stack_highwater(), (unsigned)stack_reserve(),
            stack_overran_reserve() ? "  OVERRAN-RESERVE" : "");
#ifdef EDHOC_TRANSPORT_RF
    kprintf("RF: frames=%u repeats=%u crc_err=%u reinits=%u\r\n",
            (unsigned)rf_stats.tx_frames, (unsigned)rf_stats.tx_repeats,
            (unsigned)rf_stats.crc_errors, (unsigned)rf_stats.reinits);
#endif
    for (;;) {
#ifdef EDHOC_TRANSPORT_RF
        rf_link_poll();
#endif
    }
}

enum err tx_initiator(void *sock, struct byte_array *data) {
    (void)sock;
    uint64_t t0 = _rdc();
    enum err r = frame_send(data, 1);
    g_uart_cycles += _rdc() - t0;
#ifdef DEBUG_PRINT
    kprintf("[I-TX] sent %d bytes\r\n", data->len);
#endif
    return r;
}

enum err rx_initiator(void *sock, struct byte_array *data) {
    (void)sock;
    uint64_t t0 = _rdc();
    enum err r = frame_recv(data, "I-RX", 1);
    g_uart_cycles += _rdc() - t0;
    return r;
}

enum err tx_responder(void *sock, struct byte_array *data) {
    (void)sock;
    uint64_t t0 = _rdc();
    enum err r = frame_send(data, 0);
    g_uart_cycles += _rdc() - t0;
#ifdef DEBUG_PRINT
    kprintf("[R-TX] sent %d bytes\r\n", data->len);
#endif
    return r;
}

enum err rx_responder(void *sock, struct byte_array *data) {
    (void)sock;
    uint64_t t0 = _rdc();
    enum err r = frame_recv(data, "R-RX", 0);
    g_uart_cycles += _rdc() - t0;
    return r;
}
