/*
 * edhoc_rf_link - see include/edhoc_rf_link.h.
 */
#include "edhoc_rf_link.h"
#include "mrf24j40.h"

#ifndef RF_CHANNEL
#define RF_CHANNEL 11
#endif
#define RF_PAN       0xabcd
#ifndef RF_SCK_DIV
#define RF_SCK_DIV   7u           /* f_sck = F_CPU / (2 (div + 1)) = 4.7 MHz at 75 MHz */
#endif
#ifndef RF_ACK_MS
#define RF_ACK_MS    30u          /* wait for 'A' before sending a fragment again */
#endif
#ifndef RF_SEND_TIMEOUT_MS
#define RF_SEND_TIMEOUT_MS 300000u
#endif
#ifndef RF_RECV_TIMEOUT_MS
#define RF_RECV_TIMEOUT_MS 300000u
#endif
#ifndef RF_HEAL_MS
#define RF_HEAL_MS   2000u        /* no link progress this long: re-init the radio */
#endif
#define GPIO_BASE    0x64002000u
#define GPIO_RST     (1u << 5)    /* JC8 ~RST */
#define HDR          3            /* [type][seq][flags] */
#define CRC          2            /* CRC-16 trailer, see seal() */
#define FRAG_DATA    (MRF_MAX_PAYLOAD - HDR - CRC)
#define F_FIRST      0x01
#define F_LAST       0x02

struct rf_stats rf_stats;

static uint16_t peer, self;
static uint8_t  tx_seq, rx_seq;   /* next fragment to send / to accept */
static int      rx_any;           /* a fragment has been accepted */
static uint8_t  stash[MRF_MAX_PAYLOAD];
static int      stash_len;        /* peer fragment taken as an implicit ack */
static uint8_t  pend[MRF_MAX_PAYLOAD];
static int      pend_len;         /* sent fragment still awaiting its 'A' */
static uint8_t  last_lqi, last_rssi;

static uint64_t ms_to_cycles(uint32_t ms)
{
    return (uint64_t)ms * (F_CPU / 1000u);
}

/* Reset and reprogram the radio. Also the self-heal: on the PMOD wiring a
 * corrupted SPI write can leave a radio register wrong (seen as one side
 * going deaf for good in long transfers), so a link that makes no progress
 * for RF_HEAL_MS re-inits its radio; sequence numbers are kept and the
 * normal repeats carry on. */
static void radio_up(void)
{
    mrf_hw_reset(GPIO_BASE, GPIO_RST);
    mrf_spi_init(RF_SCK_DIV);
    mrf_init(RF_CHANNEL, RF_PAN, self);
}

static void heal_if_stuck(uint64_t *heal)
{
    if (mrf_cycles() < *heal)
        return;
    rf_stats.reinits++;
    radio_up();
    *heal = mrf_cycles() + ms_to_cycles(RF_HEAL_MS);
}

static void copy(uint8_t *d, const uint8_t *s, uint32_t n)
{
    while (n--)
        *d++ = *s++;
}

/* CRC-16/CCITT over the frame, appended before it goes over SPI to the
 * radio and checked after it comes back over SPI from the radio. The radio's
 * own FCS covers only the air: a bit flipped on either SPI link would
 * otherwise be acknowledged and surface later as an AEAD failure the session
 * cannot recover from. A frame failing this check is dropped unacknowledged,
 * so the sender's repeat timer sends it again. */
static uint16_t crc16(const uint8_t *p, int n)
{
    uint16_t c = 0xFFFF;

    while (n--) {
        c ^= (uint16_t)(*p++ << 8);
        for (int k = 0; k < 8; k++)
            c = (uint16_t)((c & 0x8000) ? (c << 1) ^ 0x1021 : c << 1);
    }
    return c;
}

static int seal(uint8_t *f, int len)
{
    uint16_t c = crc16(f, len);

    f[len] = (uint8_t)(c >> 8);
    f[len + 1] = (uint8_t)c;
    return len + CRC;
}

static void send_ack(uint8_t seq)
{
    uint8_t f[HDR + CRC] = {'A', seq, 0};
    (void)mrf_send(peer, f, (uint8_t)seal(f, HDR), 1);
}

/* Next frame from the radio, or -1. A repeat of the fragment last accepted
 * (its 'A' was lost) is acknowledged again and dropped here. */
static int poll_frame(uint8_t *f)
{
    int len = mrf_recv(f, MRF_MAX_PAYLOAD, 0, &last_lqi, &last_rssi);

    if (len < HDR + CRC)
        return -1;
    len -= CRC;
    if (crc16(f, len) != (uint16_t)(f[len] << 8 | f[len + 1])) {
        rf_stats.crc_errors++;
        return -1;
    }
    if (f[0] == 'D' && rx_any && f[1] == (uint8_t)(rx_seq - 1)) {
        send_ack(f[1]);
        return -1;
    }
    return len;
}

/* Read one incoming frame while the pending fragment is unconfirmed. It is
 * confirmed by its 'A', or by the first fragment of the peer's next message
 * (the peer only starts one once it holds all of ours), which is kept. */
static void take_reply(void)
{
    uint8_t r[MRF_MAX_PAYLOAD];
    int len = poll_frame(r);

    if (len < 0)
        return;
    if (r[0] == 'A' && r[1] == pend[1]) {
        pend_len = 0;
    } else if (r[0] == 'D' && r[1] == rx_seq && (r[2] & F_FIRST) &&
               !stash_len) {
        copy(stash, r, (uint32_t)len);
        stash_len = len;
        pend_len = 0;
    }
}

/* Transmit the pending fragment until the radio reports the MAC
 * acknowledgement: the frame is then in the peer's receive FIFO, where only
 * our next frame could overwrite it. On these boards a radio with an unread
 * frame in its FIFO was seen to acknowledge nothing, so our FIFO is read
 * between attempts: with both ends in here at once (a peer slow to answer
 * lets our RF_ACK_MS repeat start just as it answers), neither would ever be
 * acknowledged, and a re-init does not help as the peer's next attempt
 * refills the FIFO. */
static int transmit(const uint8_t *f, int len, uint64_t end, int repeat)
{
    uint64_t heal = mrf_cycles() + ms_to_cycles(RF_HEAL_MS);
    int st;

    while (mrf_cycles() < end) {
        heal_if_stuck(&heal);
        rf_stats.tx_frames++;
        if (repeat++)
            rf_stats.tx_repeats++;
        st = mrf_send(peer, f, (uint8_t)len, 1);
        if (st >= 0 && !(st & 1))
            return 0;
        take_reply();
        if (!pend_len)
            return 0;
        mrf_delay_us(2000);
    }
    return -1;
}

/* Wait until the peer has read the pending fragment: its 'A', or the first
 * fragment of the peer's next message (the peer only starts one once it holds
 * all of ours). The fragment is sent again every RF_ACK_MS meanwhile. */
static int confirm_pending(void)
{
    uint64_t end = mrf_cycles() + ms_to_cycles(RF_SEND_TIMEOUT_MS);
    uint64_t again = mrf_cycles() + ms_to_cycles(RF_ACK_MS);
    uint64_t heal = mrf_cycles() + ms_to_cycles(RF_HEAL_MS);

    while (pend_len) {
        if (mrf_cycles() >= end)
            return -1;
        heal_if_stuck(&heal);
        if (mrf_cycles() >= again) {
            if (transmit(pend, pend_len, end, 1))
                return -1;
            again = mrf_cycles() + ms_to_cycles(RF_ACK_MS);
            continue;
        }
        take_reply();
    }
    return 0;
}

/* A fragment is complete once the radio acknowledged it; the peer's 'A' is
 * awaited only before the next fragment goes out, so the last message of a
 * session does not wait for an 'A' that a finished peer never repeats. */
static int send_frag(uint8_t flags, const uint8_t *data, uint32_t n)
{
    if (confirm_pending())
        return -1;
    pend[0] = 'D';
    pend[1] = tx_seq;
    pend[2] = flags;
    copy(pend + HDR, data, n);
    pend_len = seal(pend, (int)(HDR + n));
    if (transmit(pend, pend_len,
                 mrf_cycles() + ms_to_cycles(RF_SEND_TIMEOUT_MS), 0)) {
        pend_len = 0;
        return -1;
    }
    tx_seq++;
    return 0;
}

/* Next in-order data fragment (acknowledged), or -1 on timeout. An 'A' we
 * send can overwrite our own unread fragment in the peer's FIFO, so a
 * fragment not yet confirmed is sent again every RF_ACK_MS while we wait. */
static int recv_frag(uint8_t *f)
{
    uint64_t end = mrf_cycles() + ms_to_cycles(RF_RECV_TIMEOUT_MS);
    uint64_t again = mrf_cycles() + ms_to_cycles(RF_ACK_MS);
    uint64_t heal = mrf_cycles() + ms_to_cycles(RF_HEAL_MS);
    int len;

    for (;;) {
        if (stash_len) {                /* kept by take_reply() */
            len = stash_len;
            copy(f, stash, (uint32_t)len);
            stash_len = 0;
            break;
        }
        if (mrf_cycles() >= end)
            return -1;
        heal_if_stuck(&heal);
        if (pend_len && mrf_cycles() >= again) {
            (void)transmit(pend, pend_len, end, 1);
            again = mrf_cycles() + ms_to_cycles(RF_ACK_MS);
            continue;
        }
        len = poll_frame(f);
        if (len < 0)
            continue;
        if (f[0] == 'A' && pend_len && f[1] == pend[1])
            pend_len = 0;
        if (f[0] == 'D' && f[1] == rx_seq)
            break;
    }
    pend_len = 0;                       /* the peer sends only after reading ours */
    send_ack(rx_seq);
    rx_seq++;
    rx_any = 1;
    rf_stats.lqi = last_lqi;
    rf_stats.rssi = last_rssi;
    return len;
}

int rf_link_init(int initiator)
{
    peer = initiator ? RF_ADDR_RESPONDER : RF_ADDR_INITIATOR;
    self = initiator ? RF_ADDR_INITIATOR : RF_ADDR_RESPONDER;
    tx_seq = rx_seq = 0;
    rx_any = 0;
    stash_len = 0;
    pend_len = 0;
    radio_up();
    /* receive state: RFSTATE[7:5] = 0b101 */
    return ((mrf_rd_long(MRF_RFSTATE) & 0xe0) == 0xa0) ? 0 : -1;
}

int rf_link_send(const uint8_t *data, uint32_t len)
{
    uint32_t off = 0, n;
    uint8_t flags;

    do {
        n = len - off;
        if (n > FRAG_DATA)
            n = FRAG_DATA;
        flags = (uint8_t)((off == 0 ? F_FIRST : 0) | (off + n == len ? F_LAST : 0));
        if (send_frag(flags, data + off, n))
            return -1;
        off += n;
    } while (off < len);
    return 0;
}

void rf_link_poll(void)
{
    uint8_t f[MRF_MAX_PAYLOAD];

    (void)poll_frame(f);
}

int32_t rf_link_recv(uint8_t *data, uint32_t cap)
{
    uint8_t f[MRF_MAX_PAYLOAD];
    uint32_t got = 0, n;
    int len;

    if ((len = recv_frag(f)) < 0)
        return -1;
    if (!(f[2] & F_FIRST))
        return -2;
    for (;;) {
        n = (uint32_t)(len - HDR);
        if (got + n > cap)
            return -2;
        copy(data + got, f + HDR, n);
        got += n;
        if (f[2] & F_LAST)
            return (int32_t)got;
        if ((len = recv_frag(f)) < 0)
            return -1;
        if (f[2] & F_FIRST)
            return -2;
    }
}
