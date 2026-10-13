/*
 * edhoc_rf_link - board-to-board message link over the MRF24J40 (IEEE
 * 802.15.4) module on PMOD JC. Used by edhoc_transport.c when built with
 * TRANSPORT=rf; carries the handshake messages and the AEAD records of the
 * application channel alike.
 *
 * An 802.15.4 frame holds 116 payload bytes, while EDHOC messages, ML-KEM
 * keys and file records are larger, so a message travels as a sequence of
 * fragments, each frame payload [type][seq][flags][data...][crc16]:
 *
 *   'D'  data fragment; flags bit 0 = first, bit 1 = last of the message
 *   'A'  acknowledgement of fragment seq (no flags, no data)
 *
 * The radio's receive FIFO holds a single frame, so the link is stop and
 * wait: the next fragment only goes out once the peer has acknowledged the
 * previous one with an 'A', which is sent again every RF_ACK_MS until then.
 * A fragment the peer's radio has acknowledged sits in its FIFO, where only
 * our next frame could overwrite it, so a message is complete as soon as its
 * last fragment is acknowledged by the radio; the 'A' for it is awaited at the
 * start of the next send. The last message of a session therefore does not
 * wait for an 'A' that a peer which has finished would never repeat.
 *
 * seq counts fragments per direction (mod 256). A receiver acknowledges a
 * repeat of the fragment it last accepted again and drops it. The first
 * fragment of the peer's next message also confirms our pending one (the peer
 * only starts it once it holds all of ours) and is kept for the next receive.
 *
 * crc16 (CCITT) covers the SPI hops to and from the radio, which the radio's
 * FCS does not: a frame that fails it is dropped unacknowledged and repeated.
 * A side that makes no progress for RF_HEAL_MS re-inits its radio, which
 * clears a register a corrupted SPI write may have changed. Both were needed
 * for long transfers on the PMOD wiring (1 MiB: AEAD failures and stalls
 * without them).
 */
#ifndef EDHOC_RF_LINK_H
#define EDHOC_RF_LINK_H

#include <stdint.h>

#define RF_ADDR_INITIATOR 0x0001
#define RF_ADDR_RESPONDER 0x0002

struct rf_stats {
    uint32_t tx_frames;   /* data fragments sent, including repeats */
    uint32_t tx_repeats;  /* data fragments sent again */
    uint32_t crc_errors;  /* frames dropped: link CRC mismatch (SPI corruption) */
    uint32_t reinits;     /* radio re-inits after RF_HEAL_MS without progress */
    uint8_t  lqi, rssi;   /* last accepted fragment */
};
extern struct rf_stats rf_stats;

/* Pulse ~RST, configure the SPI and the radio for this role. Returns 0 if the
 * radio answers (receive state readable), -1 otherwise. */
int rf_link_init(int initiator);

/* Send one message. Returns 0 once the peer's radio holds all of it, -1 if a
 * fragment stays unacknowledged for RF_SEND_TIMEOUT_MS. */
int rf_link_send(const uint8_t *data, uint32_t len);

/* Receive one message into data (cap bytes). Returns its length, -1 on
 * timeout (RF_RECV_TIMEOUT_MS per fragment), or -2 if it exceeds cap or does
 * not start with a first fragment. */
int32_t rf_link_recv(uint8_t *data, uint32_t cap);

/* Read one incoming frame, if any, answering a repeat of the last fragment
 * received with its 'A' again. Call it in a loop once the session is over. */
void rf_link_poll(void);

#endif /* EDHOC_RF_LINK_H */
