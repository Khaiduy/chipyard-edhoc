/*
 * mrf24j40 - minimal MRF24J40 (IEEE 802.15.4) driver over the SiFive SPI.
 *
 * Datasheet DS30009776E; frame and RX FIFO
 * handling follow github.com/karlp/Mrf24j40-arduino-library. Frames use
 * short addresses and PAN ID compression: 9-byte MAC header, then payload.
 * Completion and reception are polled in INTSTAT, so ~RST and INT may float.
 */
#ifndef MRF24J40_H
#define MRF24J40_H

#include <stdint.h>

#ifndef MRF_SPI_BASE
#define MRF_SPI_BASE 0x64006000u   /* SPI1, PMOD JC with WithArtyJCRadio */
#endif
#ifndef F_CPU
#define F_CPU 75000000u            /* EdhocRocket6475MHzArty100TConfig */
#endif

#define MRF_MAX_PAYLOAD 116         /* 127 - 9 header - 2 FCS */

/* short registers */
#define MRF_PANIDL  0x01
#define MRF_SADRL   0x03
#define MRF_TXNCON  0x1b
#define MRF_TXSTAT  0x24
#define MRF_INTSTAT 0x31
/* long registers */
#define MRF_RFCON0  0x200
#define MRF_RFSTATE 0x20f

void     mrf_delay_us(uint32_t us);
uint64_t mrf_cycles(void);

/* Pulse ~RST low through a SiFive GPIO output pin (FPGA: GPIO 5 on JC8), then
 * wait the 2 ms the datasheet asks for. A soft reset alone does not recover a
 * module left stuck by an earlier run. */
void    mrf_hw_reset(uintptr_t gpio_base, uint32_t pin_mask);
void    mrf_spi_init(uint32_t sck_div);
uint8_t mrf_rd_short(uint8_t a);
void    mrf_wr_short(uint8_t a, uint8_t v);
uint8_t mrf_rd_long(uint16_t a);
void    mrf_wr_long(uint16_t a, uint8_t v);

/* Datasheet Example 3-1 initialization, then channel (11..26), PAN and
 * short address. Leaves the radio receiving. */
void mrf_init(uint8_t channel, uint16_t pan, uint16_t addr);

/* Send a data frame to dst. Returns TXSTAT (bit 0 set = no ACK after the
 * hardware retries, bit 5 = CCA failure), -1 if TX never completed, or -2
 * (MRF_VERIFY_TX builds) if the FIFO read-back differed and nothing was sent. */
int mrf_send(uint16_t dst, const uint8_t *payload, uint8_t len, int ack);

/* Return the payload length of a received frame (copied into buf, at most
 * max bytes), or -1 if none is pending. src, lqi and rssi may be NULL. */
int mrf_recv(uint8_t *buf, uint8_t max, uint16_t *src, uint8_t *lqi, uint8_t *rssi);

#endif /* MRF24J40_H */
