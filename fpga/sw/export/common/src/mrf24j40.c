/*
 * mrf24j40 - see include/mrf24j40.h.
 */
#include "mrf24j40.h"

/* SiFive TLSPI */
#define SPI(o)      (*(volatile uint32_t *)(uintptr_t)(MRF_SPI_BASE + (o)))
#define SPI_SCKDIV  0x00
#define SPI_SCKMODE 0x04
#define SPI_CSID    0x10
#define SPI_CSDEF   0x14
#define SPI_CSMODE  0x18
#define SPI_FMT     0x40
#define SPI_TXDATA  0x48
#define SPI_RXDATA  0x4c
#define CSMODE_AUTO 0u
#define CSMODE_HOLD 2u

/* registers used only here */
#define R_RXFLUSH 0x0d
#define R_TXMCR   0x11
#define R_PACON2  0x18
#define R_SOFTRST 0x2a
#define R_TXSTBL  0x2e
#define R_INTCON  0x32
#define R_RFCTL   0x36
#define R_BBREG0  0x38
#define R_BBREG1  0x39
#define R_BBREG2  0x3a
#define R_BBREG3  0x3b
#define R_BBREG4  0x3c
#define R_BBREG6  0x3e
#define R_CCAEDTH 0x3f
#define L_TXNFIFO 0x000
#define L_RXFIFO  0x300
#define L_RFCON1  0x201
#define L_RFCON2  0x202
#define L_RFCON6  0x206
#define L_RFCON7  0x207
#define L_RFCON8  0x208
#define L_SLPCON1 0x220

#ifndef MRF_TURBO
#define MRF_TURBO 0                /* 1: 625 kbit/s proprietary mode, both ends;
                                    * ~2/3 of frames went unacknowledged with
                                    * it on these modules, so off */
#endif
#define SPI_FIFO  8                /* SiFive TLSPI TX/RX FIFO depth */

#define INT_TXN   0x01
#define INT_RX    0x08
#define HDR_LEN   9
#ifndef TX_TIMEOUT_US
#define TX_TIMEOUT_US 50000u
#endif

static uint16_t my_pan, my_addr;
static uint8_t  tx_seq;
static uint8_t  pending;           /* INTSTAT clears on read; keep the flags */

uint64_t mrf_cycles(void)
{
#if __riscv_xlen == 64
    uint64_t c;
    __asm__ volatile("rdcycle %0" : "=r"(c));
    return c;
#else
    uint32_t hi, lo, hi2;
    do {
        __asm__ volatile("rdcycleh %0" : "=r"(hi));
        __asm__ volatile("rdcycle %0" : "=r"(lo));
        __asm__ volatile("rdcycleh %0" : "=r"(hi2));
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
#endif
}

void mrf_delay_us(uint32_t us)
{
    uint64_t end = mrf_cycles() + (uint64_t)us * (F_CPU / 1000000u);
    while (mrf_cycles() < end) {
    }
}

static uint8_t spi_xfer(uint8_t b)
{
    int32_t rx;
    while ((int32_t)SPI(SPI_TXDATA) < 0) {
    }
    SPI(SPI_TXDATA) = b;
    do {
        rx = (int32_t)SPI(SPI_RXDATA);
    } while (rx < 0);
    return (uint8_t)rx;
}

/* CS stays low from the first byte until CSMODE leaves HOLD (SPIFIFO.sv). */
static void cs_begin(void) { SPI(SPI_CSMODE) = CSMODE_HOLD; }
static void cs_end(void)   { SPI(SPI_CSMODE) = CSMODE_AUTO; }

/* Moves n bytes through the SPI with up to SPI_FIFO in flight instead of one
 * round trip per byte. out == 0 clocks zeros; in == 0 discards. */
static void spi_stream(const uint8_t *out, uint8_t *in, uint32_t n)
{
    uint32_t sent = 0, got = 0;
    int32_t rx;

    while (got < n) {
        if (sent < n && sent - got < SPI_FIFO) {
            SPI(SPI_TXDATA) = out ? out[sent] : 0;
            sent++;
            continue;
        }
        if ((rx = (int32_t)SPI(SPI_RXDATA)) >= 0) {
            if (in)
                in[got] = (uint8_t)rx;
            got++;
        }
    }
}

/* Long-address burst: the MRF24J40 increments the address while CS stays
 * low, so a FIFO moves as one command instead of one per byte. */
static void long_burst(uint16_t a, int write, const uint8_t *out, uint8_t *in,
                       uint32_t n)
{
    cs_begin();
    spi_xfer((uint8_t)(0x80 | (a >> 3)));
    spi_xfer((uint8_t)((a << 5) | (write ? 0x10 : 0)));
    spi_stream(out, in, n);
    cs_end();
}

#define GPIO(b, o)  (*(volatile uint32_t *)((b) + (o)))
#define GPIO_OUT_EN 0x08
#define GPIO_OUT    0x0c

void mrf_hw_reset(uintptr_t gpio_base, uint32_t pin_mask)
{
    GPIO(gpio_base, GPIO_OUT) |= pin_mask;
    GPIO(gpio_base, GPIO_OUT_EN) |= pin_mask;
    GPIO(gpio_base, GPIO_OUT) &= ~pin_mask;
    mrf_delay_us(1000);
    GPIO(gpio_base, GPIO_OUT) |= pin_mask;
    mrf_delay_us(2000);
}

void mrf_spi_init(uint32_t sck_div)
{
    SPI(SPI_SCKDIV) = sck_div;         /* f_sck = F_CPU / (2 * (div + 1)) */
    SPI(SPI_SCKMODE) = 0;              /* mode 0 */
    SPI(SPI_CSID) = 0;
    SPI(SPI_CSDEF) = 1;                /* CS idles high */
    SPI(SPI_CSMODE) = CSMODE_AUTO;
    SPI(SPI_FMT) = 8u << 16;           /* 8-bit, single, MSB first, full duplex */
    while ((int32_t)SPI(SPI_RXDATA) >= 0) {
    }                                  /* drain stale RX */
}

uint8_t mrf_rd_short(uint8_t a)
{
    uint8_t v;
    cs_begin();
    spi_xfer((uint8_t)((a << 1) & 0x7e));
    v = spi_xfer(0);
    cs_end();
    return v;
}

void mrf_wr_short(uint8_t a, uint8_t v)
{
    cs_begin();
    spi_xfer((uint8_t)(((a << 1) & 0x7e) | 1));
    spi_xfer(v);
    cs_end();
}

uint8_t mrf_rd_long(uint16_t a)
{
    uint8_t v;
    cs_begin();
    spi_xfer((uint8_t)(0x80 | (a >> 3)));
    spi_xfer((uint8_t)(a << 5));
    v = spi_xfer(0);
    cs_end();
    return v;
}

void mrf_wr_long(uint16_t a, uint8_t v)
{
    cs_begin();
    spi_xfer((uint8_t)(0x80 | (a >> 3)));
    spi_xfer((uint8_t)((a << 5) | 0x10));
    spi_xfer(v);
    cs_end();
}

void mrf_init(uint8_t channel, uint16_t pan, uint16_t addr)
{
    mrf_wr_short(R_SOFTRST, 0x07);
    mrf_delay_us(2000);                /* datasheet: 2 ms before access */
    mrf_wr_short(R_PACON2, 0x98);
    mrf_wr_short(R_TXSTBL, 0x95);
    mrf_wr_long(MRF_RFCON0, 0x03);
    mrf_wr_long(L_RFCON1, 0x02);
    mrf_wr_long(L_RFCON2, 0x80);
    mrf_wr_long(L_RFCON6, 0x90);
    mrf_wr_long(L_RFCON7, 0x80);
    mrf_wr_long(L_RFCON8, 0x10);
    mrf_wr_long(L_SLPCON1, 0x21);
    mrf_wr_short(R_BBREG2, 0x80);      /* CCA mode: energy detect */
    mrf_wr_short(R_CCAEDTH, 0x60);
    mrf_wr_short(R_BBREG6, 0x40);      /* append RSSI to RX FIFO */
    mrf_wr_short(R_INTCON, 0xf6);      /* RX and TX-normal interrupts */
    mrf_wr_short(R_TXMCR, 0x9c);       /* NOCSMA: two nodes taking turns, so
                                        * skip the ~1 ms random backoff */
#if MRF_TURBO
    mrf_wr_short(R_BBREG0, 0x01);      /* turbo mode, datasheet 3.3 */
    mrf_wr_short(R_BBREG3, 0x38);
    mrf_wr_short(R_BBREG4, 0x5c);
#endif
    mrf_wr_long(MRF_RFCON0, (uint8_t)(((channel - 11) << 4) | 0x03));
    mrf_wr_short(MRF_PANIDL, (uint8_t)pan);
    mrf_wr_short(MRF_PANIDL + 1, (uint8_t)(pan >> 8));
    mrf_wr_short(MRF_SADRL, (uint8_t)addr);
    mrf_wr_short(MRF_SADRL + 1, (uint8_t)(addr >> 8));
    mrf_wr_short(R_RFCTL, 0x04);       /* RF state machine reset */
    mrf_wr_short(R_RFCTL, 0x00);
    mrf_delay_us(200);
    mrf_wr_short(R_RXFLUSH, 0x01);
    my_pan = pan;
    my_addr = addr;
    pending = 0;
    (void)mrf_rd_short(MRF_INTSTAT);
}

int mrf_send(uint16_t dst, const uint8_t *payload, uint8_t len, int ack)
{
    uint8_t hdr[HDR_LEN] = {
        (uint8_t)(ack ? 0x61 : 0x41),  /* data frame, PAN ID compression, AR */
        0x88,                          /* short destination and source */
        ++tx_seq,
        (uint8_t)my_pan, (uint8_t)(my_pan >> 8),
        (uint8_t)dst, (uint8_t)(dst >> 8),
        (uint8_t)my_addr, (uint8_t)(my_addr >> 8)};
    uint64_t end;
    unsigned i;

    if (len > MRF_MAX_PAYLOAD)
        return -1;
    {
        uint8_t fifo[2 + HDR_LEN + MRF_MAX_PAYLOAD];

        fifo[0] = HDR_LEN;
        fifo[1] = (uint8_t)(HDR_LEN + len);
        for (i = 0; i < HDR_LEN; i++)
            fifo[2 + i] = hdr[i];
        for (i = 0; i < len; i++)
            fifo[2 + HDR_LEN + i] = payload[i];
        long_burst(L_TXNFIFO, 1, fifo, 0, 2u + HDR_LEN + len);
    }

#ifdef MRF_VERIFY_TX
    /* Read the FIFO back before triggering: a corrupted SPI write must not
     * start a transmission (or reach another register, e.g. TESTMODE). */
    if (mrf_rd_long(L_TXNFIFO) != HDR_LEN ||
        mrf_rd_long(L_TXNFIFO + 1) != (uint8_t)(HDR_LEN + len))
        return -2;
    for (i = 0; i < HDR_LEN; i++)
        if (mrf_rd_long((uint16_t)(L_TXNFIFO + 2 + i)) != hdr[i])
            return -2;
    for (i = 0; i < len; i++)
        if (mrf_rd_long((uint16_t)(L_TXNFIFO + 2 + HDR_LEN + i)) != payload[i])
            return -2;
#endif
    pending &= (uint8_t)~INT_TXN;
    mrf_wr_short(MRF_TXNCON, (uint8_t)(ack ? 0x05 : 0x01));
    end = mrf_cycles() + (uint64_t)TX_TIMEOUT_US * (F_CPU / 1000000u);
    while (!(pending & INT_TXN)) {
        if (mrf_cycles() > end)
            return -1;
        pending |= mrf_rd_short(MRF_INTSTAT);
    }
    pending &= (uint8_t)~INT_TXN;
    return mrf_rd_short(MRF_TXSTAT);
}

/* Datasheet Example 3-2: frame length at 0x300, then header, payload, FCS,
 * LQI and RSSI. RXDECINV (BBREG1) blocks reception while the FIFO is read. */
int mrf_recv(uint8_t *buf, uint8_t max, uint16_t *src, uint8_t *lqi, uint8_t *rssi)
{
    uint8_t flen, f[127 + 2];          /* frame, then LQI and RSSI */
    int n;
    unsigned i;

    if (!(pending & INT_RX))
        pending |= mrf_rd_short(MRF_INTSTAT);
    if (!(pending & INT_RX))
        return -1;
    pending &= (uint8_t)~INT_RX;

    mrf_wr_short(R_BBREG1, 0x04);
    flen = mrf_rd_long(L_RXFIFO);      /* header + payload + 2 FCS */
    n = (flen > 127) ? -1 : (int)flen - HDR_LEN - 2;
    if (n >= 0) {
        long_burst(L_RXFIFO + 1, 0, 0, f, flen + 2u);
        if (n > max)
            n = max;
        for (i = 0; i < (unsigned)n; i++)
            buf[i] = f[HDR_LEN + i];
        if (src)
            *src = (uint16_t)(f[7] | (f[8] << 8));
        if (lqi)
            *lqi = f[flen];
        if (rssi)
            *rssi = f[flen + 1];
    }
    mrf_wr_short(R_BBREG1, 0x00);
    return n;
}
