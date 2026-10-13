#ifndef EDHOC_TRANSPORT_H
#define EDHOC_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include "uart.h"
#include "edhoc.h"
#include "perf.h"   /* read_cycles() */

#define UART1_BASE 0x64003000UL
/* TRANSPORT=uart link on PMOD JB. SiFive UART: baud = f_pbus / (div + 1).
 * Flow control in edhoc_transport.c makes the baud the only pace. */
#ifndef UART1_BAUD
#define UART1_BAUD 921600u
#endif
#define UART1_DIV (PERF_CPU_HZ / UART1_BAUD - 1)
#define REG32_UART1(i) (((volatile uint32_t *)UART1_BASE)[(i) >> 2])

static inline void uart1_putc(uint8_t c) {
    while ((int32_t)REG32_UART1(UART_REG_TXFIFO) < 0);
    REG32_UART1(UART_REG_TXFIFO) = c;
}

static inline int uart1_getc(void) {
    int32_t val = (int32_t)REG32_UART1(UART_REG_RXFIFO);
    return (val < 0) ? -1 : (val & 0xFF);
}

enum err ead_process(void *params, struct byte_array *ead);
enum err tx_initiator(void *sock, struct byte_array *data);
enum err rx_initiator(void *sock, struct byte_array *data);
enum err tx_responder(void *sock, struct byte_array *data);
enum err rx_responder(void *sock, struct byte_array *data);

/* End of the program: never returns; keeps answering the peer's repeats. */
void transport_idle(void) __attribute__((noreturn));

#endif /* EDHOC_TRANSPORT_H */
