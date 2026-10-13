/*
 * test_init.h — console bring-up shared by every test binary.
 *
 * These images are loaded straight into the scratchpad over JTAG, so nothing
 * has configured the UARTs for us. Every test calls test_console_init() first,
 * mirroring what the EDHOC applications do at the top of main().
 *
 * The divisor is derived from TEST_CPU_HZ so it cannot go stale when the SoC
 * clock changes: the SiFive UART gives baud = f_pbus / (div + 1). Override
 * with -DTEST_CPU_HZ=... or -DTEST_BAUD=... for a different bitstream.
 */
#ifndef TEST_INIT_H
#define TEST_INIT_H

#include <stdint.h>
#include "platform.h"
#include "uart.h"

#define UART1_BASE_ADDR   0x64003000UL

/* Must match the bitstream: EdhocRocket6475MHzArty100TConfig runs at 75 MHz. */
#ifndef TEST_CPU_HZ
#define TEST_CPU_HZ       75000000u
#endif
#ifndef TEST_BAUD
#define TEST_BAUD         57600u
#endif
#define UART_DIV_57600    (TEST_CPU_HZ / TEST_BAUD)

#define TREG_U0(i) (((volatile uint32_t *)UART_CTRL_ADDR)[(i) >> 2])
#define TREG_U1(i) (((volatile uint32_t *)UART1_BASE_ADDR)[(i) >> 2])

static inline void test_console_init(void)
{
	TREG_U0(UART_REG_DIV)    = UART_DIV_57600;
	TREG_U0(UART_REG_TXCTRL) = UART_TXEN;
	TREG_U0(UART_REG_RXCTRL) = UART_RXEN;

	TREG_U1(UART_REG_DIV)    = UART_DIV_57600;
	TREG_U1(UART_REG_TXCTRL) = UART_TXEN;
	TREG_U1(UART_REG_RXCTRL) = UART_RXEN;
}

#endif /* TEST_INIT_H */
