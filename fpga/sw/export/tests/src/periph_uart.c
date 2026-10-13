/*
 * periph_uart.c — UART peripheral test (UART0 @ 0x64000000 console,
 *                 UART1 @ 0x64003000 PMOD JB board-to-board link).
 *
 * Phase 1/2 are self-contained register tests: the baud divisor and the TX/RX
 * control registers are written and read back, then restored. Phase 1 also
 * proves UART0 transmit implicitly — you are reading its output.
 *
 * Phase 3 probes UART1 for a loopback. It PASSES if a byte comes back (JB1-JB2
 * jumpered, or a peer board echoing), and reports SKIP otherwise rather than
 * failing, since an idle link is not a fault.
 */
#include <stdint.h>
#include "platform.h"
#include "uart.h"
#include "kprintf.h"
#include "test_init.h"

#define UART1_BASE 0x64003000UL
#define U0(i) (((volatile uint32_t *)UART_CTRL_ADDR)[(i) >> 2])
#define U1(i) (((volatile uint32_t *)UART1_BASE)[(i) >> 2])

static int check(const char *what, uint32_t got, uint32_t want)
{
	int ok = (got == want);

	kprintf("  %s: got=%x want=%x %s\r\n", what, got, want,
		ok ? "PASS" : "FAIL");
	return ok ? 0 : 1;
}

/* The divisor is the one register we can prove round-trips without disturbing
 * the console: write a probe value, read it, put the original back. */
static int test_div(volatile uint32_t *base_div, const char *name)
{
	uint32_t saved = *base_div;
	uint32_t probe = 0x0000002A;
	uint32_t got;
	int fails = 0;

	*base_div = probe;
	got = *base_div;
	*base_div = saved;              /* restore before printing anything */

	fails += check(name, got, probe);
	if (*base_div != saved) {
		kprintf("  %s: restore FAILED\r\n", name);
		fails++;
	}
	return fails;
}

int main(void)
{
	test_console_init();

	int fails = 0;

	kprintf("\r\n=== UART test ===\r\n");
	kprintf("  UART0 @ 0x%x (console), UART1 @ 0x%x (PMOD JB)\r\n",
		(unsigned)UART_CTRL_ADDR, (unsigned)UART1_BASE);

	/* 1. UART0 — reaching this line already proves TX works. */
	kprintf("  UART0 console TX: PASS (you are reading it)\r\n");
	fails += test_div(&U0(UART_REG_DIV), "UART0 div   ");

	/* 2. UART1 registers */
	fails += test_div(&U1(UART_REG_DIV), "UART1 div   ");
	U1(UART_REG_TXCTRL) = UART_TXEN;
	fails += check("UART1 txen  ", U1(UART_REG_TXCTRL) & UART_TXEN, UART_TXEN);
	U1(UART_REG_RXCTRL) = UART_RXEN;
	fails += check("UART1 rxen  ", U1(UART_REG_RXCTRL) & UART_RXEN, UART_RXEN);

	/* 3. UART1 loopback probe — drain first so we only see our own byte. */
	{
		const uint8_t probe = 0x5A;
		int got = -1;

		while ((int32_t)U1(UART_REG_RXFIFO) >= 0)
			;
		while ((int32_t)U1(UART_REG_TXFIFO) < 0)
			;
		U1(UART_REG_TXFIFO) = probe;

		for (int t = 0; t < 20000000 && got < 0; t++) {
			int32_t v = (int32_t)U1(UART_REG_RXFIFO);

			if (v >= 0)
				got = v & 0xFF;
		}

		if (got < 0)
			kprintf("  UART1 loop  : SKIP (no echo; jumper JB1-JB2 to test)\r\n");
		else if (got == probe)
			kprintf("  UART1 loop  : got=%x want=%x PASS\r\n", got, probe);
		else {
			kprintf("  UART1 loop  : got=%x want=%x FAIL\r\n", got, probe);
			fails++;
		}
	}

	kprintf("UART TEST: %s (%d failures)\r\n", fails ? "FAIL" : "PASS", fails);
	while (1)
		;
	return 0;
}
