/* edhoc_board.c - see include/edhoc_board.h. */
#include "edhoc_board.h"
#include "platform.h"
#include "kprintf.h"
#include "perf.h"
#include "secure_wipe.h"
#include "stack_probe.h"
#include "uart.h"
#include "edhoc_suite_defs.h"
#include "edhoc_transport.h"
#include "edhoc_app_data.h"
#include "common/print_util.h"

extern volatile uint64_t g_uart_cycles;

#define EDHOC_UART_BAUD 57600u
#define EDHOC_UART_DIV  (PERF_CPU_HZ / EDHOC_UART_BAUD)

void board_init(int is_responder)
{
	REG32(uart, UART_REG_DIV) = EDHOC_UART_DIV;
	REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
#ifndef EDHOC_TRANSPORT_RF
	REG32_UART1(UART_REG_DIV) = UART1_DIV;
	REG32_UART1(UART_REG_TXCTRL) = UART_TXEN;
	REG32_UART1(UART_REG_RXCTRL) = UART_RXEN;
	/* UART1 link only. The images are loaded over JTAG with halt/resume,
	 * never a reset, so loading the peer glitches bytes onto UART1 and the
	 * RX FIFO keeps the previous session's traffic. The responder settles
	 * briefly and drains; the initiator waits long enough that the
	 * responder is listening before message_1 goes out (EDHOC never
	 * retransmits). The radio link has its own framing and ACKs. */
	for (volatile uint32_t s = 0; s < (is_responder ? 40000000u : 90000000u); s++)
		;
	if (is_responder) {
		uint32_t quiet = 0, budget = 100000, dropped = 0;

		while (quiet < 2000 && budget-- > 0) {
			if (uart1_getc() >= 0) {
				quiet = 0;
				dropped++;
			} else {
				quiet++;
			}
		}
		if (dropped)
			kprintf("resp: dropped %u stale bytes\r\n", (unsigned)dropped);
	}
#endif
	kprintf("START (%s, method %d, suite %d)\r\n",
		is_responder ? "responder" : "initiator", EDHOC_METHOD,
		EDHOC_CRYPTO_SUITE);
	g_uart_cycles = 0;
}

void board_report(uint64_t t0, uint64_t t1)
{
	/* Handshake cost with the link time subtracted: crypto + CBOR work. */
	uint64_t tot = t1 - t0, lnk = g_uart_cycles;

	perf_step("handshake_total  ", tot);
	perf_step("handshake_link   ", lnk);
	perf_step("handshake_compute", tot > lnk ? tot - lnk : 0);
#ifdef TIMING_BREAKDOWN
	perf_marks_print();    /* compute time of each message step */
#endif
	/* Peak stack depth, from the canary crt0 painted over free RAM. */
	kprintf("STACK peak %u B, reserve %u B, free %u B, headroom %u%s\r\n",
		(unsigned)stack_highwater(), (unsigned)stack_reserve(),
		(unsigned)stack_free_region(), (unsigned)stack_headroom(),
		stack_overran_reserve() ? "  OVERRAN-RESERVE" : "");
}

void board_app_data(struct byte_array *prk_out, int is_initiator)
{
	static struct app_chan ch;
	enum err r;

	PRINT_ARRAY("PRK_out:", prk_out->ptr, prk_out->len);
	r = app_data_init(&ch, SUITE_ENUM, prk_out, is_initiator);
	if (r != ok) {
		kprintf("APP init FAIL: %d\r\n", r);
		return;
	}
	r = is_initiator ? app_data_run_initiator(&ch, tx_initiator, rx_initiator, NULL) :
			   app_data_run_responder(&ch, tx_responder, rx_responder, NULL);
	if (r != ok)
		kprintf("APP DATA FAIL: %d\r\n", r);
	edhoc_wipe(&ch, sizeof(ch));
}
