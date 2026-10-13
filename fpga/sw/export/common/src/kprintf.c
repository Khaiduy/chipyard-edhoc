// See LICENSE.Sifive for license details.
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#include "kprintf.h"

#include <stddef.h>

/* Single out-of-line kputc definition.
 * Under -flto, an inline-in-header version may be inlined inconsistently across
 * translation units; one out-of-line definition guarantees every caller hits
 * the same verified-clean MMIO sequence (load → branch-if-full → store). */
__attribute__((noinline)) void kputc(char c)
{
	volatile uint32_t *tx = &REG32(uart, UART_REG_TXFIFO);
	/* CR-before-LF so a bare '\n' (e.g. the EDHOC library's printf("\n\t%02X"))
	 * returns to column 0 instead of staircasing. Guarded on the previous char
	 * so strings that already send "\r\n" don't emit a double CR. */
	static char prev = 0;
	if (c == '\n' && prev != '\r') {
		while ((int32_t)(*tx) < 0);
		*tx = (uint32_t)(uint8_t)'\r';
	}
	while ((int32_t)(*tx) < 0);
	*tx = (uint32_t)(uint8_t)c;
	prev = c;
}


static inline void _kputs(const char *s)
{
	char c;
	for (; (c = *s) != '\0'; s++)
		kputc(c);
}

void kputs(const char *s)
{
	_kputs(s);
	kputc('\r');
	kputc('\n');
}

/* Unsigned n in base 10 or 16, right-aligned to width with pad. */
static void put_num(unsigned long n, unsigned base, bool upper, int width,
		    char pad)
{
	char buf[24];
	int i = 0;

	do {
		unsigned d = (unsigned)(n % base);
		buf[i++] = (char)(d < 10 ? '0' + d : (upper ? 'A' : 'a') + d - 10);
		n /= base;
	} while (n);
	while (width-- > i)
		kputc(pad);
	while (i--)
		kputc(buf[i]);
}

/* Supports %d %u %x %X %s %c %%, the l modifier, and a width with an
 * optional 0 flag (e.g. %02X). */
void vkprintf(const char *fmt, va_list vl)
{
	char c;

	while ((c = *fmt++) != '\0') {
		if (c != '%') {
			kputc(c);
			continue;
		}
		char pad = ' ';
		int width = 0;
		bool is_long = false;

		if (*fmt == '0') {
			pad = '0';
			fmt++;
		}
		while (*fmt >= '0' && *fmt <= '9')
			width = width * 10 + (*fmt++ - '0');
		if (*fmt == 'l') {
			is_long = true;
			fmt++;
		}
		switch (c = *fmt++) {
		case 'd': {
			long n = is_long ? va_arg(vl, long) : va_arg(vl, int);
			if (n < 0) {
				kputc('-');
				n = -n;
			}
			put_num((unsigned long)n, 10, false, width, pad);
			break;
		}
		case 'u':
		case 'x':
		case 'X':
			put_num(is_long ? va_arg(vl, unsigned long) : va_arg(vl, unsigned int),
				c == 'u' ? 10 : 16, c == 'X', width, pad);
			break;
		case 's':
			_kputs(va_arg(vl, const char *));
			break;
		case 'c':
			kputc((char)va_arg(vl, int));
			break;
		case '%':
			kputc('%');
			break;
		case '\0':
			return;
		default:
			kputc('%');
			kputc(c);
			break;
		}
	}
}

void kprintf(const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vkprintf(fmt, vl);
	va_end(vl);
}
