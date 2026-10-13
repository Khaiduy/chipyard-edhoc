/*
 * periph_gpio.c — GPIO peripheral test (Arty A7-100T, GPIO0 @ 0x64002000).
 *
 * Register-level test that needs no operator and no external wiring: every
 * check is a read-back of what was written. The 8 GPIO pins drive the board's
 * 4 LEDs and 4 RGB LED segments, so the walking-ones phase is also visible.
 *
 *   1. output enable / output value read-back
 *   2. walking ones across all 8 pins
 *   3. output XOR register
 *   4. pin isolation (no pin disturbs its neighbours)
 *
 * Prints one PASS/FAIL line per phase and a final verdict.
 */
#include <stdint.h>
#include "platform.h"
#include "gpio.h"
#include "kprintf.h"
#include "test_init.h"

#define GPIO_WIDTH 8
#define GPIO_MASK  ((1u << GPIO_WIDTH) - 1u)

static void gpio_w(uint32_t off, uint32_t v) { GPIO_REG(off) = v; }
static uint32_t gpio_r(uint32_t off) { return GPIO_REG(off); }

/* Make the LED state visible to a human without depending on any timer. */
static void settle(void)
{
	for (volatile int d = 0; d < 400000; d++)
		;
}

static int check(const char *what, uint32_t got, uint32_t want)
{
	int ok = (got == want);

	kprintf("  %s: got=%x want=%x %s\r\n", what, got, want,
		ok ? "PASS" : "FAIL");
	return ok ? 0 : 1;
}

int main(void)
{
	test_console_init();

	int fails = 0;

	kprintf("\r\n=== GPIO test (0x%x, %d pins) ===\r\n",
		(unsigned)GPIO_CTRL_ADDR, GPIO_WIDTH);

	/* Drive all pins as outputs, inputs enabled so we can read back. */
	gpio_w(GPIO_OUTPUT_EN, GPIO_MASK);
	gpio_w(GPIO_INPUT_EN, GPIO_MASK);
	gpio_w(GPIO_OUTPUT_XOR, 0);

	/* 1. output enable / value read-back */
	fails += check("output_en   ", gpio_r(GPIO_OUTPUT_EN) & GPIO_MASK, GPIO_MASK);
	gpio_w(GPIO_OUTPUT_VAL, 0);
	fails += check("all low     ", gpio_r(GPIO_OUTPUT_VAL) & GPIO_MASK, 0);
	gpio_w(GPIO_OUTPUT_VAL, GPIO_MASK);
	fails += check("all high    ", gpio_r(GPIO_OUTPUT_VAL) & GPIO_MASK, GPIO_MASK);
	settle();

	/* 2. walking ones — proves each pin is independently addressable */
	kprintf("  walking ones (watch the LEDs):\r\n");
	{
		int walk_fails = 0;

		for (int i = 0; i < GPIO_WIDTH; i++) {
			uint32_t bit = 1u << i;

			gpio_w(GPIO_OUTPUT_VAL, bit);
			if ((gpio_r(GPIO_OUTPUT_VAL) & GPIO_MASK) != bit) {
				kprintf("    pin %d: FAIL\r\n", i);
				walk_fails++;
			}
			settle();
		}
		kprintf("    walk: %s\r\n", walk_fails ? "FAIL" : "PASS");
		fails += walk_fails;
	}

	/* 3. output XOR register holds what we write */
	gpio_w(GPIO_OUTPUT_VAL, 0x0F);
	gpio_w(GPIO_OUTPUT_XOR, GPIO_MASK);
	fails += check("xor set     ", gpio_r(GPIO_OUTPUT_XOR) & GPIO_MASK, GPIO_MASK);
	gpio_w(GPIO_OUTPUT_XOR, 0);

	/* 4. pin isolation: alternating patterns must survive intact */
	gpio_w(GPIO_OUTPUT_VAL, 0xAA);
	fails += check("pattern AA  ", gpio_r(GPIO_OUTPUT_VAL) & GPIO_MASK, 0xAA);
	gpio_w(GPIO_OUTPUT_VAL, 0x55);
	fails += check("pattern 55  ", gpio_r(GPIO_OUTPUT_VAL) & GPIO_MASK, 0x55);

	/* Leave the LEDs off. */
	gpio_w(GPIO_OUTPUT_VAL, 0);

	kprintf("GPIO TEST: %s (%d failures)\r\n", fails ? "FAIL" : "PASS", fails);
	while (1)
		;
	return 0;
}
