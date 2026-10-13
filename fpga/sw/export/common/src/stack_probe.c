#include "stack_probe.h"

extern char _end[];        /* top of .bss; free RAM starts here */
extern char _heap_end[];   /* bottom of the declared stack reservation */
extern char _ram_end[];    /* top of RAM; the stack grows down from here */

size_t stack_reserve(void)
{
	return (size_t)(_ram_end - _heap_end);
}

size_t stack_free_region(void)
{
	return (size_t)(_ram_end - _end);
}

size_t stack_highwater(void)
{
	const char *p = _end;

	while (p < _ram_end && *p == (char)STACK_CANARY_BYTE)
		p++;

	return (size_t)(_ram_end - p);
}

int stack_overran_reserve(void)
{
	return stack_highwater() > stack_reserve();
}

size_t stack_headroom(void)
{
	size_t peak = stack_highwater();
	size_t free_region = stack_free_region();

	/* Headroom against the RAM actually available, not against the declared
	 * reservation -- the reservation can be, and here was, too small. */
	return (free_region > peak) ? (free_region - peak) : 0;
}

size_t stack_canary_bytes(void)
{
	/* Total surviving canary bytes anywhere in the painted region.
	 *
	 * Diagnostic: if this is much larger than free_region - highwater, the
	 * first non-canary byte near _end is an isolated write (a global the
	 * linker placed above _end, or a stray store) rather than the stack
	 * mark, and highwater is an overestimate. */
	const char *p;
	size_t n = 0;

	for (p = _end; p < _ram_end; p++)
		if (*p == (char)STACK_CANARY_BYTE)
			n++;
	return n;
}
