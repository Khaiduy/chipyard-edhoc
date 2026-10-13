#ifndef STACK_PROBE_H
#define STACK_PROBE_H

#include <stddef.h>

/* Runtime stack high-water measurement.
 *
 * crt0 paints the whole stack reservation [_heap_end, _ram_end) with
 * STACK_CANARY_BYTE before calling main. Scanning upward from the bottom for
 * the first surviving canary byte gives the deepest point the stack has ever
 * reached -- including transient frames that have already returned, which is
 * exactly what a static analyser misses.
 *
 * Why this rather than -fstack-usage alone: .su files miss multi-instruction
 * prologues, VLAs, and anything LTO merges or inlines across translation
 * units. The measured figure is the one STACK_SIZE should be derived from. */

#define STACK_CANARY_BYTE 0x5A

/* Deepest stack use observed so far, in bytes. */
size_t stack_highwater(void);

/* The declared stack reservation, in bytes (== STACK_SIZE). */
size_t stack_reserve(void);

/* Free RAM above .bss, in bytes: the region crt0 paints, and the real limit
 * the stack has to stay inside. */
size_t stack_free_region(void);

/* Nonzero if peak depth exceeded the declared reservation. The program can
 * still run in that state -- it grows into the incidental free RAM below the
 * reservation -- so this is the check that catches a STACK_SIZE which is only
 * working by luck. */
int stack_overran_reserve(void);

/* Bytes of painted RAM never touched. Zero means the mark reached _end and
 * the stack has run into .bss: the figure is then a lower bound and memory
 * is already corrupt. */
size_t stack_headroom(void);

/* Diagnostic: total surviving canary bytes in the painted region. */
size_t stack_canary_bytes(void);

#endif /* STACK_PROBE_H */
