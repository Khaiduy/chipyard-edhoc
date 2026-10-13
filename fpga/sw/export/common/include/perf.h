/*
 * perf.h — cycle and wall-time reporting for the EDHOC steps.
 *
 * Requirement A5 asks for "cycle count and execution time" per step, so every
 * measurement is printed both ways. Time is derived from the cycle counter and
 * the SoC clock; there is no wall clock on this target.
 *
 * PERF_CPU_HZ must match the bitstream. The Arty A7-100T configs in this tree
 * run the core at 75 MHz (EdhocRocket6475MHzArty100TConfig); override with
 * -DPERF_CPU_HZ=... if you build a different frequency.
 *
 * Output is one line per step, fixed shape, so a host script can tabulate it:
 *   PERF <label> <cycles> cyc <sec>.<ms><us> s
 */
#ifndef EDHOC_PERF_H
#define EDHOC_PERF_H

#include <stdint.h>
#include "kprintf.h"

/* 64-bit cycle counter, one instruction on the RV64 target. */
static inline uint64_t read_cycles(void)
{
	uint64_t c;

	__asm__ volatile ("rdcycle %0" : "=r" (c));
	return c;
}

#ifndef PERF_CPU_HZ
#define PERF_CPU_HZ 75000000u
#endif

/**
 * @brief  Reports one measured step as cycles and as elapsed time.
 * @param label  Step name, printed verbatim.
 * @param cyc    Cycle count for that step.
 */
static inline void perf_step(const char *label, uint64_t cyc)
{
	uint64_t us = cyc / (PERF_CPU_HZ / 1000000u);

	kprintf("PERF %s %lu cyc %lu.%06lu s\r\n", label, (unsigned long)cyc,
		(unsigned long)(us / 1000000u), (unsigned long)(us % 1000000u));
}

/**
 * @brief  Reports a data transfer: cycles, time and throughput in bytes/s.
 */
static inline void perf_xfer(const char *label, uint32_t bytes, uint64_t cyc)
{
	uint64_t us = cyc / (PERF_CPU_HZ / 1000000u);
	uint64_t bps = us ? (uint64_t)bytes * 1000000u / us : 0;

	kprintf("PERF %s %lu cyc %lu.%06lu s %u bytes %lu B/s\r\n", label,
		(unsigned long)cyc, (unsigned long)(us / 1000000u),
		(unsigned long)(us % 1000000u), (unsigned)bytes, (unsigned long)bps);
}

#ifdef TIMING_BREAKDOWN
/* TIMING=1: the EDHOC libraries time each message step with PERF_TIME and
 * the application prints the steps after the handshake (perf_marks_print),
 * so printing does not land inside the measured handshake. */
void perf_mark(const char *label, uint64_t cyc);
void perf_marks_print(void);
#define PERF_TIME(label, stmt)                                                 \
	do {                                                                   \
		uint64_t _perf_t0 = read_cycles();                             \
		stmt;                                                          \
		perf_mark(label, read_cycles() - _perf_t0);                    \
	} while (0)
#endif

#endif /* EDHOC_PERF_H */
