/* perf.c — per-step handshake timing table, see perf.h (TIMING=1). */
#include "perf.h"

#ifdef TIMING_BREAKDOWN
#define PERF_MARKS 8

static struct {
	const char *label;
	uint64_t cyc;
} marks[PERF_MARKS];
static int n_marks;

void perf_mark(const char *label, uint64_t cyc)
{
	if (n_marks < PERF_MARKS) {
		marks[n_marks].label = label;
		marks[n_marks].cyc = cyc;
		n_marks++;
	}
}

void perf_marks_print(void)
{
	for (int i = 0; i < n_marks; i++)
		perf_step(marks[i].label, marks[i].cyc);
	n_marks = 0;
}
#endif
