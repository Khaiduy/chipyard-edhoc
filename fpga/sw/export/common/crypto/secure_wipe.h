#ifndef SECURE_WIPE_H
#define SECURE_WIPE_H

#include <stddef.h>
#include <stdint.h>

/* Erase key material so it does not outlive its use.
 *
 * A plain memset() over a buffer that is dead afterwards is a legal target
 * for dead-store elimination, and at -O2/-flto the compiler does remove it.
 * Writing through a volatile pointer is not removable.
 *
 * Scope: this clears secrets on the normal return path. Error paths taken by
 * the TRY() macro return early and skip the wipe, and any copies the compiler
 * spilled to other stack slots or registers are not reachable from here. It
 * shortens the window; it does not close it.
 */
/* Defined in src/common/secure_wipe.c. Forcing it out of line was tried and
 * made things worse: the ~420 B the wipes cost is per-call-site setup, not
 * the loop body, and noinline added call overhead on top. */
void edhoc_wipe(void *p, size_t n);

#endif /* SECURE_WIPE_H */
