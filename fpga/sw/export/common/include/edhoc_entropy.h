#ifndef EDHOC_ENTROPY_H
#define EDHOC_ENTROPY_H

#include <stdint.h>

/* Hardware entropy hook for the CSPRNG (src/csprng_stub.c).
 *
 * The demo profile seeds the CSPRNG from cycle-counter jitter: fine on a
 * bench, useless in the field. PROFILE=production provides no default, so a
 * missing implementation is a link error at build time rather than something
 * found on a device; supply one via PROVISION_SRC=<files>.
 *
 * Fill `out` with `len` bytes from a conditioned hardware entropy source.
 * Return 1 only after every requested byte is written; any other value makes
 * default_CSPRNG() fail closed, and the handshake with it -- an EDHOC run with
 * predictable ephemeral keys is worse than no run. If the platform TRNG needs
 * the SP 800-90B continuous health tests (repetition count, adaptive
 * proportion), run them here and return 0 on failure rather than returning
 * suspect entropy. */
int edhoc_platform_entropy(uint8_t *out, unsigned int len);

#endif /* EDHOC_ENTROPY_H */
