#ifndef AUTHKEM_PROVISION_H
#define AUTHKEM_PROVISION_H

#include <stdint.h>

/* Provisioning interface for PROFILE=production.
 *
 * The demo profile builds with the ML-KEM-512 test vectors in
 * src/mlkem512_test_keys.h and a deterministically seeded CSPRNG. Both are
 * fine on a bench with two boards and unusable in the field: the private keys
 * sit in the firmware image, so every device flashed with it shares one
 * identity, and the CSPRNG is seeded from cycle-counter jitter.
 *
 * PROFILE=production removes both. It provides no default for anything
 * declared here, so a missing implementation is a link error at build time
 * rather than something discovered on a device.
 *
 * Supply implementations via PROVISION_SRC=<files>, and device credentials
 * via PROVISION_DIR=<dir> containing an authkem_creds.h that defines
 * CRED_I_CCS / CRED_R_CCS / CRED_I_PK / CRED_R_PK and the matching _LEN
 * macros, in the same shape tools/gen_ccs.c emits for the demo profile.
 */

/* The entropy hook, edhoc_platform_entropy(), is declared in
 * edhoc_entropy.h (shared with edhoc-wolfssl). */
#include "edhoc_entropy.h"

/* Return a pointer to this device's ML-KEM-512 static private key
 * (MLKEM512_SK_SIZE bytes).
 *
 * Returning a pointer into ordinary .rodata reintroduces the problem this
 * interface exists to solve: the key is then readable by anyone who can read
 * flash. Prefer a key that never leaves a hardware key store, exposing only
 * a decapsulate operation; where that is not available, at minimum keep the
 * key in a region the application cannot read after boot.
 */
const uint8_t *authkem_device_static_sk(void);

#endif /* AUTHKEM_PROVISION_H */
