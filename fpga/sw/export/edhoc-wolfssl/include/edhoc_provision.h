#ifndef EDHOC_PROVISION_H
#define EDHOC_PROVISION_H

#include <stdint.h>

/* Provisioning interface for PROFILE=production (wolfCrypt build).
 *
 * The demo profile derives long-term keys from the fixed seeds in
 * include/edhoc_demo_keys.h and seeds its CSPRNG from cycle-counter jitter.
 * Both are fine on a bench and useless in the field.
 *
 * PROFILE=production provides no default for anything declared here, so a
 * missing implementation is a link error at build time rather than something
 * found on a device. Supply implementations via PROVISION_SRC=<files>.
 *
 * Buffer lengths come from edhoc_suite_defs.h (SUITE_SIGN_SK_LEN etc.), which
 * carries no key material.
 */

/* The entropy hook, edhoc_platform_entropy(), is declared in
 * common/include/edhoc_entropy.h. */
#include "edhoc_entropy.h"

/* This device's long-term signing private key, SUITE_SIGN_SK_LEN bytes.
 *
 * Returning a pointer into ordinary .rodata reintroduces exactly the problem
 * this interface exists to solve. Prefer a key held in a hardware key store
 * that exposes only a sign operation. */
const uint8_t *edhoc_device_sign_sk(void);

/* This device's long-term signing public key, SUITE_SIGN_PK_LEN bytes. */
const uint8_t *edhoc_device_sign_pk(void);

/* The trusted peer's long-term signing public key, SUITE_SIGN_PK_LEN bytes. */
const uint8_t *edhoc_peer_sign_pk(void);

#endif /* EDHOC_PROVISION_H */
