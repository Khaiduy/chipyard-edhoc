/*
 * edhoc_app.h - the demo identities and EDHOC contexts for one method, shared
 * by the board programs (src/edhoc_initiator.c, src/edhoc_responder.c) and
 * the host loopback test (tests/test_loopback.c).
 *
 * The method is a build-time choice, EDHOC_METHOD (RFC 9528 Section 3.2):
 *   0  initiator signs,          responder signs
 *   1  initiator signs,          responder static DH
 *   2  initiator static DH,      responder signs
 *   3  initiator static DH,      responder static DH
 */
#ifndef EDHOC_APP_H
#define EDHOC_APP_H

#include <stdint.h>
#include "edhoc.h"
#include "edhoc_suite_defs.h"

#ifndef EDHOC_METHOD
#error "build with -DEDHOC_METHOD=0..3"
#endif
#define APP_I_SIGNS (EDHOC_METHOD == 0 || EDHOC_METHOD == 1)
#define APP_R_SIGNS (EDHOC_METHOD == 0 || EDHOC_METHOD == 2)

/* Fill a context for this build's method from the demo identities (or, with
 * PROFILE=production, the provisioned signing keys). x/g_x (y/g_y) are the
 * caller's ephemeral key buffers, generated before the call; peer receives
 * the other party's credential entry. */
void app_initiator_ctx(struct edhoc_initiator_context *c,
		       struct other_party_cred *peer, uint8_t *x, uint8_t *g_x);
void app_responder_ctx(struct edhoc_responder_context *c,
		       struct other_party_cred *peer, uint8_t *y, uint8_t *g_y);

/* Fresh ephemeral key pair (SUITE_DH_LEN bytes each) from the CSPRNG. */
void app_ephemeral_key(uint8_t *sk, uint8_t *pk);

/* Wipe the long-term private keys once the handshake is done. */
void app_wipe_keys(void);

#endif /* EDHOC_APP_H */
