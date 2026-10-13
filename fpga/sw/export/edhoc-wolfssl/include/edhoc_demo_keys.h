#ifndef EDHOC_DEMO_KEYS_H
#define EDHOC_DEMO_KEYS_H

/* DEMO long-term signing seeds — NOT FOR PRODUCTION.
 *
 * These two constants derive the Initiator's and Responder's long-term
 * signing key pairs. They are fixed, public, and identical on every device
 * built from this tree, so any image containing them has no authentication
 * value whatsoever: anyone can derive the private key and impersonate either
 * party.
 *
 * PROFILE=production refuses to compile this header. Long-term keys must come
 * from edhoc_device_sign_sk() / edhoc_device_sign_pk() instead; see
 * include/edhoc_provision.h.
 *
 * Key sizes and algorithm metadata deliberately live in edhoc_suite_defs.h,
 * not here, so code needing a buffer length does not have to pull in key
 * material to get it.
 */

#ifdef EDHOC_PROFILE_PRODUCTION
#error "edhoc_demo_keys.h holds fixed DEMO signing seeds shared by every build and must never enter a production image. Provide device keys via PROVISION_SRC (see include/edhoc_provision.h)."
#endif

#define EDHOC_DEMO_I_SIGN_SEED                                                 \
	{                                                                      \
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x01                                                     \
	}

#define EDHOC_DEMO_R_SIGN_SEED                                                 \
	{                                                                      \
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x02                                                     \
	}

/* Static DH demo keys (methods 1-3): 32-byte scalars, zero-padded to the
 * suite's DH key length. */
#define EDHOC_DEMO_I_DH_SEED                                                   \
	{                                                                      \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x01                                                     \
	}
#define EDHOC_DEMO_R_DH_SEED                                                   \
	{                                                                      \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    \
		0x00, 0x02                                                     \
	}

#endif /* EDHOC_DEMO_KEYS_H */
