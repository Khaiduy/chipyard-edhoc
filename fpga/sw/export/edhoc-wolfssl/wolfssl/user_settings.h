/* user_settings.h — wolfCrypt bare-metal config for RV32IMAC EDHOC
 *
 * All suites 0–7, 24, 25 share this file.  Features are conditionally enabled
 * by EDHOC_CRYPTO_SUITE (injected via Makefile -D flag) so that only the
 * cryptographic primitives actually needed for a given suite are compiled.
 *
 * Suite → required wolfCrypt features:
 *   0,1 : AES-CCM + SHA-256 + X25519 + Ed25519  (Ed25519 needs SHA-512)
 *   2,3 : AES-CCM + SHA-256 + P-256 + ES256
 *   4   : ChaCha20/Poly1305 + SHA-256 + X25519 + Ed25519
 *   5   : ChaCha20/Poly1305 + SHA-256 + P-256 + ES256
 *   6   : AES-128-GCM + SHA-256 + X25519 + Ed25519
 *   7   : Ascon-AEAD-128 + Ascon-Hash256 + X25519 + Ed25519
 *   24  : AES-256-GCM + SHA-384 + P-384 + ES384
 *   25  : ChaCha20/Poly1305 + SHAKE-256 + X448 + Ed448
 */
#ifndef WOLF_USER_SETTINGS_H
#define WOLF_USER_SETTINGS_H

/* ── Core mode ─────────────────────────────────────────────────────── */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WOLFSSL_MEMORY       /* no wolfSSL memory wrappers; use raw libc */
#define WOLFSSL_EXPERIMENTAL_SETTINGS  /* required for Ascon */

/* ── Math backend: SP (single-precision) C-only ────────────────────── */
/* WOLFSSL_SP_MATH, not _ALL. _ALL keeps wolfCrypt's generic multi-precision
 * bignum (sp_exptmod, _sp_div, sp_invmod, sp_read_radix, mp_sqrtmod_prime)
 * *alongside* the curve-specific sp_256 and sp_384 code, so the image pays for
 * two independent ECC implementations. Plain SP_MATH keeps only the
 * curve-specific paths, which is all EDHOC needs.
 *
 * Measured on RV64, suite 2, this build:  text 51432 -> 36328 (-15.1 kB),
 * rodata 5421 -> 2685 (-2.7 kB). It is the difference between the P-256 and
 * P-384 suites overflowing the 64 kB scratchpad and every suite fitting.
 *
 * WOLFSSL_SP_NO_MALLOC keeps SP's temporaries on the stack, which lets the
 * libc_stubs heap arena shrink from 16 kB to 1 kB (see HEAP_ARENA_SIZE).
 */
#define WOLFSSL_SP_MATH         /* curve-specific SP only; no generic bignum */
#define WOLFSSL_SP_NO_MALLOC    /* SP temporaries on the stack, not the heap */
/* RV64: 64-bit SP words (sp_c64.c). Products are unsigned __int128, which GCC
 * lowers to mul/mulhu inline; WOLFSSL_SP_DIV_WORD_HALF keeps division to
 * 64-bit divides, so no libgcc __udivti3 is linked (libgcc here is built
 * -mcmodel=medlow and cannot reach the 0x80000000 RAM base). Measured on the
 * board: suite 2 handshake compute 2.71 s -> 1.82 s against sp_c32.c. */
#define SP_WORD_SIZE 64
#define HAVE___UINT128_T
#define WOLFSSL_SP_DIV_WORD_HALF
/* WOLFSSL_SP_SMALL: kept on. It was measured against the fast variant on this
 * target and made no difference to the handshake (984,762,438 vs 984,745,543
 * cycles), while turning it off grows the P-256/P-384 images enough to
 * overflow the 64 kB scratchpad. Size for free. */
#define WOLFSSL_SP_SMALL        /* smaller code / fewer unrolled loops */
#define WOLFSSL_SP_NO_PINNED_REGS

/* ── AEAD, SHA-256/384, HMAC, HKDF: not wolfCrypt's ─────────────────
 * AES-CCM/GCM, SHA-256/384, HMAC and HKDF come from common/crypto (shared with
 * edhoc-authkem), ChaCha20-Poly1305 from Monocypher. wolfCrypt is left with
 * P-256/P-384 (SP math), X448/Ed448 and SHA-3/KMAC (suite 25). */
#define NO_AES
#define NO_HMAC


/* ── Hash algorithms ───────────────────────────────────────────────────
 * SHA-256/384 come from common/crypto; wolfCrypt's RNG takes its output
 * straight from our CSPRNG (CUSTOM_RAND_GENERATE_BLOCK below), so it needs no
 * SHA-256 DRBG. Only suite 25's SHA-3 family remains wolfCrypt's. */
#define NO_SHA256
#define WC_NO_HASHDRBG
#if EDHOC_CRYPTO_SUITE != 25
#  define WC_HASH_CUSTOM_MIN_DIGEST_SIZE 32   /* no wolfCrypt hash compiled */
#endif

/* SHA-3 / SHAKE-256 / KMAC256: Suite 25 only.
 * RFC 9528 §4.1.1 mandates KMAC256 (not HMAC-SHA3-256) for EDHOC_Extract/Expand.
 * WOLFSSL_SHA3_SMALL: compact Keccak permutation. Saves ~1-2 KB; permutation
 * ~1.5x slower but Suite 25 runtime is dominated by X448/Ed448 so SHAKE
 * cycles are noise. */
#if EDHOC_CRYPTO_SUITE == 25
#  define WOLFSSL_SHA3
#  define WOLFSSL_SHAKE256
#  define WOLFSSL_KMAC
#  define WOLFSSL_SHA3_SMALL
#endif

#define NO_SHA
#define NO_MD5



/* ── ECC P-256 / ES256 — Suites 2, 3, 5, 6 ───────────────────────────
 * Suites 2/3/5: P-256 ECDH + ES256 sign (need HAVE_ECC_DHE).
 * Suite 6:      X25519 ECDH + ES256 sign (ECDH via curve25519, ECC only for sign). */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || \
    EDHOC_CRYPTO_SUITE == 5 || EDHOC_CRYPTO_SUITE == 6
#  define HAVE_ECC
#  define WOLFSSL_HAVE_SP_ECC   /* enables sp_c32.c P-256 path; without this,
                                 * ecc.c falls back to heap-alloc generic path
                                 * which fails on bare-metal (malloc returns NULL) */
#  define WOLFSSL_SP_NO_384     /* P-256 builds: exclude P-384 SP code */
#  define ECC_TIMING_RESISTANT
#  define HAVE_COMP_KEY         /* wc_ecc_import_x963_ex (0x02/0x03 prefix)
                                 * returns NOT_COMPILED_IN without this */
#endif
/* HAVE_ECC_DHE only for the suites that actually use P-256 for ECDH (not Suite 6). */
#if EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || \
    EDHOC_CRYPTO_SUITE == 5
#  define HAVE_ECC_DHE
#endif

/* ── ECC P-384 / ES384 — Suite 24 ──────────────────────────────────── */
#if EDHOC_CRYPTO_SUITE == 24
#  define HAVE_ECC
#  define HAVE_ECC_DHE
#  define WOLFSSL_HAVE_SP_ECC   /* enables sp_c32.c P-384 path */
#  define WOLFSSL_SP_384        /* gates the P-384 block in sp_c32.c */
#  define WOLFSSL_SP_NO_256     /* P-384 builds: exclude P-256 SP code */
#  define HAVE_ECC384           /* needed alongside WOLFSSL_SP_384 */
#  define ECC_TIMING_RESISTANT
#  define HAVE_COMP_KEY         /* wc_ecc_import_x963_ex (compressed point) uses
                                 * sp_ecc_uncompress_384 — no heap needed */
#endif

/* Sign/verify gating: wolfSSL's settings.h force-defines HAVE_ECC_SIGN and
 * HAVE_ECC_VERIFY whenever HAVE_ECC is set. Use the NO_* opt-outs to remove
 * the path the role doesn't need. Mirrors the Ed25519/Ed448 NO_*_SIGN/VERIFY
 * pattern: only drop a path when its opposite is explicitly active.
 * Verify-only role (PEER_SK, !AUTH_SK) → drop SIGN.
 * Sign-only role  (AUTH_SK, !PEER_SK) → drop VERIFY.
 * Method 3 (neither flag): keep both (sp_c32.c needs order arithmetic that
 * is only compiled in when SIGN or VERIFY is enabled). */
#if (EDHOC_CRYPTO_SUITE == 2 || EDHOC_CRYPTO_SUITE == 3 || \
     EDHOC_CRYPTO_SUITE == 5 || EDHOC_CRYPTO_SUITE == 6 || \
     EDHOC_CRYPTO_SUITE == 24)
#  if defined(EDHOC_PEER_SK) && !defined(EDHOC_AUTH_SK)
#    define NO_ECC_SIGN
#  endif
#  if defined(EDHOC_AUTH_SK) && !defined(EDHOC_PEER_SK)
#    define NO_ECC_VERIFY
#  endif
#endif

/* ── X448 / Ed448 — Suite 25 ────────────────────────────────────────── */
/* X448 and Ed448 use wolfSSL's 64-bit field (CURVED448_128BIT: 8 x 56-bit
 * limbs, 128-bit products, golden-ratio Karatsuba), as X25519 uses donna-c64.
 * The *_SMALL variants work on 56 one-byte limbs: ~3000 64-bit multiplies per
 * field multiply on a core whose multiplier is bit-serial, about 20x slower.
 * WOLFSSL_ED448_NO_BASE_TABLE is a local option (ge_448.c) that replaces the
 * 59 kB table of base-point multiples with a constant-time ladder. */
#if EDHOC_CRYPTO_SUITE == 25
#  define HAVE_CURVE448
#endif
/* Ed448: only when this role signs (AUTH_SK) or verifies (PEER_SK).
 * Method 3 uses static DH on both sides and needs no Ed448 at all. */
#if EDHOC_CRYPTO_SUITE == 25 \
    && (defined(EDHOC_AUTH_SK) || defined(EDHOC_PEER_SK))
#  define HAVE_ED448
#  define WOLFSSL_ED448_NO_BASE_TABLE
#  define WOLFSSL_ED448_NO_LARGE_CODE
#endif
#if EDHOC_CRYPTO_SUITE == 25 && defined(EDHOC_PEER_SK) && !defined(EDHOC_AUTH_SK)
#  define NO_ED448_SIGN
#endif
#if EDHOC_CRYPTO_SUITE == 25 && defined(EDHOC_AUTH_SK) && !defined(EDHOC_PEER_SK)
#  define NO_ED448_VERIFY
#endif

/* ── RNG ─────────────────────────────────────────────────────────────── */
/* Bypass wolfSSL's DRBG — call our platform CSPRNG directly. */
#ifndef __ASSEMBLER__
int csprng_generate_block(unsigned char *output, unsigned int sz);
#endif
#define CUSTOM_RAND_GENERATE_BLOCK csprng_generate_block

/* ── Disabled features (reduce footprint) ───────────────────────────── */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_AES_CBC
#define NO_CERTS
#define NO_ASN
#define NO_ASN_CRYPT
#define NO_PSK
#define NO_ERROR_STRINGS
#define NO_WOLFSSL_STUB
#define WOLFSSL_NO_SOCK
#define NO_MULTIBYTE_PRINT
#define WC_NO_RNG_SIMPLE
#define NO_OLD_RNGNAME
#define NO_PWDBASED
#define WOLFSSL_NO_HASH_RAW

/* ── Bare-metal I/O ──────────────────────────────────────────────────── */
#define NO_WRITEV
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM

/* ── Size optimisations for embedded ─────────────────────────────────── */
/* WOLFSSL_SMALL_STACK intentionally disabled: malloc() always returns NULL on
 * this bare-metal target, so heap-allocated wolfSSL structs would silently
 * fail, producing zero-filled hash/HMAC outputs.  All structs go on the
 * stack instead; ~31 KB of headroom is available. */

#endif /* WOLF_USER_SETTINGS_H */
