/*
 * csprng_stub.c — Demo CSPRNG for bare-metal RISC-V FPGA
 *
 * Entropy source : rdcycle (multiple samples) + CLINT mtime via MMIO
 *                  (base 0x02000000, mtime at +0xBFF8). The rdtime CSR
 *                  is NOT used — it traps on this board configuration.
 *
 * Backends       : EDHOC_SHA256_CSPRNG (edhoc-wolfssl, common/crypto
 *                  SHA-256/HMAC) or EDHOC_KECCAK_CSPRNG (edhoc-authkem,
 *                  reusing the Keccak linked for ML-KEM).
 *
 * Whitening      : 64 bytes of raw entropy -> 32-byte key, by SHA-256 or
 *                  SHAKE256.
 *
 * Stream output  : HMAC-SHA-256 or KMAC256 counter mode, keyed by the
 *                  32-byte key.
 *
 * Board entropy  : Call csprng_add_entropy(data, len) after long-term keys
 *                  are derived to fold in board-specific material. This
 *                  guarantees different ephemeral keys on initiator vs.
 *                  responder even when mtime/rdcycle values match.
 * *
 * Limitation: entropy comes from execution timing. Main variation is CLINT
 *   mtime at seed time, which differs between FPGA programming sessions.
 *   For production security, replace with a real TRNG peripheral.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "perf.h"          /* read_cycles() */
#include "secure_wipe.h"

#ifdef EDHOC_SHA256_CSPRNG
#include "sha256.h"
#include "hmac_hkdf.h"
#endif

#ifdef EDHOC_KECCAK_CSPRNG
#include "keccak_kmac.h"
#endif

/* CLINT mtime low 32 bits (Arty A7 SoC: CLINT base = 0x02000000).
 * mtime offset = 0xBFF8. Returns 0 if CLINT is not present. */
static inline uint32_t rv32_clint_mtime(void)
{
    return *(volatile uint32_t *)0x0200BFF8UL;
}

/* -------------------------------------------------------------------------
 * splitmix64 finalizer — avalanche mixer, no dependencies.
 * ------------------------------------------------------------------------- */
static uint64_t mix64(uint64_t x)
{
    x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27; x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/* -------------------------------------------------------------------------
 * CSPRNG state
 * ------------------------------------------------------------------------- */
#if !defined(EDHOC_SHA256_CSPRNG) && !defined(EDHOC_KECCAK_CSPRNG)
#error "csprng_stub.c needs EDHOC_SHA256_CSPRNG or EDHOC_KECCAK_CSPRNG"
#endif
static uint8_t  g_key[32];
static uint32_t g_counter;

static int g_ready = 0;

#ifdef EDHOC_PROFILE_PRODUCTION
/* Declares edhoc_platform_entropy() without defining it, so the failure for a
 * missing TRNG is an undefined-reference at link rather than an implicit
 * declaration at compile. */
#include "edhoc_entropy.h"
#endif

#if !defined(EDHOC_INSECURE_DEMO_RNG) && !defined(EDHOC_PROFILE_PRODUCTION)
/* Integration point for non-demo builds that are not yet PROFILE=production.
 * Fails closed: default_CSPRNG() refuses to seed, so a handshake cannot run
 * with predictable ephemeral keys.
 *
 * PROFILE=production deliberately omits this default. A weak fail-closed stub
 * turns a missing TRNG into a runtime failure discovered on a device; with no
 * definition at all it is a link error at build time, which is where a
 * missing entropy source should be caught. See include/edhoc_entropy.h. */
__attribute__((weak)) int edhoc_platform_entropy(uint8_t *out,
						 unsigned int len)
{
	(void)out; (void)len;
	return 0;
}
#endif

/* -------------------------------------------------------------------------
 * Entropy collection and initial seeding
 * ------------------------------------------------------------------------- */
static void csprng_seed(void)
{
#ifndef EDHOC_INSECURE_DEMO_RNG
	uint8_t entropy[64];
	if (edhoc_platform_entropy(entropy, sizeof(entropy)) != 1)
		return; /* fail closed in default_CSPRNG */
#else
    /*
     * Collect 8 entropy words:
     *   raw[0..3]: rdcycle snapshots (64-bit, large value after sign_key_gen)
     *   raw[4]:    CLINT mtime low 32 bits (main inter-run entropy source)
     *   raw[5]:    second mtime sample + accumulated work word
     *   raw[6..7]: inter-sample cycle differences (timing jitter)
     *
     * Between samples, run volatile busy-loops of different lengths so
     * each successive reading lands at a different pipeline/memory offset.
     */
    uint64_t raw[8];
    volatile uint32_t work = 0;

    raw[0] = read_cycles();
    raw[4] = (uint64_t)rv32_clint_mtime();

    /* Delay 1 */
    for (volatile int i = 0; i < 500; i++) work ^= (uint32_t)(i * 0x9e3779b9u);
    raw[1] = read_cycles();

    /* Delay 2 — memory-touching */
    volatile uint8_t scratch[32];
    for (volatile int i = 0; i < 32; i++) scratch[i] = (uint8_t)(work >> i);
    for (volatile int i = 31; i >= 0; i--) work ^= scratch[i];
    raw[2] = read_cycles();
    raw[5] = (uint64_t)rv32_clint_mtime() | ((uint64_t)work << 32);

    /* Delay 3 — length depends on raw[1] to prevent compile-time folding */
    for (volatile uint32_t i = 0; i < (raw[1] & 0xFFF) + 200; i++) work += i;
    raw[3] = read_cycles();

    /* Capture cycle deltas — pure timing jitter */
    raw[6] = (raw[1] - raw[0]) ^ ((raw[2] - raw[1]) << 17);
    raw[7] = (raw[3] - raw[2]) ^ ((raw[3] - raw[0]) << 13) ^ (uint64_t)work;

    /* Pre-mix with splitmix64 before whitening */
    for (int i = 0; i < 8; i++)
        raw[i] = mix64(raw[i] ^ raw[(i + 5) % 8]);

    /* Pack 8×uint64 into 64-byte entropy buffer (little-endian) */
    uint8_t entropy[64];
    for (int i = 0; i < 8; i++) {
        uint64_t v = raw[i];
        for (int b = 0; b < 8; b++) {
            entropy[i * 8 + b] = (uint8_t)(v & 0xFF);
            v >>= 8;
        }
    }
#endif

#ifdef EDHOC_SHA256_CSPRNG
    /* Whiten with SHA-256: 64 bytes of entropy -> 32-byte key */
    sha256_hash(entropy, sizeof(entropy), g_key);
    g_counter = 0;

#elif defined(EDHOC_KECCAK_CSPRNG)
    /* Whiten with SHAKE256 (Keccak already linked for ML-KEM and the EDHOC
     * hash): 64 bytes of entropy -> 32-byte key */
    struct keccak_ctx kc;
    shake256_init(&kc);
    keccak_absorb(&kc, entropy, sizeof(entropy));
    shake256_final(&kc, g_key, sizeof(g_key));
    g_counter = 0;
    edhoc_wipe(&kc, sizeof(kc));

#endif

    edhoc_wipe(entropy, sizeof(entropy));
#ifdef EDHOC_INSECURE_DEMO_RNG
    edhoc_wipe(raw, sizeof(raw));
#endif
    g_ready = 1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/*
 * csprng_add_entropy — fold external data into the CSPRNG key.
 *
 * Call ONCE after deriving long-term keys from a board-specific seed.
 * Ensures different boards produce different ephemeral keys even when
 * rdcycle/mtime entropy values happen to collide.
 *
 *   new_key = HMAC-SHA-256(current_key, data)   (SHA-256 backend)
 *   new_key = SHAKE256(current_key || data)     (Keccak backend)
 */
void csprng_add_entropy(const uint8_t *data, uint32_t len)
{
    if (!data || len == 0) return;
    if (!g_ready) csprng_seed();
	if (!g_ready) return;

#ifdef EDHOC_SHA256_CSPRNG
    /* new_key = HMAC-SHA-256(current_key, data) */
    {
        struct hmac_ctx m;
        hmac_init(&m, &hash_sha256, g_key, 32);
        hmac_update(&m, data, len);
        hmac_final(&m, g_key);       /* hmac_final wipes m */
    }
    g_counter = 0;

#elif defined(EDHOC_KECCAK_CSPRNG)
    /* new_key = SHAKE256(current_key || data) */
    struct keccak_ctx kc;
    shake256_init(&kc);
    keccak_absorb(&kc, g_key, 32);
    keccak_absorb(&kc, data, len);
    shake256_final(&kc, g_key, 32);
    g_counter = 0;
    edhoc_wipe(&kc, sizeof(kc));

#endif
}

/*
 * default_CSPRNG — fill dest with `size` pseudo-random bytes.
 * Returns 1 on success, 0 on bad arguments.
 */
int default_CSPRNG(uint8_t *dest, unsigned int size)
{
    if (!dest || size == 0) return 0;
    if (!g_ready) csprng_seed();
	if (!g_ready) return 0;

#ifdef EDHOC_SHA256_CSPRNG
    unsigned int done = 0;
    while (done < size) {
        /* HMAC-SHA-256(key, counter_LE32) -> 32-byte block */
        uint8_t ctr_buf[4] = {
            (uint8_t)(g_counter),
            (uint8_t)(g_counter >> 8),
            (uint8_t)(g_counter >> 16),
            (uint8_t)(g_counter >> 24)
        };
        struct hmac_ctx m;
        uint8_t block[32];
        hmac_init(&m, &hash_sha256, g_key, 32);
        hmac_update(&m, ctr_buf, 4);
        hmac_final(&m, block);
        g_counter++;

        unsigned int chunk = size - done;
        if (chunk > 32) chunk = 32;
        memcpy(dest + done, block, chunk);
        done += chunk;

        edhoc_wipe(block, sizeof(block));
    }

#elif defined(EDHOC_KECCAK_CSPRNG)
    unsigned int done = 0;
    while (done < size) {
        /* KMAC256(key, counter_LE32) -> 32-byte block, as the HMAC branches */
        uint8_t ctr_buf[4] = {
            (uint8_t)(g_counter),
            (uint8_t)(g_counter >> 8),
            (uint8_t)(g_counter >> 16),
            (uint8_t)(g_counter >> 24)
        };
        struct keccak_ctx kc;
        uint8_t block[32];
        kmac256_init(&kc, g_key, 32);
        keccak_absorb(&kc, ctr_buf, 4);
        kmac256_final(&kc, block, sizeof(block));
        g_counter++;

        unsigned int chunk = size - done;
        if (chunk > sizeof(block)) chunk = sizeof(block);
        memcpy(dest + done, block, chunk);
        done += chunk;

        edhoc_wipe(&kc, sizeof(kc));
        edhoc_wipe(block, sizeof(block));
    }

#endif

    return 1;
}

/* wolfCrypt's RNG hook (CUSTOM_RAND_GENERATE_BLOCK in edhoc-wolfssl's
 * user_settings.h): 0 on success, as wolfCrypt expects. */
int csprng_generate_block(unsigned char *output, unsigned int sz)
{
    return default_CSPRNG((uint8_t *)output, sz) == 1 ? 0 : -1;
}
