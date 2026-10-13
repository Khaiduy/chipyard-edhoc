# mk/config.mk — toolchain, flags, suite dispatch, wolfCrypt sources, includes.
# Included first by ../Makefile.  Methods 0-3, all suites, wolfCrypt backend only.

TARGET    = main
BUILD_DIR = build

# Platform, radio, app-data, CSPRNG and SD sources shared with edhoc-authkem;
# toolchain, RV64 target, TRANSPORT=rf|uart and link flags in rv64.mk.
COMMON = $(CURDIR)/../common
include $(COMMON)/mk/rv64.mk

# DEBUG=1 enables debug prints; DEBUG=0 (default) gives clean timing.
DEBUG  ?= 0
TIMING ?= 0

CFLAGS  = $(ARCH_FLAGS) -Os -flto -g0 -ffunction-sections -fdata-sections -Wunused-function
CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
CFLAGS += -nostartfiles -nostdlib -nodefaultlibs -fno-builtin -fno-tree-loop-distribute-patterns
CFLAGS += -Wall -Wextra -DMESSAGE_4

# ── Build profile ────────────────────────────────────────────────────────
# PROFILE=demo (default)
#   Cycle-counter-seeded CSPRNG, and long-term signing keys derived from the
#   fixed seeds in include/edhoc_demo_keys.h. Those seeds are identical in
#   every build, so an image containing them has no authentication value.
#
# PROFILE=production
#   Refuses to build unless real entropy and real keys are supplied:
#     * DEMO_RNG=1 is rejected outright rather than silently ignored,
#     * include/edhoc_demo_keys.h fails to compile (#error inside it),
#     * no weak edhoc_platform_entropy() default exists, so a missing TRNG is
#       a link error rather than a runtime fail-closed,
#     * PROVISION_SRC must name sources implementing the interfaces in
#       include/edhoc_provision.h.
#
# Failing the build is deliberate: a profile that quietly falls back to demo
# keys or a weak RNG is the failure mode this exists to prevent.
PROFILE ?= demo

ifeq ($(PROFILE),demo)
DEMO_RNG ?= 1
else ifeq ($(PROFILE),production)
ifeq ($(DEMO_RNG),1)
$(error PROFILE=production is incompatible with DEMO_RNG=1. The demo CSPRNG is seeded from cycle-counter jitter and is not a usable entropy source)
endif
DEMO_RNG := 0
ifndef PROVISION_SRC
$(error PROFILE=production requires PROVISION_SRC=<files> implementing include/edhoc_provision.h (entropy + long-term signing keys))
endif
ifeq ($(DEBUG),1)
$(error PROFILE=production is incompatible with DEBUG=1: debug builds print every key, PRK_out included)
endif
CFLAGS += -DEDHOC_PROFILE_PRODUCTION
else
$(error Invalid PROFILE=$(PROFILE). Use demo or production)
endif

ifeq ($(DEMO_RNG),1)
CFLAGS += -DEDHOC_INSECURE_DEMO_RNG
endif
ifeq ($(TIMING),1)
CFLAGS += -DTIMING_BREAKDOWN
endif
ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG_PRINT
endif

# APP_FILE_BYTES=<n> appends a bulk transfer to the post-handshake demo: the
# initiator streams n bytes through the AEAD channel in APP_PT_MAX chunks and
# the responder verifies them, both reporting cycles. Memory use is constant,
# so n is limited by link rate, not RAM (1 MB over a 57600-baud UART is ~3 min).
ifdef APP_FILE_BYTES
CFLAGS += -DAPP_FILE_BYTES=$(APP_FILE_BYTES)
endif

# ── Crypto suite selection ───────────────────────────────────────────────
#   0  AES-CCM-16-64-128  + SHA-256  + X25519 + EdDSA
#   1  AES-CCM-16-128-128 + SHA-256  + X25519 + EdDSA
#   2  AES-CCM-16-64-128  + SHA-256  + P-256  + ES256   (default)
#   3  AES-CCM-16-128-128 + SHA-256  + P-256  + ES256
#   4  ChaCha20/Poly1305  + SHA-256  + X25519 + EdDSA
#   5  ChaCha20/Poly1305  + SHA-256  + P-256  + ES256
#   6  AES-128-GCM        + SHA-256  + X25519 + EdDSA
#  24  AES-256-GCM        + SHA-384  + P-384  + ES384
#  25  ChaCha20/Poly1305  + SHAKE256 + X448   + Ed448
CRYPTO_SUITE ?= 2

# ── wolfCrypt library root ───────────────────────────────────────────────
WOLFSSL_ROOT     = $(CURDIR)/wolfssl
WOLFCRYPT_DIR    = $(WOLFSSL_ROOT)/wolfcrypt/src
# -fwrapv: sp_c64.c relies on signed overflow wrapping (C leaves it undefined;
# UBSan flags it in the P-256/P-384 code). Signed << is defined by GCC.
WOLFCRYPT_CFLAGS = -fwrapv -DWOLFSSL_USER_SETTINGS -I$(WOLFSSL_ROOT) -include $(WOLFSSL_ROOT)/user_settings.h
WOLFCRYPT_CFLAGS += -I$(CURDIR)/../common/externals/monocypher -I$(CURDIR)/../common/crypto

# ── wolfCrypt component source sets ──────────────────────────────────────
# 64-bit single-precision math (SP_WORD_SIZE 64 in user_settings.h).
_WC_SPMATH = $(WOLFCRYPT_DIR)/sp_c64.c

# Symmetric crypto shared with edhoc-authkem (common/crypto): SHA-256/384,
# HMAC/HKDF and AES-CCM/GCM. ChaCha20-Poly1305 is Monocypher's.
SYM_DIR  = $(CURDIR)/../common/crypto
_SYM     = $(SYM_DIR)/sha256.c $(SYM_DIR)/hmac_hkdf.c $(SYM_DIR)/secure_wipe.c
_SHA384  = $(SYM_DIR)/sha384.c
_AES_CCM = $(SYM_DIR)/aes.c $(SYM_DIR)/aes_ccm.c
_AES_GCM = $(SYM_DIR)/aes.c $(SYM_DIR)/aes_gcm.c
_CHACHA  = $(CURDIR)/../common/externals/monocypher/monocypher.c

_WC_CORE = \
    $(WOLFCRYPT_DIR)/wc_port.c $(WOLFCRYPT_DIR)/wolfmath.c \
    $(WOLFCRYPT_DIR)/random.c  $(WOLFCRYPT_DIR)/error.c $(_SYM)
_WC_SP   = $(WOLFCRYPT_DIR)/sp_int.c $(_WC_SPMATH)

_WC_SHA3   = $(WOLFCRYPT_DIR)/sha3.c $(WOLFCRYPT_DIR)/hash.c
_WC_KMAC   = $(WOLFCRYPT_DIR)/kmac.c

# Curve25519 is not wolfCrypt's: X25519 is curve25519-donna-c64 (radix 2^51,
# 8.9 M cycles per X25519 on this core vs 328 M for wolfCrypt's
# CURVE25519_SMALL), Ed25519 is Monocypher's RFC 8032 code (sign 6.3 M,
# verify 21 M cycles). Both measured on the board against RFC 7748 / 8032.
COMMON_EXT  = $(CURDIR)/../common/externals
_WC_X25519  = $(COMMON_EXT)/curve25519-donna/curve25519-donna-c64.c
_WC_ECC    = $(WOLFCRYPT_DIR)/ecc.c $(_WC_SP)
_WC_X448   = $(WOLFCRYPT_DIR)/curve448.c $(WOLFCRYPT_DIR)/fe_448.c

# Edwards signing (Methods 0-2)
_WC_ED25519 = $(COMMON_EXT)/monocypher/monocypher.c $(COMMON_EXT)/monocypher/monocypher-ed25519.c
_WC_ED448   = $(WOLFCRYPT_DIR)/ed448.c   $(WOLFCRYPT_DIR)/ge_448.c

# ── Cipher-suite table (wolfCrypt) ───────────────────────────────────────
#   _WC   AEAD + hash + ECDH (no signing)
#   _SIGN Edwards signing (Methods 0-2)
#   _NAME description printed at build start
SUITE_0_WC    = $(_WC_CORE) $(_AES_CCM) $(_WC_X25519)
SUITE_0_SIGN = $(_WC_ED25519)
SUITE_0_NAME = AES-CCM-16-64-128 + SHA-256 + X25519 + EdDSA

SUITE_1_WC    = $(_WC_CORE) $(_AES_CCM) $(_WC_X25519)
SUITE_1_SIGN = $(_WC_ED25519)
SUITE_1_NAME = AES-CCM-16-128-128 + SHA-256 + X25519 + EdDSA

SUITE_2_WC    = $(_WC_CORE) $(_AES_CCM) $(_WC_ECC)
SUITE_2_NAME = AES-CCM-16-64-128 + P-256 + ES256

SUITE_3_WC    = $(_WC_CORE) $(_AES_CCM) $(_WC_ECC)
SUITE_3_NAME = AES-CCM-16-128-128 + P-256 + ES256

SUITE_4_WC    = $(_WC_CORE) $(_CHACHA) $(_WC_X25519)
SUITE_4_SIGN = $(_WC_ED25519)
SUITE_4_NAME = ChaCha20/Poly1305 + X25519 + EdDSA

SUITE_5_WC    = $(_WC_CORE) $(_CHACHA) $(_WC_ECC)
SUITE_5_NAME = ChaCha20/Poly1305 + P-256 + ES256

SUITE_6_WC    = $(_WC_CORE) $(_AES_GCM) $(_WC_X25519) $(_WC_ECC)
SUITE_6_NAME = AES-128-GCM + X25519 + ES256

SUITE_24_WC   = $(_WC_CORE) $(_SHA384) $(_AES_GCM) $(_WC_ECC)
SUITE_24_NAME = AES-256-GCM + P-384 + ES384

SUITE_25_WC   = $(_WC_CORE) $(_WC_SHA3) $(_WC_KMAC) $(_CHACHA) $(_WC_X448)
SUITE_25_SIGN = $(_WC_ED448)
SUITE_25_NAME = ChaCha20/Poly1305 + SHAKE256 + X448 + Ed448

# ── Suite resolver ───────────────────────────────────────────────────────
ifndef SUITE_$(CRYPTO_SUITE)_WC
$(error Invalid CRYPTO_SUITE=$(CRYPTO_SUITE). Use 0 1 2 3 4 5 6 24 25)
endif

WOLFCRYPT_SRCS      = $(SUITE_$(CRYPTO_SUITE)_WC)
WOLFCRYPT_SIGN_SRCS = $(SUITE_$(CRYPTO_SUITE)_SIGN)

CFLAGS += -DEDHOC_CRYPTO_SUITE=$(CRYPTO_SUITE) $(WOLFCRYPT_CFLAGS)
CFLAGS += -DEDHOC_SHA256_CSPRNG

# EXTRA_CFLAGS lets the caller add defines without clobbering the flags above
# (a plain CFLAGS= on the command line would drop -DWOLFCRYPT and the includes).
#   make EXTRA_CFLAGS=-DHEAP_ARENA_SIZE=8192
#   make EXTRA_CFLAGS=-DAPP_SD_XFER
CFLAGS += $(TRANSPORT_CFLAGS)
CFLAGS += $(EXTRA_CFLAGS)
$(info Building Suite $(CRYPTO_SUITE): $(SUITE_$(CRYPTO_SUITE)_NAME) [wolfCrypt])


# ── Stack reservation, per suite ─────────────────────────────────────────
# Derived from measured high-water marks, not static analysis.
#
# crt0 paints all free RAM with a canary and stack_highwater() reports the
# deepest point reached (see include/stack_probe.h). Every method x suite
# combination was run on the 75 MHz RV64 boards, both roles; the figures below
# are the worst case over all four methods and both roles for each suite.
#
# The previous values came from a static walk of the deepest direct call
# chain. That walk under-reports -- it misses multi-instruction prologues,
# VLAs, and frames LTO merges across translation units -- and the measurements
# show by how much: 20 of the 36 combinations exceeded their reservation. They
# never faulted because the stack grew past the reservation into the
# unallocated gap below it, which is the same failure mode AuthKEM had, and it
# stops being harmless as soon as .text or .bss grow enough to close that gap.
#
#   suite       measured peak   +25%     reserved   (2026-10-06)
#   0, 1, 4        4,152 B      5,190 B   5,376 B
#   2, 3, 5, 6     6,688 B      8,360 B   8,448 B
#   24             8,704 B     10,880 B  11,008 B
#   25             9,944 B     12,430 B  12,544 B
#
# Suite 25's peak is Ed448: verification keeps 16 projective points of the
# public key (3 kB) and signing a 16-point window of the base point.
#
# Depth depends on both method and suite, and method 3 (neither side signs)
# is the shallowest everywhere. Each suite therefore takes the worst case
# across all methods, since one image serves whichever method is selected.
#
# Re-derive after any crypto or call-depth change: run every combination and
# check the runtime report says no OVERRAN-RESERVE. Override with
# STACK_SIZE=<bytes>.
STACK_SIZE_0  = 5376
STACK_SIZE_1  = 5376
STACK_SIZE_2  = 8448
STACK_SIZE_3  = 8448
STACK_SIZE_4  = 5376
STACK_SIZE_5  = 8448
STACK_SIZE_6  = 8448
STACK_SIZE_24 = 11008
STACK_SIZE_25 = 12544
STACK_SIZE ?= $(or $(STACK_SIZE_$(CRYPTO_SUITE)),8192)

# ── EDHOC library (full Method 0-3 library) ──────────────────────────────
EDHOC_LIB_DIR = uoscore-uedhoc

INCLUDES  = -I. -Iinclude -I$(COMMON)/include -I$(COMMON)/crypto -I$(EDHOC_LIB_DIR)/inc
INCLUDES += -I$(EDHOC_LIB_DIR)/inc/common
INCLUDES += -I$(COMMON)/edhoc/inc -I$(COMMON)/cbor
INCLUDES += -I$(WOLFSSL_ROOT)

# C_SOURCES and ASM_SOURCES are set per target in mk/targets.mk.
LIBS = -L$(EDHOC_LIB_DIR)/build -luoscore-uedhoc -lgcc

OBJECTS  = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.S=.o)))

vpath %.c $(sort $(dir $(C_SOURCES)))
vpath %.S $(sort $(dir $(ASM_SOURCES)))
