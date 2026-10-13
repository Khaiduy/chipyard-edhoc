# mk/config.mk — toolchain and flags for five-message EDHOC AuthKEM
# (draft-ietf-lake-authkem-edhoc-01, cipher suite pqsuites-01 TBD1, TBD2 or TBD3).
# Crypto: FIPS 203 ML-KEM-512 (mlkem-native), A256GCM, SHAKE256/KMAC256 (TBD2)
#      or FIPS 203 ML-KEM-1024, A256GCM, SHA-384/HKDF (TBD3).

TARGET    = main
# Sources shared with edhoc-wolfssl (EDHOC core, CBOR, crypto, platform);
# toolchain, RV64 target, TRANSPORT=rf|uart and link flags in rv64.mk.
COMMON    = $(CURDIR)/../common
include $(COMMON)/mk/rv64.mk
# ── Cipher suite ─────────────────────────────────────────────────────────
# draft-ietf-lake-pqsuites-01, Table 3:
# SUITE=TBD1:           AES-CCM-16-128-128, SHAKE256, MAC 16, ML-KEM-512
#                       (application AEAD AES-CCM-16-64-128).
# SUITE=TBD2 (default): A256GCM, SHAKE256, MAC 16, ML-KEM-512.
# SUITE=TBD3:           A256GCM, SHA-384,  MAC 16, ML-KEM-1024.
# One suite per image, and only that suite's AEAD and hash are compiled
# (SUITE_SRC). TBD1/TBD3 builds go to build-tbd1/ and build-tbd3/ so suites
# never share objects.
SUITE ?= TBD2
ifeq ($(SUITE),TBD1)
SUITE_CFLAGS = -DAUTHKEM_PQ_SUITE=1 -DMLK_CONFIG_PARAMETER_SET=512
SUITE_SRC = aes.c aes_ccm.c
BUILD_DIR = build-tbd1
else ifeq ($(SUITE),TBD2)
SUITE_CFLAGS = -DAUTHKEM_PQ_SUITE=2 -DMLK_CONFIG_PARAMETER_SET=512
SUITE_SRC = aes.c aes_gcm.c
BUILD_DIR = build
else ifeq ($(SUITE),TBD3)
SUITE_CFLAGS = -DAUTHKEM_PQ_SUITE=3 -DMLK_CONFIG_PARAMETER_SET=1024
SUITE_SRC = aes.c aes_gcm.c sha384.c hmac_hkdf.c
BUILD_DIR = build-tbd3
else
$(error Invalid SUITE=$(SUITE). Use TBD1, TBD2 or TBD3)
endif

DEBUG  ?= 0
TIMING ?= 0

# ── Build profile ────────────────────────────────────────────────────────
# PROFILE=demo (default)
#   Deterministic-seeded CSPRNG and the ML-KEM-512 test-vector key pairs in
#   src/mlkem512_test_keys.h. Fine for the two-board demo, unusable in the
#   field: the private keys are in the firmware image and every device that
#   runs it shares them.
#
# PROFILE=production
#   Refuses to build unless the caller supplies real entropy and real keys:
#     * src/mlkem512_test_keys.h fails to compile (#error inside it),
#     * no weak edhoc_platform_entropy() default exists, so a missing TRNG
#       is a link error rather than a runtime fail-closed,
#     * PROVISION_DIR must name a directory providing authkem_creds.h with
#       device credentials, and the sources implementing the interfaces in
#       include/authkem_provision.h.
#
# Failing the build is deliberate. A profile that quietly falls back to demo
# keys or a weak RNG is the failure mode this is meant to prevent.
PROFILE ?= demo

ifeq ($(PROFILE),demo)
DEMO_RNG ?= 1
else ifeq ($(PROFILE),production)
DEMO_RNG := 0
ifndef PROVISION_DIR
$(error PROFILE=production requires PROVISION_DIR=<dir> providing authkem_creds.h and PROVISION_SRC=<files> implementing include/authkem_provision.h)
endif
ifndef PROVISION_SRC
$(error PROFILE=production requires PROVISION_SRC=<files> implementing edhoc_platform_entropy() -- see include/authkem_provision.h)
endif
AK_CFLAGS_PROFILE = -DEDHOC_PROFILE_PRODUCTION
AK_COMMON_SRC_PROFILE = $(PROVISION_SRC)
AK_INCLUDES_PROFILE = -I$(PROVISION_DIR)
else
$(error Invalid PROFILE=$(PROFILE). Use demo or production)
endif

# ── EDHOC Method 5 AuthKEM library ───────────────────────────────────────
AK_EDHOC_LIB := AUTHKEM
# Symmetric crypto comes from ../common/crypto (SUITE_SRC, keccak_kmac.c);
# Keccak-f[1600] comes from mlkem-native.

# FIPS 203 ML-KEM: mlkem-native (commit 9cd4c6df), portable C, as a single
# compilation unit.
AK_MLKEM_SRC = $(COMMON)/externals/mlkem-native/mlkem/mlkem_native.c

# App-common sources (shared by initiator + responder)
AK_COMMON_SRC  = $(addprefix $(COMMON)/src/,kprintf.c libc_stubs.c csprng_stub.c)
AK_COMMON_SRC += $(addprefix $(COMMON)/src/,edhoc_transport.c edhoc_app_data.c stack_probe.c perf.c)
AK_COMMON_SRC += $(TRANSPORT_SRC)
# SD-card file transfer, EXTRA_CFLAGS=-DAPP_SD_XFER (see edhoc_file_xfer.h).
AK_COMMON_SRC += $(addprefix $(COMMON)/src/,sd_card.c fat32.c edhoc_file_xfer.c)
# Production provisioning sources (entropy + device key access), if any.
AK_COMMON_SRC += $(AK_COMMON_SRC_PROFILE)

# Generated headers (CCS credentials; see tools/gen_ccs.c).
GEN_DIR = $(BUILD_DIR)/gen

# In production, PROVISION_DIR supplies authkem_creds.h instead of GEN_DIR.
AK_INCLUDES  = -I. -Iinclude -I$(COMMON)/include $(AK_INCLUDES_PROFILE) -I$(GEN_DIR)
AK_INCLUDES += -I$(AK_EDHOC_LIB)/inc -I$(AK_EDHOC_LIB)/inc/edhoc -I$(AK_EDHOC_LIB)/inc/common
AK_INCLUDES += -I$(COMMON)/edhoc/inc -I$(COMMON)/cbor
AK_INCLUDES += -I$(COMMON)/crypto -I$(COMMON)/externals/mlkem-native/mlkem

# ID_CRED_{I,R}_SIZE default to 400 in buffer_sizes.h. This build identifies
# credentials by kid -- id_cred_r_buf is 4 bytes -- so 64 is generous. The
# constants also drive AUTHKEM_PLAINTEXT2/3/4_SIZE, so shrinking them takes
# several hundred bytes out of the handshake stack frame that sits under the
# ML-KEM decapsulation. The other limits accept what RFC 9528 lets a peer
# send: 64 B of EAD (padding, non-critical items), connection identifiers up
# to 7 B (the OSCORE Recipient ID limit with a 13-byte nonce), and a SUITES_I
# of up to 8 suites so a peer preferring another suite gets ERR_CODE 2.
AK_CFLAGS  = $(ARCH_FLAGS) -Os -flto -g0 -ffunction-sections -fdata-sections \
             -fno-unwind-tables -fno-asynchronous-unwind-tables \
             -nostartfiles -nostdlib -nodefaultlibs -fno-builtin \
             -fno-tree-loop-distribute-patterns -Wall -Wextra \
             -DMESSAGE_4 -DHEAP_ARENA_SIZE=512 \
             -DEDHOC_KECCAK_CSPRNG \
             $(SUITE_CFLAGS) -DMLK_CONFIG_NO_RANDOMIZED_API -DMLK_CONFIG_LOW_RAM \
             -DMLK_CONFIG_SERIAL_FIPS202_ONLY \
             -DEAD_SIZE=64 -DC_I_SIZE=7 -DC_R_SIZE=7 -DSUITES_I_SIZE=8 \
             -DID_CRED_I_SIZE=64 -DID_CRED_R_SIZE=64
AK_CFLAGS += $(AK_CFLAGS_PROFILE)
ifeq ($(DEMO_RNG),1)
AK_CFLAGS += -DEDHOC_INSECURE_DEMO_RNG
endif
ifeq ($(DEBUG),1)
AK_CFLAGS += -DDEBUG_PRINT
endif
ifeq ($(TIMING),1)
AK_CFLAGS += -DTIMING_BREAKDOWN
endif

# APP_FILE_BYTES=<n> appends a bulk transfer to the post-handshake demo: the
# initiator streams n bytes through the AEAD channel in APP_PT_MAX chunks and
# the responder verifies them, both reporting cycles. Memory use is constant,
# so n is bounded by link rate rather than RAM.
ifdef APP_FILE_BYTES
AK_CFLAGS += -DAPP_FILE_BYTES=$(APP_FILE_BYTES)
endif

# ── Defaults consumed by mk/rules.mk (overridden per target) ─────────────
# EXTRA_CFLAGS lets the caller add defines without clobbering the flags
# above; mk/targets.mk passes AK_CFLAGS to the sub-makes explicitly, so it
# must be appended there rather than to CFLAGS.
AK_CFLAGS += $(TRANSPORT_CFLAGS)
AK_CFLAGS += $(EXTRA_CFLAGS)

CFLAGS   = $(AK_CFLAGS)
INCLUDES = $(AK_INCLUDES)

# Stack reservation: the deepest static call path (disassembly walk of the
# linked image) plus 25%, rounded up to 256 B, and checked against the
# on-board high-water mark (crt0 paints free RAM; stack_highwater() in
# include/stack_probe.h reports the deepest point reached).
#
# Static peaks with -DMLK_CONFIG_LOW_RAM (2026-10-05):
#
#   suite  role       stack peak   image (text+data+bss)   reservation
#   TBD2   initiator  17,473 B     33,258 B                22,016 B
#   TBD2   responder  14,816 B     32,380 B                18,688 B
#   TBD3   initiator  18,848 B     37,820 B                23,808 B
#   TBD3   responder  16,048 B     37,874 B                20,480 B
#
# Per role, so the responder keeps room for SD transfer + TIMING=1 (on board
# with both: responder 16,352 B, the base of its 20,480 B).
#
# The initiator's deepest path is a decapsulation (main + KEM decaps +
# re-encryption in indcpa_enc). MLK_CONFIG_LOW_RAM is a local option in the
# vendored mlkem-native (src/indcpa.c): it samples the ML-KEM matrix one row
# at a time instead of holding all K*K entries, encrypts and generates keys
# row by row for ML-KEM-1024, and keeps indcpa_dec out of line so its buffers
# are released before re-encryption. Outputs are bit-identical (tests/ checks
# FIPS 203 known answers); for ML-KEM-1024 it cuts the decapsulation path
# from 34.1 kB to 18.8 kB, which is what lets TBD3 fit 64 kB.
#
# Earlier on-board marks (TBD2, before LOW_RAM): initiator 18,400 / 18,560 B,
# responder 15,984 / 16,256 B, within 100 B of the static walk.
ifeq ($(SUITE),TBD3)
STACK_INITIATOR ?= 23808
STACK_RESPONDER ?= 20480
else
STACK_INITIATOR ?= 22016
STACK_RESPONDER ?= 18688
endif

EDHOC_LIB_DIR = $(AK_EDHOC_LIB)
# Library sources compiled directly into the image: the AuthKEM protocol,
# the EDHOC core and CBOR shared with edhoc-wolfssl, and the suite's crypto.
AK_LIB_SRC  = $(wildcard $(AK_EDHOC_LIB)/src/edhoc/*.c)
AK_LIB_SRC += $(wildcard $(COMMON)/edhoc/src/*.c) $(COMMON)/cbor/cbor.c
AK_LIB_SRC += $(AK_EDHOC_LIB)/src/common/crypto_wrapper.c
AK_LIB_SRC += $(addprefix $(COMMON)/crypto/,$(SUITE_SRC) keccak_kmac.c secure_wipe.c)

LIBS = -lgcc

# C_SOURCES and ASM_SOURCES are set per target in mk/targets.mk.

OBJECTS  = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
OBJECTS += $(addprefix $(BUILD_DIR)/,$(notdir $(ASM_SOURCES:.S=.o)))

vpath %.c $(sort $(dir $(C_SOURCES)))
vpath %.S $(sort $(dir $(ASM_SOURCES)))
