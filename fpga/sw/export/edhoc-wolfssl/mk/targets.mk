# mk/targets.mk — EDHOC Method 0-3 app targets (initiator + responder).
#
# Each of the eight edhoc_m{0,1,2,3}_{initiator,responder} targets:
#   1. rebuilds the uoscore-uedhoc static library with the current suite/flags,
#   2. links the matching app source against it.
#
# Method / auth mapping (which role signs with Ed25519):
#   M0 (SK-SK):     both roles sign+verify  -> AUTH_SK + PEER_SK
#   M1 (SK-SDHK):   initiator signs         -> init AUTH_SK / resp PEER_SK
#   M2 (SDHK-SK):   responder signs         -> init PEER_SK / resp AUTH_SK
#   M3 (SDHK-SDHK): neither signs           -> no Ed25519 (nosign source set)

M3_EDHOC_LIB = uoscore-uedhoc

# App-common sources (shared by all eight targets); platform, radio, app
# data, CSPRNG and SD sources live in ../common, shared with edhoc-authkem.
M3_COMMON_SRC  = $(COMMON)/src/kprintf.c $(COMMON)/src/libc_stubs.c
M3_COMMON_SRC += $(COMMON)/src/csprng_stub.c $(COMMON)/src/edhoc_transport.c
M3_COMMON_SRC += src/edhoc_cred_builder.c
M3_COMMON_SRC += $(TRANSPORT_SRC)
M3_COMMON_SRC += $(COMMON)/src/edhoc_app_data.c $(COMMON)/src/stack_probe.c $(COMMON)/src/perf.c
# PROFILE=production: board-specific entropy and long-term key access.
M3_COMMON_SRC += $(PROVISION_SRC)
# SD-card file transfer, EXTRA_CFLAGS=-DAPP_SD_XFER (see edhoc_file_xfer.h).
M3_COMMON_SRC += $(addprefix $(COMMON)/src/,sd_card.c fat32.c edhoc_file_xfer.c)

# Crypto source sets: M3 drops Ed25519 signing (SDHK-SDHK, no signatures).
M3_CRYPTO_SRC        = $(sort $(WOLFCRYPT_SRCS) $(WOLFCRYPT_SIGN_SRCS))
M3_CRYPTO_SRC_NOSIGN = $(sort $(WOLFCRYPT_SRCS))

M3_INCLUDES  = -I. -Iinclude -I$(COMMON)/include -I$(COMMON)/crypto -I$(M3_EDHOC_LIB)/inc
M3_INCLUDES += -I$(M3_EDHOC_LIB)/inc/common
M3_INCLUDES += -I$(COMMON)/edhoc/inc -I$(COMMON)/cbor
M3_INCLUDES += -I$(WOLFSSL_ROOT)

# ── M-family target skeleton ─────────────────────────────────────────────
# Params: (1)=method (2)=role (3)=SK auth flags (4)=crypto source set.
# (3) empty for M3 -> no app-level CFLAGS override.
define EDHOC_M_RULE
edhoc_m$(1)_$(2):
	@echo "Building EDHOC Method $(1) $(2) (Suite $$(CRYPTO_SUITE), wolfCrypt)..."
	-@$$(MAKE) -C $$(M3_EDHOC_LIB) clean
	@$$(MAKE) -C $$(M3_EDHOC_LIB) CC="$$(CC)" AR="$$(AR)" CFLAGS="$$(CFLAGS) $(3)" CRYPTO_SUITE=$$(CRYPTO_SUITE) DEBUG=$$(DEBUG)
	@$$(MAKE) all TARGET=edhoc_m$(1)_$(2) EDHOC_LIB_DIR=$$(M3_EDHOC_LIB) \
		C_SOURCES="src/edhoc_$(2).c src/edhoc_app.c src/edhoc_board.c $$(M3_COMMON_SRC) $(4)" \
		ASM_SOURCES="$(COMMON)/src/crt0.S" \
		INCLUDES="$$(M3_INCLUDES)" "CFLAGS=$$(CFLAGS) $(3) -DEDHOC_METHOD=$(1)"
endef

$(eval $(call EDHOC_M_RULE,0,initiator,-DEDHOC_AUTH_SK -DEDHOC_PEER_SK,$(M3_CRYPTO_SRC)))
$(eval $(call EDHOC_M_RULE,0,responder,-DEDHOC_AUTH_SK -DEDHOC_PEER_SK,$(M3_CRYPTO_SRC)))
$(eval $(call EDHOC_M_RULE,1,initiator,-DEDHOC_AUTH_SK,$(M3_CRYPTO_SRC)))
$(eval $(call EDHOC_M_RULE,1,responder,-DEDHOC_PEER_SK,$(M3_CRYPTO_SRC)))
$(eval $(call EDHOC_M_RULE,2,initiator,-DEDHOC_PEER_SK,$(M3_CRYPTO_SRC)))
$(eval $(call EDHOC_M_RULE,2,responder,-DEDHOC_AUTH_SK,$(M3_CRYPTO_SRC)))
$(eval $(call EDHOC_M_RULE,3,initiator,,$(M3_CRYPTO_SRC_NOSIGN)))
$(eval $(call EDHOC_M_RULE,3,responder,,$(M3_CRYPTO_SRC_NOSIGN)))

# sp_c64.c and ecc.c must NOT be compiled with -flto: LTO whole-program
# analysis eliminates sp_ecc_sign_256/sp_ecc_make_key_256 because the indirect
# call chains from wc_ecc_sign_hash_ex are constant-propagated away. Compiling
# these two without LTO gives them real ELF symbols the linker keeps.
$(BUILD_DIR)/sp_c64.o $(BUILD_DIR)/ecc.o: $(BUILD_DIR)/%.o: $(WOLFCRYPT_DIR)/%.c $(CFLAGS_STAMP)
	@echo "[CC-nolto] $<"
	@$(CC) -c $(filter-out -flto,$(CFLAGS)) $(INCLUDES) $(EXTRA_INCLUDES) $< -o $@
