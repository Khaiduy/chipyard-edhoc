# EDHOC RV32 firmware — Methods 0-3, all suites, wolfCrypt backend.
# See README.md for usage.  Load order matters:
#   config  -> toolchain, flags, suite table, wolfCrypt source sets
#   rules   -> core compile/link rules (default goal 'all'), ../common/mk
#   targets -> per-app recipes (edhoc_m{0,1,2,3}_{initiator,responder})
include mk/config.mk
include $(COMMON)/mk/rules.mk
include mk/targets.mk

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	-@$(MAKE) -C uoscore-uedhoc clean
	@echo "Clean complete!"

.PHONY: all clean \
        edhoc_m0_initiator edhoc_m0_responder edhoc_m1_initiator edhoc_m1_responder \
        edhoc_m2_initiator edhoc_m2_responder edhoc_m3_initiator edhoc_m3_responder

# Full handshake on the host: initiator and responder threads, same library,
# crypto and src/edhoc_app.c as the firmware, compared on PRK_out.
#   make loopback-test CRYPTO_SUITE=<s> METHOD=<m>
METHOD ?= 0
LIB = uoscore-uedhoc
LOOPBACK_SRC  = tests/test_loopback.c src/edhoc_app.c src/edhoc_cred_builder.c
LOOPBACK_SRC += $(wildcard $(LIB)/src/edhoc/*.c) $(wildcard $(LIB)/src/common/*.c)
LOOPBACK_SRC += $(wildcard $(COMMON)/edhoc/src/*.c) $(COMMON)/cbor/cbor.c
LOOPBACK_SRC += $(sort $(WOLFCRYPT_SRCS) $(WOLFCRYPT_SIGN_SRCS))
# Buffer sizes are the library defaults, as in the firmware.
LOOPBACK_DEFS = -DMESSAGE_4 \
  -DEDHOC_CRYPTO_SUITE=$(CRYPTO_SUITE) -DEDHOC_METHOD=$(METHOD) \
  -DEDHOC_AUTH_SK -DEDHOC_PEER_SK
.PHONY: loopback-test
loopback-test:
	@mkdir -p $(BUILD_DIR)
	@cc -std=gnu11 -O1 -w $(LOOPBACK_DEFS) $(LOOPBACK_EXTRA) $(WOLFCRYPT_CFLAGS) \
	  -Iinclude -I$(COMMON)/include -I$(COMMON)/crypto -I$(LIB)/inc \
	  -I$(LIB)/inc/common -I$(COMMON)/edhoc/inc -I$(COMMON)/cbor \
	  $(LOOPBACK_SRC) -lpthread -o $(BUILD_DIR)/test_loopback
	@$(BUILD_DIR)/test_loopback

# The library against the RFC 9529 traces on the host: every message each role
# sends, PRK_out and the exporter outputs must equal the RFC byte for byte.
# Trace 1 needs suite 0 with signatures, Trace 2 suite 2 with static DH;
# suite 24 runs invalid case 4.2.1, which is about P-384.
#   make rfc9529-test
RFC9529_SRC  = tests/test_rfc9529.c
RFC9529_SRC += $(wildcard $(LIB)/src/edhoc/*.c) $(wildcard $(LIB)/src/common/*.c)
RFC9529_SRC += $(wildcard $(COMMON)/edhoc/src/*.c) $(COMMON)/cbor/cbor.c
RFC9529_SRC += $(sort $(WOLFCRYPT_SRCS) $(WOLFCRYPT_SIGN_SRCS))
# Library default buffers, except credentials: x5t certificates are 243 B
# and their ID_CRED 14 B.
RFC9529_DEFS = -DMESSAGE_4 -DEDHOC_CRYPTO_SUITE=$(CRYPTO_SUITE) \
  -DID_CRED_R_SIZE=16 -DID_CRED_I_SIZE=16 -DCRED_R_SIZE=256 -DCRED_I_SIZE=256
.PHONY: rfc9529-test rfc9529-one rfc9529-images rfc9529-image
rfc9529-test:
	@$(MAKE) -s rfc9529-one CRYPTO_SUITE=0 RFC9529_AUTH="-DEDHOC_AUTH_SK -DEDHOC_PEER_SK"
	@$(MAKE) -s rfc9529-one CRYPTO_SUITE=2
	@$(MAKE) -s rfc9529-one CRYPTO_SUITE=24
# Same test on the board: build/rfc9529_s{0,2,24}.elf.
rfc9529-images:
	@$(MAKE) -s rfc9529-image CRYPTO_SUITE=0 RFC9529_AUTH="-DEDHOC_AUTH_SK -DEDHOC_PEER_SK"
	@$(MAKE) -s rfc9529-image CRYPTO_SUITE=2
	@$(MAKE) -s rfc9529-image CRYPTO_SUITE=24
rfc9529-image:
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(ARCH_FLAGS) -Os -ffunction-sections -fdata-sections -nostartfiles \
	  -nostdlib -nodefaultlibs -fno-builtin -fno-tree-loop-distribute-patterns -w \
	  $(RFC9529_DEFS) $(RFC9529_AUTH) $(WOLFCRYPT_CFLAGS) \
	  -Iinclude -Itests -I../tests/include -I$(COMMON)/include -I$(COMMON)/crypto \
	  -I$(LIB)/inc -I$(LIB)/inc/common -I$(COMMON)/edhoc/inc -I$(COMMON)/cbor \
	  $(RFC9529_SRC) $(COMMON)/src/kprintf.c $(COMMON)/src/libc_stubs.c $(COMMON)/src/crt0.S \
	  -T $(COMMON)/linker/main.lds -L$(COMMON)/linker -Wl,--gc-sections \
	  -Wl,--defsym=__stack_size=16384 -lgcc -o $(BUILD_DIR)/rfc9529_s$(CRYPTO_SUITE).elf
	@$(SIZE) $(BUILD_DIR)/rfc9529_s$(CRYPTO_SUITE).elf
rfc9529-one:
	@mkdir -p $(BUILD_DIR)
	@cc -std=gnu11 -O1 -w $(RFC9529_DEFS) $(RFC9529_AUTH) $(WOLFCRYPT_CFLAGS) \
	  -Iinclude -Itests -I$(COMMON)/include -I$(COMMON)/crypto -I$(LIB)/inc \
	  -I$(LIB)/inc/common -I$(COMMON)/edhoc/inc -I$(COMMON)/cbor \
	  $(RFC9529_SRC) -o $(BUILD_DIR)/test_rfc9529_s$(CRYPTO_SUITE)
	@$(BUILD_DIR)/test_rfc9529_s$(CRYPTO_SUITE)
