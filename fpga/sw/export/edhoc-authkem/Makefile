# EDHOC RV64 firmware — five-message Method 5 AuthKEM (ML-KEM-512 or -1024).
# See README.md for usage.  Load order:
#   config  -> flags, suite, ML-KEM and crypto sources, includes
#   rules   -> core compile/link rules (default goal 'all'), ../common/mk
#   targets -> app recipes (edhoc_authkem_initiator/responder)
include mk/config.mk
include $(COMMON)/mk/rules.mk
include mk/targets.mk

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete!"

.PHONY: all clean edhoc_authkem_initiator edhoc_authkem_responder unit-test loopback-test

# Library unit tests on the host (suite gate, KEM, codecs), built per SUITE
# from the same sources and defines as the firmware.
unit-test: $(GEN_CREDS)
	@cc -std=c11 -O1 -g -Wall -Wno-unused-function $(LOOPBACK_DEFS) $(AK_INCLUDES) -Isrc \
	  tests/test_units.c $(AK_LIB_SRC) $(AK_MLKEM_SRC) -o $(BUILD_DIR)/test_units
	@$(BUILD_DIR)/test_units

# Full five-message handshake, Initiator and Responder threads on the host,
# built from the same library sources and defines as the firmware.
#   make loopback-test [LOOPBACK_LOG=<file>]   (log feeds tools/authkem_ref.py)
LOOPBACK_DEFS = $(filter -D%,$(AK_CFLAGS))
loopback-test: $(GEN_CREDS)
	@cc -std=c11 -O1 -g -Wall -Wno-unused-function $(LOOPBACK_DEFS) $(AK_INCLUDES) -Isrc \
	  tests/test_loopback.c $(AK_LIB_SRC) \
	  $(AK_MLKEM_SRC) -lpthread -o $(BUILD_DIR)/test_loopback
	@$(BUILD_DIR)/test_loopback $(LOOPBACK_LOG)
