# mk/targets.mk — EDHOC Method 5 AUTHKEM app targets.
#
#   edhoc_authkem_initiator / edhoc_authkem_responder
#       The 5-message handshake of draft-ietf-lake-authkem-edhoc-01, with
#       ML-KEM-512 static keys on both sides and CCS (kid) credentials.
#
# The protocol library is compiled straight into each image rather than built
# as a static library first: EDHOC_KEM_ONLY/EDHOC_NO_CERT_CRED already trim it
# to the KEM-only subset, so there is nothing to select at link time.

# ML-KEM-512 is linked in here too: with the library compiled directly there
# is no static archive to carry it.
AK_APP_COMMON = $(AK_LIB_SRC) $(AK_COMMON_SRC) $(AK_MLKEM_SRC)

# CCS credentials are constants, so they are generated into .rodata at build
# time rather than rebuilt into .bss on every boot. gen_ccs validates the
# encoding (and that the raw key really sits at AUTHKEM_CRED_OVERHEAD) before
# emitting; the generated header additionally carries _Static_asserts.
# Only the demo profile generates credentials, because gen_ccs reads the
# test-vector keys. Production takes them from PROVISION_DIR/authkem_creds.h.
ifeq ($(PROFILE),demo)
GEN_CREDS = $(GEN_DIR)/authkem_creds.h
else
GEN_CREDS =
endif

$(GEN_CREDS): tools/gen_ccs.c include/authkem_cred.h src/authkem_test_keys.h \
		src/mlkem512_test_keys.h src/mlkem1024_test_keys.h
	@echo "Generating CCS credentials..."
	@mkdir -p $(GEN_DIR)
	@cc -std=c11 -Wall $(SUITE_CFLAGS) -Iinclude -Isrc tools/gen_ccs.c -o $(BUILD_DIR)/gen_ccs
	@$(BUILD_DIR)/gen_ccs $@

edhoc_authkem_initiator: $(GEN_CREDS)
	@echo "Building EDHOC Method 5 AUTHKEM Initiator (authkem-01, pqsuites $(SUITE))..."
	@$(MAKE) all TARGET=edhoc_authkem_initiator STACK_SIZE=$(STACK_INITIATOR) \
		C_SOURCES="src/edhoc_initiator_authkem.c $(AK_APP_COMMON)" \
		ASM_SOURCES="$(COMMON)/src/crt0.S" \
		INCLUDES="$(AK_INCLUDES)" "CFLAGS=$(AK_CFLAGS)" LIBS="-lgcc"

edhoc_authkem_responder: $(GEN_CREDS)
	@echo "Building EDHOC Method 5 AUTHKEM Responder (authkem-01, pqsuites $(SUITE))..."
	@$(MAKE) all TARGET=edhoc_authkem_responder STACK_SIZE=$(STACK_RESPONDER) \
		C_SOURCES="src/edhoc_responder_authkem.c $(AK_APP_COMMON)" \
		ASM_SOURCES="$(COMMON)/src/crt0.S" \
		INCLUDES="$(AK_INCLUDES)" "CFLAGS=$(AK_CFLAGS)" LIBS="-lgcc"
