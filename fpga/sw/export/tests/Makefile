# tests/Makefile — peripheral and crypto tests for the RV64 Rocket SoC.
#
#   make <target> [CROSS_COMPILE=<prefix>]
#
# Peripheral targets (requirement B7):  gpio_test uart_test spi_test jtag_test
# Crypto targets     (requirement B6):  crypto_test mlkem_test
# SD card bench tool:                   sd_prep (format / SEND.BIN / verify, see
#                                       src/sd_prep.c); fat32-host-test on the host
#
# Startup, console, libc stubs, linker script and platform headers are the
# ones the EDHOC firmware uses (../common); only test_init.h is test-specific.

COMMON = ../common
include $(COMMON)/mk/rv64.mk

BUILD_DIR = build
.DEFAULT_GOAL := all

CFLAGS  = $(ARCH_FLAGS) -Os -g0 -ffunction-sections -fdata-sections
CFLAGS += -fno-unwind-tables -fno-asynchronous-unwind-tables
CFLAGS += -nostartfiles -nostdlib -nodefaultlibs -fno-builtin
CFLAGS += -fno-tree-loop-distribute-patterns -Wall -Wextra
# EXTRA_CFLAGS lets the caller add defines without clobbering the flags above.
CFLAGS += $(EXTRA_CFLAGS)
INCLUDES = -Iinclude -I$(COMMON)/include

LDFLAGS  = $(ARCH_FLAGS) -T $(COMMON)/linker/main.lds -L$(COMMON)/linker
LDFLAGS += -nostartfiles -nostdlib -nodefaultlibs -fno-builtin
LDFLAGS += -Wl,--gc-sections -Wl,--allow-multiple-definition
LIBS = -lgcc

COMMON_SRC = $(COMMON)/src/kprintf.c $(COMMON)/src/libc_stubs.c
ASM_SRC    = $(COMMON)/src/crt0.S

PERIPH_TESTS = gpio_test uart_test spi_test jtag_test
CRYPTO_TESTS = crypto_test mlkem_test
ALL_TESTS    = $(PERIPH_TESTS) $(CRYPTO_TESTS)

# The crypto tests run the implementations the EDHOC firmware links, not a
# separate copy: ../common/crypto for SHA-2, HMAC/HKDF and AES-CCM/GCM,
# curve25519-donna for X25519, mlkem-native (FIPS 203) for ML-KEM.
CRYPTO_DIR = $(COMMON)/crypto
CRYPTO_SRC = $(addprefix $(CRYPTO_DIR)/,sha256.c sha384.c hmac_hkdf.c aes.c \
               aes_ccm.c aes_gcm.c secure_wipe.c) \
             $(COMMON)/externals/curve25519-donna/curve25519-donna-c64.c
MLK_ROOT   = $(COMMON)/externals/mlkem-native/mlkem

# All three ML-KEM parameter sets (requirement B6): mlkem-native's multi-level
# build compiles the library once per parameter set; the 512 build also carries
# the level-independent code (FIPS 202) that the other two share. Symbols come
# out as mlk512_*, mlk768_*, mlk1024_*.
MLK_CFLAGS = -I$(MLK_ROOT) -DMLK_CONFIG_MULTILEVEL_BUILD \
             -DMLK_CONFIG_NAMESPACE_PREFIX=mlk -DMLK_CONFIG_NO_RANDOMIZED_API \
             -DMLK_CONFIG_LOW_RAM
MLK_OBJS   = $(BUILD_DIR)/mlk512.o $(BUILD_DIR)/mlk768.o $(BUILD_DIR)/mlk1024.o

$(BUILD_DIR)/mlk512.o: $(MLK_ROOT)/mlkem_native.c
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) $(MLK_CFLAGS) -DMLK_CONFIG_PARAMETER_SET=512 \
		-DMLK_CONFIG_MULTILEVEL_WITH_SHARED -c $< -o $@
$(BUILD_DIR)/mlk768.o $(BUILD_DIR)/mlk1024.o: $(BUILD_DIR)/mlk%.o: $(MLK_ROOT)/mlkem_native.c
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) $(MLK_CFLAGS) -DMLK_CONFIG_PARAMETER_SET=$* \
		-DMLK_CONFIG_MULTILEVEL_NO_SHARED -c $< -o $@

.PHONY: all periph crypto clean fat32-host-test sd_prep $(ALL_TESTS)

all: $(ALL_TESTS)
periph: $(PERIPH_TESTS)
crypto: $(CRYPTO_TESTS)

crypto_test:
	@echo "== crypto_test (RV64) =="
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) $(INCLUDES) -I$(CRYPTO_DIR) $(LDFLAGS) \
		src/crypto_classic.c $(CRYPTO_SRC) $(COMMON_SRC) $(ASM_SRC) $(LIBS) \
		-o $(BUILD_DIR)/crypto_test.elf
	@$(OBJCOPY) -O binary $(BUILD_DIR)/crypto_test.elf $(BUILD_DIR)/crypto_test.bin
	@$(SIZE) $(BUILD_DIR)/crypto_test.elf

# Deepest ML-KEM call with MLK_CONFIG_LOW_RAM: ML-KEM-768 decapsulation,
# ~13 KB of stack (static call-graph worst case on RV64, -Os; ML-KEM-1024
# decapsulation is ~11.7 KB, ~22 KB without LOW_RAM). Require 16 KB free
# above the image.
mlkem_test: $(MLK_OBJS)
	@echo "== mlkem_test (RV64) =="
	@mkdir -p $(BUILD_DIR)
	@$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -Wl,--defsym=__stack_size=16384 \
		src/crypto_mlkem.c $(MLK_OBJS) $(COMMON_SRC) $(ASM_SRC) $(LIBS) \
		-o $(BUILD_DIR)/mlkem_test.elf
	@$(OBJCOPY) -O binary $(BUILD_DIR)/mlkem_test.elf $(BUILD_DIR)/mlkem_test.bin
	@$(SIZE) $(BUILD_DIR)/mlkem_test.elf

# BUILD_RULE: <target-name> <main-source>
define BUILD_RULE
$(1):
	@echo "== $(1) (RV64) =="
	@mkdir -p $$(BUILD_DIR)
	@$$(CC) $$(CFLAGS) $$(INCLUDES) $$(LDFLAGS) \
		$(2) $$(COMMON_SRC) $$(ASM_SRC) $$(LIBS) \
		-o $$(BUILD_DIR)/$(1).elf
	@$$(OBJCOPY) -O binary $$(BUILD_DIR)/$(1).elf $$(BUILD_DIR)/$(1).bin
	@$$(SIZE) $$(BUILD_DIR)/$(1).elf
endef

$(eval $(call BUILD_RULE,gpio_test,src/periph_gpio.c))
$(eval $(call BUILD_RULE,uart_test,src/periph_uart.c))
$(eval $(call BUILD_RULE,spi_test,src/periph_spi.c))
$(eval $(call BUILD_RULE,jtag_test,src/periph_jtag.c))

# SD card bench tool (format / SEND.BIN / verify RECV.BIN over JTAG), see src/sd_prep.c
$(eval $(call BUILD_RULE,sd_prep,src/sd_prep.c src/sd_format.c $(COMMON)/src/sd_card.c $(COMMON)/src/fat32.c))

# FAT32 layer of the SD file transfer, on the host against a disk image
# (needs dosfstools and `pip install pyfatfs`).
fat32-host-test:
	@mkdir -p $(BUILD_DIR)
	@cc -O2 -Wall -Wextra -Iinclude -I$(COMMON)/include -o $(BUILD_DIR)/fat32_host \
		src/fat32_host.c src/sd_format.c $(COMMON)/src/fat32.c
	@python3 fat32_test.py $(BUILD_DIR)/fat32_host

clean:
	@$(RM) -r $(BUILD_DIR)
	@echo "cleaned"
