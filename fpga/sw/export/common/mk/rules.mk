# common/mk/rules.mk — compile/link rules (all, %.o, .elf, .bin, stamp)
# shared by edhoc-wolfssl and edhoc-authkem.

all: $(BUILD_DIR)/$(TARGET).elf $(BUILD_DIR)/$(TARGET).bin
	@echo "Build complete!"
	@$(SIZE) $(BUILD_DIR)/$(TARGET).elf

# Stamp named after a hash of the compile flags: any change of suite, method,
# role, transport or profile rebuilds every object without a manual
# `make clean`. Targets share one build directory and differ only in flags.
CFLAGS_STAMP = $(BUILD_DIR)/.cflags-$(shell echo '$(CFLAGS) $(INCLUDES)' | md5sum | cut -c1-12)

$(CFLAGS_STAMP): | $(BUILD_DIR)
	@rm -f $(BUILD_DIR)/.cflags-*
	@touch $@

$(BUILD_DIR)/%.o: %.c $(CFLAGS_STAMP)
	@echo "[CC] $<"
	@$(CC) -c $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES) $< -o $@

$(BUILD_DIR)/%.o: %.S $(CFLAGS_STAMP)
	@echo "[AS] $<"
	@$(CC) -c $(CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES) $< -o $@

$(BUILD_DIR)/$(TARGET).elf: $(OBJECTS)
	@echo "[LD] $@"
	@$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	@echo "[OBJCOPY] $@"
	@$(OBJCOPY) -O binary $< $@

$(BUILD_DIR):
	@mkdir -p $@
