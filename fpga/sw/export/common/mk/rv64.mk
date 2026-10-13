# common/mk/rv64.mk — toolchain, target, board link and link flags shared by
# edhoc-wolfssl and edhoc-authkem. Included by each package's mk/config.mk,
# which sets COMMON, BUILD_DIR, TARGET and STACK_SIZE.

# ── Toolchain ────────────────────────────────────────────────────────────
# Point CROSS_COMPILE at your RISC-V GCC prefix, or put the toolchain on PATH.
#   make CROSS_COMPILE=/opt/riscv/bin/riscv64-unknown-elf-
CROSS_COMPILE ?= riscv64-unknown-elf-
CC      = $(CROSS_COMPILE)gcc
AR      = $(CROSS_COMPILE)gcc-ar
OBJCOPY = $(CROSS_COMPILE)objcopy
SIZE    = $(CROSS_COMPILE)size

# Target: the 64-bit Rocket of EdhocRocket6475MHzArty100TConfig (RV64IMAC,
# lp64). The crypto is tuned for it (64-bit limbs), so there is no RV32 build.
ARCH_FLAGS = -march=rv64imac_zicsr_zifencei -mabi=lp64 -mcmodel=medany

# ── Board-to-board link ──────────────────────────────────────────────────
# TRANSPORT=rf (default) carries every message over the MRF24J40 802.15.4
# radio on PMOD JC (bitstream built with WithArtyJCRadio, SPI1 @0x64006000).
# TRANSPORT=uart keeps the original UART1 wire on PMOD JB.
TRANSPORT ?= rf
ifeq ($(TRANSPORT),rf)
TRANSPORT_CFLAGS = -DEDHOC_TRANSPORT_RF
TRANSPORT_SRC    = $(COMMON)/src/edhoc_rf_link.c $(COMMON)/src/mrf24j40.c
else ifneq ($(TRANSPORT),uart)
$(error Invalid TRANSPORT=$(TRANSPORT). Use rf or uart)
endif

# ── Link flags ───────────────────────────────────────────────────────────
LDFLAGS  = $(ARCH_FLAGS) -flto -T $(COMMON)/linker/main.lds -L$(COMMON)/linker
LDFLAGS += -fno-builtin -fno-tree-loop-distribute-patterns -fno-unwind-tables -fno-asynchronous-unwind-tables
LDFLAGS += -nostartfiles -nostdlib -nodefaultlibs
LDFLAGS += -Wl,--defsym=__stack_size=$(STACK_SIZE)
LDFLAGS += -Wl,--gc-sections -Wl,-Map=$(BUILD_DIR)/$(TARGET).map
LDFLAGS += -Wl,--allow-multiple-definition
LDFLAGS += -Wl,--undefined=memset -Wl,--undefined=memcpy -Wl,--undefined=memmove
