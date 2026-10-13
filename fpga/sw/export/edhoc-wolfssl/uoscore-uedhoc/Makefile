# Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
# file at the top-level directory of this distribution.

# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# EDHOC library (RFC 9528, methods 0-3) built as libuoscore-uedhoc.a, with
# the EDHOC core shared with edhoc-authkem (../../common/edhoc).
# CC, AR and CFLAGS (crypto backend, suite, includes) come from ../mk.

LIB_NAME = libuoscore-uedhoc.a
COMMON  ?= ../../common

include makefile_config.mk

PREFIX ?= build
DIR = $(PREFIX)
$(shell mkdir -p $(DIR))

C_SOURCES  = $(wildcard src/edhoc/*.c) $(wildcard src/common/*.c)
C_SOURCES += $(wildcard $(COMMON)/edhoc/src/*.c) $(COMMON)/cbor/cbor.c
vpath %.c $(sort $(dir $(C_SOURCES)))

EXTENDED_CFLAGS  = $(filter-out -Os,$(CFLAGS))
EXTENDED_CFLAGS += $(FEATURES) $(OPT) $(DEBUG_PRINT)
EXTENDED_CFLAGS += -ffunction-sections -fdata-sections -std=c11
EXTENDED_CFLAGS += -MMD -MP -MF"$(@:%.o=%.d)"
EXTENDED_CFLAGS += -Iinc -I$(COMMON)/edhoc/inc -I$(COMMON)/cbor -I$(COMMON)/include

OBJ = $(addprefix $(DIR)/,$(notdir $(C_SOURCES:.c=.o)))

$(DIR)/$(LIB_NAME): $(OBJ)
	@echo "[Link (Static)]"
	@$(AR) -rcs $@ $^

# crypto_wrapper.c must NOT be compiled with -flto: LTO whole-program analysis
# eliminates the ES256 signing branch because alg is a compile-time constant at
# each call site from signature_or_mac_msg.c, and LTO dead-strips the branch.
$(DIR)/crypto_wrapper.o: src/common/crypto_wrapper.c Makefile makefile_config.mk
	@echo [Compile-nolto] $<
	@$(CC) -c $(filter-out -flto,$(EXTENDED_CFLAGS)) $< -o $@

$(DIR)/%.o: %.c Makefile makefile_config.mk
	@echo [Compile] $<
	@$(CC) -c $(EXTENDED_CFLAGS) $< -o $@

-include $(OBJ:.o=.d)

clean:
	rm -fR $(DIR)
