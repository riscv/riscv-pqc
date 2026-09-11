# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause

SAIL ?= sail
SAIL_LIB_DIR ?= $(shell $(SAIL) --dir)/lib
SAILFLAGS ?=
CFLAGS ?= -O2
LDLIBS += -lgmp -lz

SOURCES := tests/prelude.sail tests/model.sail zvknhk_insts.sail tests/test_vkeccak.sail
SAIL_OPTIONS := --no-color --memo-z3-path build/sail_smt_cache $(SAILFLAGS)
RUNTIME := $(addprefix $(SAIL_LIB_DIR)/,sail.c rts.c sail_config.c cJSON.c sail_failure.c elf.c)

.DEFAULT_GOAL := test
.DELETE_ON_ERROR:
.PHONY: check test clean

check: | build
	$(SAIL) $(SAIL_OPTIONS) --just-check $(SOURCES)

test: build/test_vkeccak
	./build/test_vkeccak

build/test_vkeccak.c: $(SOURCES) Makefile | build
	$(SAIL) $(SAIL_OPTIONS) -c -o build/test_vkeccak $(SOURCES)

build/test_vkeccak: build/test_vkeccak.c $(RUNTIME) Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) -I"$(SAIL_LIB_DIR)" $(LDFLAGS) -o $@ $< $(RUNTIME) $(LDLIBS)

build:
	mkdir -p $@

clean:
	$(RM) build/test_vkeccak build/test_vkeccak.c build/test_vkeccak.h build/sail_smt_cache
