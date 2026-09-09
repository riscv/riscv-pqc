# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
# Makefile for the Zvknhk (Vector Keccak) reference implementations and tests.
#
# The specification itself lives in ../src/zvknhk.adoc and is built by the
# Makefile at the repository root; nothing here touches the document.
#
# Targets:
#   make spike        — Build Spike (riscv-isa-sim) with the Zvknhk instruction
#   make patch-spike  — Patch the Zvknhk instruction into the upstream Spike sources
#   make unpatch-spike— Restore the Spike sources to pristine upstream
#   make test         — Build and run the instruction tests under the built Spike
#   make test-all     — Run the tests at every VLEN the spec tabulates (128..2048)
#   make qemu         — Build QEMU (qemu-src) with the Zvknhk instruction
#   make patch-qemu   — Patch the Zvknhk instruction into the upstream QEMU sources
#   make unpatch-qemu — Restore the QEMU sources to pristine upstream
#   make test-qemu    — Build and run the instruction tests under the built QEMU
#   make test-qemu-all— Run the tests under QEMU at every VLEN it supports
#   make boot-qemu    — Boot the system-mode smoke test on qemu-system-riscv64
#   make openssl      — Build OpenSSL (demo/openssl) with the Zvknhk backend
#   make patch-openssl— Patch the Zvknhk Keccak backend into the OpenSSL sources
#   make unpatch-openssl — Restore the OpenSSL sources to pristine upstream
#   make test-openssl — Run the OpenSSL Keccak/ML-KEM/ML-DSA checks under QEMU
#   make test-openssl-all — Run those checks at every VLEN QEMU supports
#   make -C demo count    — Instructions removed per ML-KEM/ML-DSA operation
#   make -C demo cycles   — Cycles per operation; runs natively, on the target
#   make clean        — Remove build artifacts

SIM_DIR    := riscv-isa-sim
SIM_BUILD  := $(SIM_DIR)/build
SPIKE_BIN  := $(SIM_BUILD)/spike
QEMU_DIR   := qemu-src
QEMU_BUILD := $(QEMU_DIR)/build
QEMU_USER  := $(QEMU_BUILD)/qemu-riscv64
QEMU_SYS   := $(QEMU_BUILD)/qemu-system-riscv64
SSL_DIR    := demo/openssl
SSL_BUILD  := $(SSL_DIR)/build
SSL_APP    := $(SSL_BUILD)/apps/openssl
TEST_DIR   := test
DEMO_DIR   := demo

# QEMU targets. riscv64-linux-user runs RISC-V Linux binaries, static and
# dynamic alike; riscv64-softmmu is full-system emulation, for booting a
# kernel. Override QEMU_TARGETS to build just one of them.
QEMU_TARGETS ?= riscv64-linux-user,riscv64-softmmu
QEMU_CONFIG_FLAGS ?= --target-list=$(QEMU_TARGETS) --disable-docs --disable-werror

# OpenSSL cross build. no-shared keeps apps/openssl free of an OpenSSL runtime
# search path; libc is still dynamic, so the emulator needs -L $(RISCV)/sysroot.
SSL_CROSS ?= riscv64-unknown-linux-gnu-
SSL_CONFIG_FLAGS ?= linux64-riscv64 --cross-compile-prefix=$(SSL_CROSS) \
                    --prefix=/usr/local/openssl-zvknhk no-shared

NPROC ?= $(shell nproc 2>/dev/null || echo 4)

# Submodule paths are recorded relative to the superproject root, so run the
# submodule commands with git's cwd set here and let it resolve the pathspec.
GIT := git -C $(CURDIR)

.PHONY: all clean
.PHONY: spike patch-spike unpatch-spike test test-all test-clean spike-clean sim-submodule-init
.PHONY: qemu patch-qemu unpatch-qemu qemu-clean qemu-submodule-init test-qemu test-qemu-all
.PHONY: boot-qemu boot-qemu-all
.PHONY: openssl patch-openssl unpatch-openssl openssl-clean openssl-submodule-init
.PHONY: test-openssl test-openssl-all

all: test

clean:
	$(MAKE) spike-clean qemu-clean openssl-clean test-clean

# --- Spike (riscv-isa-sim) -------------------------------------------------
#
# The simulator is a pristine upstream submodule, and scripts/apply-spike-patch.sh
# layers the Zvknhk instruction onto it. The patch is idempotent, so it is safe
# to re-run on every build.

sim-submodule-init:
	@if [ ! -f $(SIM_DIR)/riscv/riscv.mk.in ]; then \
		echo "Initializing the $(SIM_DIR) submodule..."; \
		$(GIT) submodule update --init --recursive $(SIM_DIR); \
	fi

patch-spike: sim-submodule-init
	./scripts/apply-spike-patch.sh

# Restore the simulator sources to pristine upstream. Needed after changing
# *what* apply-spike-patch.sh inserts: each site is guarded by a token that
# only the patch introduces, so an already-patched file is skipped and would
# otherwise keep the previous version of the insertion.
unpatch-spike:
	git -C $(SIM_DIR) checkout -- disasm/ riscv/
	rm -f $(SIM_DIR)/riscv/insns/vkeccak_vi.h

# Configure once, then build. Re-running is cheap; the configure step is
# skipped when the build directory already has a Makefile.
spike: patch-spike
	@mkdir -p $(SIM_BUILD)
	@if [ ! -f $(SIM_BUILD)/Makefile ]; then \
		echo "==> Configuring Spike..."; \
		cd $(SIM_BUILD) && ../configure; \
	fi
	@echo "==> Building Spike (-j$(NPROC))..."
	$(MAKE) -C $(SIM_BUILD) -j$(NPROC)
	@echo -e '\n  Built $(SPIKE_BIN)\n'

# Build the test binary and run it under the Spike we just built. Needs a
# riscv64-unknown-linux-gnu toolchain and $$RISCV set (see test/README.md).
test: spike
	$(MAKE) -C $(TEST_DIR) run SPIKE=$(abspath $(SPIKE_BIN))

# The fixed element group spans NREG=ceil(2048/VLEN) registers, so the number
# of registers it occupies -- and which vd are legal -- changes with VLEN.
# This runs the whole suite at each VLEN the specification tabulates.
test-all: spike
	$(MAKE) -C $(TEST_DIR) run-all SPIKE=$(abspath $(SPIKE_BIN))

spike-clean:
	rm -rf $(SIM_BUILD)

test-clean:
	$(MAKE) -C $(TEST_DIR) clean

# --- QEMU (qemu-src) --------------------------------------------------------
#
# Same pattern again: QEMU is a pristine upstream submodule and
# scripts/apply-qemu-patch.sh layers the Zvknhk instruction onto it. The patch
# is idempotent, so it is safe to re-run on every build. See qemu/README.md
# for what it inserts and where.

qemu-submodule-init:
	@if [ ! -f $(QEMU_DIR)/target/riscv/insn32.decode ]; then \
		echo "Initializing the $(QEMU_DIR) submodule..."; \
		$(GIT) submodule update --init --recursive $(QEMU_DIR); \
	fi

patch-qemu: qemu-submodule-init
	./scripts/apply-qemu-patch.sh

# Restore the QEMU sources to pristine upstream. Needed after changing *what*
# apply-qemu-patch.sh inserts: each site is guarded by a token that only the
# patch introduces, so an already-patched file is skipped and would otherwise
# keep the previous version of the insertion.
unpatch-qemu:
	git -C $(QEMU_DIR) checkout -- target/riscv/
	rm -f $(QEMU_DIR)/target/riscv/tcg/vkeccak_vi.c.inc
	rm -f $(QEMU_DIR)/target/riscv/tcg/insn_trans/trans_vkeccak_vi.c.inc

# Configure once, then build. Re-running is cheap; the configure step is
# skipped when the build directory already has a build.ninja.
qemu: patch-qemu
	@mkdir -p $(QEMU_BUILD)
	@if [ ! -f $(QEMU_BUILD)/build.ninja ]; then \
		echo "==> Configuring QEMU..."; \
		cd $(QEMU_BUILD) && ../configure $(QEMU_CONFIG_FLAGS); \
	fi
	@echo "==> Building QEMU (-j$(NPROC))..."
	$(MAKE) -C $(QEMU_BUILD) -j$(NPROC)
	@echo -e '\n  Built $(QEMU_USER)\n        $(QEMU_SYS)\n'

# Run the instruction tests under the QEMU we just built, rather than Spike.
test-qemu: qemu
	$(MAKE) -C $(TEST_DIR) run-qemu QEMU=$(abspath $(QEMU_USER))

test-qemu-all: qemu
	$(MAKE) -C $(TEST_DIR) run-qemu-all QEMU=$(abspath $(QEMU_USER))

# The same instruction in full-system emulation: a freestanding payload booted
# on the 'virt' machine with no proxy kernel and no firmware.
boot-qemu: qemu
	$(MAKE) -C $(TEST_DIR)/system boot QEMU=$(abspath $(QEMU_SYS))

boot-qemu-all: qemu
	$(MAKE) -C $(TEST_DIR)/system boot-all QEMU=$(abspath $(QEMU_SYS))

qemu-clean:
	rm -rf $(QEMU_BUILD)
	$(MAKE) -C $(TEST_DIR)/system clean

# --- OpenSSL (demo/openssl) -------------------------------------------------
#
# Same pattern once more: OpenSSL is a pristine upstream submodule and
# scripts/apply-openssl-patch.sh layers the Zvknhk Keccak backend onto it. The
# patch is idempotent, so it is safe to re-run on every build. See
# openssl/README.md for what it inserts and why it goes where it does.
#
# This is the consumer-facing end of the extension: patching KeccakF1600()
# puts vkeccak.vi under SHA-3, SHAKE, KMAC, ML-KEM, ML-DSA and SLH-DSA at once.

openssl-submodule-init:
	@if [ ! -f $(SSL_DIR)/crypto/sha/keccak1600.c ]; then \
		echo "Initializing the $(SSL_DIR) submodule..."; \
		$(GIT) submodule update --init --recursive $(SSL_DIR); \
	fi

patch-openssl: openssl-submodule-init
	./scripts/apply-openssl-patch.sh

# Restore the OpenSSL sources to pristine upstream. Needed after changing
# *what* apply-openssl-patch.sh inserts: each site is guarded by a token that
# only the patch introduces, so an already-patched file is skipped and would
# otherwise keep the previous version of the insertion.
unpatch-openssl:
	git -C $(SSL_DIR) checkout -- crypto/sha/ include/crypto/
	rm -f $(SSL_DIR)/crypto/sha/keccak1600_zvknhk.c.inc

# Configure once, then build. Re-running is cheap; the configure step is
# skipped when the build directory already has a Makefile.
openssl: patch-openssl
	@mkdir -p $(SSL_BUILD)
	@if [ ! -f $(SSL_BUILD)/Makefile ]; then \
		echo "==> Configuring OpenSSL..."; \
		cd $(SSL_BUILD) && ../Configure $(SSL_CONFIG_FLAGS); \
	fi
	@echo "==> Building OpenSSL (-j$(NPROC))..."
	$(MAKE) -C $(SSL_BUILD) -j$(NPROC)
	@echo -e '\n  Built $(SSL_APP)\n'

# Known-answer checks for SHA-3 and SHAKE with the instruction on and off, an
# ML-KEM and an ML-DSA round trip, and a negative test that the instruction is
# genuinely executing. Needs the QEMU from `make qemu`.
# Depends on qemu as well as openssl: the checks run the emulator built here,
# and the negative test needs a CPU model that can be told to omit Zvknhk.
test-openssl: openssl qemu
	$(MAKE) -C $(DEMO_DIR) test QEMU=$(abspath $(QEMU_USER))

test-openssl-all: openssl qemu
	$(MAKE) -C $(DEMO_DIR) test-all QEMU=$(abspath $(QEMU_USER))

openssl-clean:
	rm -rf $(SSL_BUILD)
	$(MAKE) -C $(DEMO_DIR) clean
