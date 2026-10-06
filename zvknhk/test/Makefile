# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
#	Makefile -- Zvknhk (vkeccak.vi) instruction tests
#
#	Builds a static RISC-V test binary and runs it under the Spike built by
#	this repository. SPIKE and PK default to that build; the binary is
#	compiled for the smallest supported VLEN, and the VLEN the simulator runs
#	at is chosen with VLEN= (see the run-all target).

XBIN	=	xtest
CC		=	riscv64-unknown-linux-gnu-gcc
#RVKISA	=	rv64gcv_zbb_zvbb_zvbc_zvkg_zvkned_zvknhb_zvksed_zvksh_zvl256b
#	Compile-time ISA: the minimum VLEN the tests support, so one binary runs
#	at every VLEN in the table below.
RVKISA	=	rv64gcv_zvl128b

#	Runtime VLEN for the simulator. zvknhk.adoc tabulates 128, 256, 512,
#	1024 and >=2048; `make run-all` sweeps through 4096.
VLEN	?=	256
VLENS	=	128 256 512 1024 2048 4096

#	Spike built by `make spike` in zvknhk/; override to use another build.
SPIKE	?=	../riscv-isa-sim/build/spike
#	The proxy kernel that the test binary runs under.
PK		?=	$(RISCV)/riscv64-unknown-linux-gnu/bin/pk

#	QEMU built by `make qemu` in zvknhk/; override to use another build.
#	This is user-mode QEMU, which runs the binary directly -- no proxy kernel.
QEMU	?=	../qemu-src/build/qemu-riscv64
#	Interpreter prefix, so that dynamically linked RISC-V binaries resolve
#	their loader and libraries. Harmless for the static binary built here.
QEMU_SYSROOT ?= $(SYSROOT)

#	QEMU caps VLEN at RV_VLEN_MAX, which upstream currently sets to 1024, so
#	the 2048 row of the specification's table cannot be exercised here.
QEMUVLENS =	128 256 512 1024

SPIKEFL	=	--isa=rv64gcv_zvl$(VLEN)b_zvknhk_zicntr_zihpm
QEMUFL	=	-L $(QEMU_SYSROOT) \
			-cpu rv64,v=true,vlen=$(VLEN),elen=64,zvknhk=true,zicntr=true,zihpm=true
#	Target sysroot. Note this is $(RISCV)/sysroot, not $(RISCV)/sysroot/usr:
#	the loader and the shared libc live in <sysroot>/lib, so pointing one
#	level too deep still links -static (libc.a is found as <sysroot>/lib) but
#	makes a dynamic link fail to find ld-linux-riscv64-lp64d.so.1.
SYSROOT	?=	$(RISCV)/sysroot

CFLAGS	=	-march=$(RVKISA) -mabi=lp64d -Wall
LDFLAGS	=	-static --sysroot=$(SYSROOT)
CSRC	= 	$(filter-out edge_probe.c,$(wildcard *.c))
SSRC	= 	$(wildcard *.s *.S)
OBJS	=	$(CSRC:.c=.o) $(SSRC:.s=.o)
LDLIBS	=
EDGE_CASES =	0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
EDGE_BINS =	$(addprefix edge_probe,$(EDGE_CASES))

run:	$(XBIN)
	$(SPIKE) $(SPIKEFL) $(PK) $(XBIN)

#	Run the suite at every VLEN the specification tabulates.
#
#	Each iteration checks four things independently, because no single one is
#	sufficient: that the simulator exited cleanly (test_main returns the failure
#	count, and a trap exits 255), that it really ran at the VLEN we asked for,
#	that no vector reported a failure, and that vectors actually ran at all --
#	the last so an empty or truncated run cannot pass silently.
#
#	The simulator output is captured rather than piped, so that $$? is the
#	simulator's status and not some filter's.
run-all: $(XBIN) $(EDGE_BINS)
	@rc=0; \
	for v in $(VLENS); do \
		out=`$(SPIKE) --isa=rv64gcv_zvl$${v}b_zvknhk_zicntr_zihpm $(PK) $(XBIN) 2>&1`; \
		st=$$?; \
		got=`printf '%s\n' "$$out" | sed -n 's/^ *vlen *= *//p'`; \
		bad=`printf '%s\n' "$$out" | sed -n 's/^\[INFO\] fail= *//p'`; \
		ran=`printf '%s\n' "$$out" | grep -c '^\[PASS\]'`; \
		if [ $$st -ne 0 ]; then \
			echo "VLEN=$$v FAIL: simulator exited $$st"; rc=1; \
		elif [ "$$got" != "$$v" ]; then \
			echo "VLEN=$$v FAIL: ran at vlen=$${got:-unknown}"; rc=1; \
		elif [ "$$bad" != "0" ]; then \
			echo "VLEN=$$v FAIL: $${bad:-no} vector failure count"; rc=1; \
		elif [ $$ran -eq 0 ]; then \
			echo "VLEN=$$v FAIL: no vectors ran"; rc=1; \
		else \
			echo "VLEN=$$v ok: $$ran vectors"; \
		fi; \
	done; \
	if ! ./run_edge_cases.sh spike "$(SPIKE)" "$(PK)" "$(VLENS)"; then rc=1; fi; \
	[ $$rc -eq 0 ] || echo "run-all: FAILED"; \
	exit $$rc

#	The same suite under user-mode QEMU instead of Spike.
run-qemu: $(XBIN)
	$(QEMU) $(QEMUFL) $(XBIN)

#	The VLEN sweep under QEMU. Same four checks as run-all: that the emulator
#	exited cleanly, that it really ran at the VLEN we asked for, that no vector
#	reported a failure, and that vectors actually ran at all.
run-qemu-all: $(XBIN) $(EDGE_BINS)
	@rc=0; \
	for v in $(QEMUVLENS); do \
		out=`$(QEMU) -L $(QEMU_SYSROOT) \
			-cpu rv64,v=true,vlen=$${v},elen=64,zvknhk=true,zicntr=true,zihpm=true \
			$(XBIN) 2>&1`; \
		st=$$?; \
		got=`printf '%s\n' "$$out" | sed -n 's/^ *vlen *= *//p'`; \
		bad=`printf '%s\n' "$$out" | sed -n 's/^\[INFO\] fail= *//p'`; \
		ran=`printf '%s\n' "$$out" | grep -c '^\[PASS\]'`; \
		if [ $$st -ne 0 ]; then \
			echo "VLEN=$$v FAIL: qemu exited $$st"; rc=1; \
		elif [ "$$got" != "$$v" ]; then \
			echo "VLEN=$$v FAIL: ran at vlen=$${got:-unknown}"; rc=1; \
		elif [ "$$bad" != "0" ]; then \
			echo "VLEN=$$v FAIL: $${bad:-no} vector failure count"; rc=1; \
		elif [ $$ran -eq 0 ]; then \
			echo "VLEN=$$v FAIL: no vectors ran"; rc=1; \
		else \
			echo "VLEN=$$v ok: $$ran vectors"; \
		fi; \
	done; \
	out=`$(QEMU) -L $(QEMU_SYSROOT) \
		-cpu rv64,v=true,vlen=512,elen=64,zvknhk=true,rvv_vl_half_avl=true,zicntr=true,zihpm=true \
		$(XBIN) 2>&1`; \
	st=$$?; \
	bad=`printf '%s\n' "$$out" | sed -n 's/^\[INFO\] fail= *//p'`; \
	if [ $$st -ne 0 ] || [ "$$bad" != "0" ]; then \
		echo "VLEN=512 half-AVL FAIL: exit=$$st fail=$${bad:-unknown}"; rc=1; \
	else \
		echo "VLEN=512 half-AVL ok: EGSMAX=32"; \
	fi; \
	if ! ./run_edge_cases.sh qemu "$(QEMU)" - "$(QEMUVLENS)"; then rc=1; fi; \
	[ $$rc -eq 0 ] || echo "run-qemu-all: FAILED"; \
	exit $$rc

$(XBIN): $(OBJS) Makefile
	$(CC) $(LDFLAGS) $(CFLAGS) -o $(XBIN) $(OBJS) $(LDLIBS)

$(EDGE_BINS): edge_probe%: edge_probe.c Makefile
	$(CC) $(LDFLAGS) $(CFLAGS) -DCASE=$* -o $@ $<

#	A dynamically linked build of the same suite. Spike's proxy kernel runs
#	static binaries only, so this one exists for QEMU user-mode emulation,
#	which resolves the loader and libc through -L $(QEMU_SYSROOT).
$(XBIN)-dyn: $(OBJS) Makefile
	$(CC) --sysroot=$(SYSROOT) $(CFLAGS) -o $(XBIN)-dyn $(OBJS) $(LDLIBS)

run-qemu-dyn: $(XBIN)-dyn
	$(QEMU) $(QEMUFL) $(XBIN)-dyn

%.o:	%.c
	$(CC) $(CFLAGS) -c $< -o $@

#	Cleanup
clean:
	$(RM) -f $(XBIN) $(OBJS) $(EDGE_BINS)
