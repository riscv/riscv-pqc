# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
#	Makefile -- Zvknhk in OpenSSL
#
#	Runs the OpenSSL built by `make openssl` in zvknhk/ under the QEMU
#	built by `make qemu`, and checks that the vkeccak.vi backend is actually
#	the code doing the work.
#
#	The capability has no hwprobe key -- Zvknhk is not an upstream extension --
#	so it is switched on through OPENSSL_riscvcap. That makes the interesting
#	tests cheap: the same binary can be run with the instruction enabled and
#	disabled, and against a CPU that does not implement it.

OPENSSL	?=	openssl/build/apps/openssl
QEMU	?=	../qemu-src/build/qemu-riscv64
SYSROOT	?=	$(RISCV)/sysroot

VLEN	?=	256
VLENS	=	128 256 512 1024

#	parse_env() searches the string for "_<EXT>", so V has to be spelled with
#	its own underscore -- "rv64gcv_zvknhk" contains no "_V", riscv_vlen() would
#	then read back 0, and the backend would decline.
CAP		=	rv64gc_v_zvknhk
NOCAP	=	rv64gc

#	A CPU with the instruction, and one without it. The software-path checks
#	deliberately run on QEMUFL_NO: if they ran on a CPU that has the
#	instruction, a regression that executed vkeccak.vi even with the
#	capability off would still pass.
QEMUFL	=	-L $(SYSROOT) -cpu rv64,v=true,vlen=$(VLEN),elen=64,zvknhk=true
QEMUFL_NO =	-L $(SYSROOT) -cpu rv64,v=true,vlen=$(VLEN),elen=64

#	Known answers for the empty input, "<alg>:<extra args>:<expected>" with '@'
#	standing in for a space so each triple stays one make word.
#
#	The 200-byte SHAKE vectors are the ones that matter. Output shorter than
#	the rate (168 for SHAKE128, 136 for SHAKE256) is copied straight out of the
#	state after the padding permutation, so it never reaches the KeccakF1600()
#	call in SHA3_squeeze() -- only the one in SHA3_absorb(). Counted directly:
#	xoflen 32 and 168 execute vkeccak.vi once, 200 executes it twice, 400 three
#	times. The 32-byte vectors are FIPS 202; the 200-byte ones were taken from
#	an independent OpenSSL build on another architecture, and their first 32
#	bytes agree with the FIPS 202 values.
KATS = \
	-sha3-256:@:a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a \
	-sha3-512:@:a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26 \
	-shake128:-xoflen@32:7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26 \
	-shake256:-xoflen@32:46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f \
	-shake128:-xoflen@200:7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877 \
	-shake256:-xoflen@200:46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab

test:
	@$(MAKE) --no-print-directory check VLEN=$(VLEN)

#	The whole point of the sweep: NREG = ceil(2048/VLEN) changes how many
#	registers the state occupies, and at VLEN=128 the transfer has to be split
#	in two. Both paths through KeccakF1600_zvknhk() need exercising.
test-all: pqcbench
	@rc=0; \
	for v in $(VLENS); do \
		if $(MAKE) --no-print-directory check VLEN=$$v > /tmp/zvknhk-ssl-$$v.log 2>&1; then \
			echo "VLEN=$$v ok: `grep -c '^  ok' /tmp/zvknhk-ssl-$$v.log` checks"; \
		else \
			echo "VLEN=$$v FAIL:"; sed 's/^/    /' /tmp/zvknhk-ssl-$$v.log; rc=1; \
		fi; \
	done; \
	[ $$rc -eq 0 ] || echo "test-all: FAILED"; \
	exit $$rc

check: pqcbench
	@echo "== VLEN=$(VLEN) =="; \
	fail=0; \
	for mode in vkeccak software; do \
		if [ $$mode = vkeccak ]; then cap="$(CAP)"; fl="$(QEMUFL)"; \
		else cap="$(NOCAP)"; fl="$(QEMUFL_NO)"; fi; \
		for t in $(KATS); do \
			alg=`echo "$$t" | cut -d: -f1`; \
			arg=`echo "$$t" | cut -d: -f2 | sed 's/^@$$//' | tr '@' ' '`; \
			exp=`echo "$$t" | cut -d: -f3`; \
			got=`printf '' | OPENSSL_riscvcap="$$cap" $(QEMU) $$fl $(OPENSSL) \
			     dgst $$alg $$arg 2>&1 | sed 's/.*= //'`; \
			if [ "$$got" = "$$exp" ]; then \
				printf "  ok   %-20s (%s)\n" "$$alg $$arg" "$$mode"; \
			else \
				printf "  FAIL %-20s (%s): %s\n" "$$alg $$arg" "$$mode" "$$got"; \
				fail=1; \
			fi; \
		done; \
	done; \
	d=`mktemp -d`; \
	export OPENSSL_riscvcap="$(CAP)"; \
	$(QEMU) $(QEMUFL) $(OPENSSL) genpkey -algorithm ML-KEM-768 -out $$d/k.pem 2>/dev/null && \
	$(QEMU) $(QEMUFL) $(OPENSSL) pkeyutl -encap -inkey $$d/k.pem -secret $$d/s1 -out $$d/ct 2>/dev/null && \
	$(QEMU) $(QEMUFL) $(OPENSSL) pkeyutl -decap -inkey $$d/k.pem -in $$d/ct -secret $$d/s2 2>/dev/null && \
	cmp -s $$d/s1 $$d/s2 && echo "  ok   ML-KEM-768 keygen/encap/decap" \
	                     || { echo "  FAIL ML-KEM-768"; fail=1; }; \
	echo zvknhk > $$d/m; \
	$(QEMU) $(QEMUFL) $(OPENSSL) genpkey -algorithm ML-DSA-65 -out $$d/d.pem 2>/dev/null && \
	$(QEMU) $(QEMUFL) $(OPENSSL) pkeyutl -sign -rawin -inkey $$d/d.pem -in $$d/m -out $$d/sig 2>/dev/null && \
	$(QEMU) $(QEMUFL) $(OPENSSL) pkeyutl -verify -rawin -inkey $$d/d.pem -in $$d/m -sigfile $$d/sig >/dev/null 2>&1 && \
	echo "  ok   ML-DSA-65 keygen/sign/verify" \
	  || { echo "  FAIL ML-DSA-65"; fail=1; }; \
	rm -rf $$d; \
	unset OPENSSL_riscvcap; \
	a=`OPENSSL_riscvcap=$(CAP)   $(QEMU) $(QEMUFL)    ./pqcbench fingerprint 1 \
	   2>/dev/null`; sa=$$?; \
	b=`OPENSSL_riscvcap=$(NOCAP) $(QEMU) $(QEMUFL_NO) ./pqcbench fingerprint 1 \
	   2>/dev/null`; sb=$$?; \
	na=`printf '%s\n' "$$a" | grep -c '^ml-'`; \
	if [ $$sa -eq 0 ] && [ $$sb -eq 0 ] && [ $$na -eq 3 ] && [ "$$a" = "$$b" ]; then \
		echo "  ok   ML-KEM/ML-DSA fingerprints agree across both backends"; \
	else \
		echo "  FAIL fingerprints: status $$sa/$$sb, $$na of 3 lines"; \
		printf '%s\n' "$$a" "--" "$$b" | sed 's/^/         /'; fail=1; \
	fi; \
	OPENSSL_riscvcap="$(CAP)" $(QEMU) $(QEMUFL_NO) $(OPENSSL) dgst -sha3-256 /dev/null \
	    >/dev/null 2>&1; \
	st=$$?; \
	if [ $$st -eq 132 ]; then \
		echo "  ok   negative: SIGILL (132) on a CPU without Zvknhk"; \
	else \
		echo "  FAIL negative: exit $$st, wanted 132 (128+SIGILL). Anything else"; \
		echo "                 means the run died for some other reason and the"; \
		echo "                 instruction may never have executed"; fail=1; \
	fi; \
	exit $$fail

#	--- instruction counting -------------------------------------------------
#
#	QEMU has no timing model, and in user mode it answers every counter CSR
#	from the host cpu's tick counter (read_hpmcounter -> get_ticks ->
#	cpu_get_host_ticks), so rdcycle/rdinstret are useless here. What QEMU does
#	do exactly is count executed instructions, via a TCG plugin.
#
#	pqcbench runs one operation in a loop with setup hoisted out, so counting
#	at n and 2n and differencing cancels process startup. Without that, the
#	numbers measure OpenSSL's CLI rather than the algorithm.

PLUGIN	?=	../qemu-src/build/tests/tcg/plugins/libinsn.so
OPS		=	mlkem-keygen mlkem-encap mlkem-decap \
			mldsa-keygen mldsa-sign mldsa-verify
N		?=	21

CFLAGS	=	-O2 -Wall -I openssl/include -I openssl/build/include
LDLIBS	=	openssl/build/libcrypto.a -lpthread -ldl
CC		=	riscv64-unknown-linux-gnu-gcc

pqcbench: pqcbench.c openssl/build/libcrypto.a
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

#	The instructions-per-permutation constants are calibrated by count.sh on
#	every run, with this binary at this VLEN -- they used to be hardcoded, and
#	were both stale and VLEN-dependent.
count: pqcbench
	@QEMU="$(QEMU)" QEMUFL="$(QEMUFL)" OPENSSL="$(OPENSSL)" \
	 PLUGIN="$(PLUGIN)" CAP="$(CAP)" NOCAP="$(NOCAP)" N="$(N)" \
	 OPS="$(OPS)" ./count.sh

#	--- cycle counting on real hardware --------------------------------------
#
#	rdcycle/rdinstret, best of CYCLE_REPS runs of CYCLE_N iterations. This is
#	the target to use on an FPGA or silicon; on QEMU it prints numbers but
#	flags them, because qemu-riscv64 answers both CSRs from the host clock and
#	the "CPI" comes out at 1.000. Where the counters are not readable at all
#	the tool falls back to wall clock and says so -- but not under Spike behind
#	pk, which aborts on the trap rather than raising SIGILL; use `pqcbench <op>
#	<n>` there and count from outside.
#
#	Run it natively on the target -- no emulator:
#	    ./pqcbench all 10 5                 # software path
#	    OPENSSL_riscvcap=rv64gc_v_zvknhk ./pqcbench all 10 5

CYCLE_N	?=	10
CYCLE_REPS ?=	5

#	NATIVE. No emulator: this must run on the target, where the counter CSRs
#	mean something. On a build host it will fail to exec a RISC-V binary, which
#	is the correct outcome -- copy demo/pqcbench to the board and run it there.
cycles: pqcbench
	@if ! ./pqcbench mlkem-encap 1 >/dev/null 2>&1; then \
		echo "cycles: ./pqcbench does not run on this host -- it is a RISC-V"; \
		echo "        binary, and this target deliberately uses no emulator,"; \
		echo "        because counter CSRs only mean something on the target."; \
		echo "        Copy demo/pqcbench to the board and run it there:"; \
		echo ""; \
		echo "            ./pqcbench all $(CYCLE_N) $(CYCLE_REPS)"; \
		echo "            OPENSSL_riscvcap=$(CAP) ./pqcbench all $(CYCLE_N) $(CYCLE_REPS)"; \
		echo ""; \
		echo "        'make count' measures instructions under QEMU."; \
		echo "        'make cycles-qemu' exercises this code path under QEMU,"; \
		echo "        where the numbers are host ticks, not cycles."; \
		exit 1; \
	fi
	@echo "== software path =="
	@OPENSSL_riscvcap=$(NOCAP) ./pqcbench all $(CYCLE_N) $(CYCLE_REPS)
	@echo "== vkeccak path =="
	@OPENSSL_riscvcap=$(CAP) ./pqcbench all $(CYCLE_N) $(CYCLE_REPS)

#	Exercises the same code path under QEMU. The numbers are NOT cycles --
#	qemu answers the counter CSRs from the host cpu's tick counter -- and the
#	counter check at the top of the output says so. For the code path only.
cycles-qemu: pqcbench
	@OPENSSL_riscvcap=$(CAP) $(QEMU) $(QEMUFL) \
		./pqcbench all $(CYCLE_N) $(CYCLE_REPS)

clean:
	$(RM) -f pqcbench

.PHONY: test test-all check count cycles cycles-qemu clean
