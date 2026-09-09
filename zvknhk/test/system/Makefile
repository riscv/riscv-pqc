# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
#	Makefile -- Zvknhk system-mode smoke test
#
#	Builds a freestanding payload for the QEMU 'virt' machine and boots it
#	under qemu-system-riscv64. This is the full-system counterpart to the
#	Linux-user suite in ../: same instruction, no proxy kernel, the vector
#	unit enabled by the payload itself in M-mode.

BOOTBIN	=	boot.elf
CC		=	riscv64-unknown-linux-gnu-gcc

#	Freestanding: no libc, no startup files, and position-dependent at the
#	address the linker script names.
CFLAGS	=	-march=rv64gcv_zvl128b -mabi=lp64d -mcmodel=medany \
			-nostdlib -nostartfiles -ffreestanding -O2 -Wall \
			-Wl,--no-warn-rwx-segments

#	QEMU built by `make qemu` in zvknhk/; override to use another build.
QEMU	?=	../../qemu-src/build/qemu-system-riscv64

VLEN	?=	256
VLENS	=	128 256 512 1024

#	-bios none: the payload is the whole software stack, loaded at 0x80000000
#	and entered in M-mode. -nographic wires the 16550 UART to stdout.
QEMUFL	=	-M virt -bios none -nographic \
			-cpu rv64,v=true,vlen=$(VLEN),elen=64,zvknhk=true \
			-kernel $(BOOTBIN)

boot:	$(BOOTBIN)
	$(QEMU) $(QEMUFL)

#	Boot at every VLEN QEMU supports. The payload exits through the SiFive
#	test finisher, so QEMU's exit status is the verdict: 0 for pass, 1 for a
#	nonzero failure count.
boot-all: $(BOOTBIN)
	@rc=0; \
	for v in $(VLENS); do \
		out=`$(QEMU) -M virt -bios none -nographic \
			-cpu rv64,v=true,vlen=$${v},elen=64,zvknhk=true \
			-kernel $(BOOTBIN) 2>&1`; \
		st=$$?; \
		ran=`printf '%s\n' "$$out" | grep -c '^\[PASS\]'`; \
		if [ $$st -ne 0 ]; then \
			echo "VLEN=$$v FAIL: qemu exited $$st"; rc=1; \
		elif [ $$ran -ne 2 ]; then \
			echo "VLEN=$$v FAIL: $$ran of 2 checks passed"; rc=1; \
		else \
			echo "VLEN=$$v ok: $$ran checks"; \
		fi; \
	done; \
	[ $$rc -eq 0 ] || echo "boot-all: FAILED"; \
	exit $$rc

$(BOOTBIN): boot.S boot.c boot.ld Makefile
	$(CC) $(CFLAGS) -T boot.ld -o $(BOOTBIN) boot.S boot.c

clean:
	$(RM) -f $(BOOTBIN)
