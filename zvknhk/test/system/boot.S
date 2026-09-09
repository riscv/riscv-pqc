# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
#	boot.S -- entry for the system-mode Zvknhk smoke test.
#
#	QEMU's virt machine enters here in M-mode with -bios none -kernel.

	.section .text.init,"ax",@progbits
	.globl _start
_start:
	li	t0, (1 << 9)		# mstatus.VS = Initial: enable the vector unit
	csrs	mstatus, t0
	la	sp, _stack_top
	call	boot_main		# returns a failure count in a0

	#	Exit through the SiFive test finisher at 0x100000:
	#	0x5555 = pass, 0x3333 | (code << 16) = fail.
	li	t0, 0x100000
	beqz	a0, 1f
	slli	a0, a0, 16
	li	t1, 0x3333
	or	a0, a0, t1
	sw	a0, 0(t0)
1:	li	t1, 0x5555
	sw	t1, 0(t0)
2:	j	2b
