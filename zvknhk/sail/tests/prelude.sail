// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
// Standalone subset of the RISC-V prelude interfaces used by this test.
// Uses only libraries installed with Sail; no sail-riscv checkout is needed.

default Order dec

$include <prelude.sail>
$include <smt.sail>
$include <generic_equality.sail>

overload operator ^ = {xor_vec}
overload ~ = {not_vec}

// All operands of % in the operation are nonnegative, as in sail-riscv.
overload operator % = {emod_int}

val zeros : forall 'n, 'n >= 0. implicit('n) -> bits('n)
function zeros(n) = sail_zeros(n)

// The operation uses the RISC-V model's <<< operator on 64-bit words.
function test_rotl64(value : bits(64), shift : range(0, 63)) -> bits(64) =
  sail_shiftleft(value, shift) | sail_shiftright(value, 64 - shift)

infix 7 <<<
overload operator <<< = {test_rotl64}
