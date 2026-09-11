// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
// Minimal execution environment for the operation listing. It represents
// one logical fixed group at vd=v0, not a complete vector register file.

newtype vregidx = Vregidx : bits(5)

scattered union instruction

union ExecutionResult = {
  Retire_Success      : unit,
  Illegal_Instruction : unit,
}

let RETIRE_SUCCESS : ExecutionResult = Retire_Success()

val execute : instruction -> ExecutionResult
scattered function execute

register vstart : bits(64)
register fixed_eg : vector(32, bits(64))

function get_fixed_eg(vd : vregidx) -> vector(32, bits(64)) = {
  assert(vd == Vregidx(0b00000));
  fixed_eg
}

function set_fixed_eg_elem(vd : vregidx, i : range(0, 24),
                          value : bits(64)) -> unit = {
  assert(vd == Vregidx(0b00000));
  fixed_eg[i] = value
}

function set_vstart(value : bits(16)) -> unit =
  vstart = sail_zero_extend(value, 64)
