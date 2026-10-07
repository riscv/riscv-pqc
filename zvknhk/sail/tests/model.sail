// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
// Standalone vector register file for the operation listing. The first 512
// 64-bit words cover eight element groups at VLEN=4096, LMUL=8.

newtype vregidx = Vregidx : bits(5)

scattered union instruction

union ExecutionResult = {
  Retire_Success      : unit,
  Illegal_Instruction : unit,
}

let RETIRE_SUCCESS : ExecutionResult = Retire_Success()

val execute : instruction -> ExecutionResult
scattered function execute

register VLEN : int
register vill : bool
register SEW : int
register test_lmul_pow : int
register vl : bits(64)
register vstart : bits(64)
register vregs : vector(512, bits(64))

function valid_vtype() -> bool = not(vill)
function get_sew() -> int = SEW
function get_lmul_pow() -> int = test_lmul_pow

function vregidx_bits(vd : vregidx) -> bits(5) = match vd {
  Vregidx(n) => n
}

function get_eg_elem(vd : vregidx, i : int) -> bits(64) = {
  let index = unsigned(vregidx_bits(vd)) * ediv_int(VLEN, 64) + i;
  if index >= 0 then if index < 512 then vregs[index] else zeros()
  else zeros()
}

function set_eg_elem(vd : vregidx, i : int, value : bits(64)) -> unit = {
  let index = unsigned(vregidx_bits(vd)) * ediv_int(VLEN, 64) + i;
  if index >= 0 then if index < 512 then vregs[index] = value
}

function set_vstart(value : bits(16)) -> unit =
  vstart = sail_zero_extend(value, 64)
