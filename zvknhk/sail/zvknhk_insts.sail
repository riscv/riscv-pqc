// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
// Operation listing for vkeccak.vi, included by src/zvknhk.adoc.
// Requires the RISC-V Sail prelude, instruction/execute declarations,
// vregidx, ExecutionResult, vstart, set_vstart, and the fixed-group helpers.
// The standalone definitions in tests/ are test scaffolding only.

// tag::operation[]
type keccak_state = vector(25, bits(64))

function keccak_rc(i : range(0, 23)) -> bits(64) = match i {
   0 => 0x0000000000000001,
   1 => 0x0000000000008082,
   2 => 0x800000000000808A,
   3 => 0x8000000080008000,
   4 => 0x000000000000808B,
   5 => 0x0000000080000001,
   6 => 0x8000000080008081,
   7 => 0x8000000000008009,
   8 => 0x000000000000008A,
   9 => 0x0000000000000088,
  10 => 0x0000000080008009,
  11 => 0x000000008000000A,
  12 => 0x000000008000808B,
  13 => 0x800000000000008B,
  14 => 0x8000000000008089,
  15 => 0x8000000000008003,
  16 => 0x8000000000008002,
  17 => 0x8000000000000080,
  18 => 0x000000000000800A,
  19 => 0x800000008000000A,
  20 => 0x8000000080008081,
  21 => 0x8000000000008080,
  22 => 0x0000000080000001,
  23 => 0x8000000080008008,
}

function keccak_round(input : keccak_state, rc : bits(64)) -> keccak_state = {
  var a = input;
  var b : keccak_state = vector_init(zeros());
  var c : vector(5, bits(64)) = vector_init(zeros());
  var d : vector(5, bits(64)) = vector_init(zeros());

  foreach (x from 0 to 4) {
    c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
  };
  foreach (x from 0 to 4) {
    d[x] = c[(x + 4) % 5] ^ (c[(x + 1) % 5] <<< 1)
  };
  foreach (x from 0 to 4) {
    foreach (y from 0 to 4) {
      a[x + 5 * y] = a[x + 5 * y] ^ d[x]
    }
  };

  // Rho and pi: visit all lanes except (0, 0).
  // The rotation offset is (t + 1) * (t + 2) / 2 modulo 64.
  b[0] = a[0];
  var x : range(0, 4) = 1;
  var y : range(0, 4) = 0;
  var offset : range(0, 63) = 0;
  foreach (t from 0 to 23) {
    let next_x = y;
    let next_y = (2 * x + 3 * y) % 5;
    offset = (offset + t + 1) % 64;
    b[next_x + 5 * next_y] = a[x + 5 * y] <<< offset;
    x = next_x;
    y = next_y
  };

  foreach (x from 0 to 4) {
    foreach (y from 0 to 4) {
      a[x + 5 * y] = b[x + 5 * y] ^
        (~(b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
    }
  };

  a[0] = a[0] ^ rc;
  a
}

function keccak_p(input : keccak_state,
                 first_round : {0, 12}) -> keccak_state = {
  var state = input;
  foreach (round from first_round to 23) {
    state = keccak_round(state, keccak_rc(round))
  };
  state
}

union clause instruction = VKECCAK_VI : (bits(5), vregidx)

function clause execute VKECCAK_VI(imm5, vd) = {
  if unsigned(vstart) != 0 then return Illegal_Instruction();

  let first_round : {0, 12} = match imm5 {
    0b00000 => 0,
    0b00001 => 12,
    _       => return Illegal_Instruction()
  };

  let group = get_fixed_eg(vd);
  var state : keccak_state = vector_init(zeros());
  foreach (i from 0 to 24) {
    state[i] = group[i]
  };

  state = keccak_p(state, first_round);
  foreach (i from 0 to 24) {
    set_fixed_eg_elem(vd, i, state[i])
  };

  set_vstart(zeros());
  RETIRE_SUCCESS
}
// end::operation[]
