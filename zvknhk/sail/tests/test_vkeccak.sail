// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
// All-zero Keccak-p[1600,24] and Keccak-p[1600,12] known answers from
// ../../test/system/boot.c, plus checks of the instruction wrapper.

function test_execute(imm5 : bits(5), expected : keccak_state) -> unit = {
  foreach (i from 0 to 31) {
    fixed_eg[i] = if i < 25 then zeros() else 0xA5A5A5A500000000 + i
  };
  vstart = zeros();

  assert(execute(VKECCAK_VI(imm5, Vregidx(0b00000))) == Retire_Success());
  foreach (i from 0 to 24) {
    assert(fixed_eg[i] == expected[i], "incorrect state word")
  };
  foreach (i from 25 to 31) {
    assert(fixed_eg[i] == 0xA5A5A5A500000000 + i, "state tail changed")
  };
  assert(unsigned(vstart) == 0)
}

function test_illegal(imm5 : bits(5), start : bits(64)) -> unit = {
  foreach (i from 0 to 31) {
    fixed_eg[i] = 0x0123456789ABC000 + i
  };
  let before = fixed_eg;
  vstart = start;

  assert(execute(VKECCAK_VI(imm5, Vregidx(0b00000))) == Illegal_Instruction());
  foreach (i from 0 to 31) {
    assert(fixed_eg[i] == before[i], "illegal instruction changed the group")
  };
  assert(vstart == start, "illegal instruction changed vstart")
}

function main() -> unit = {
  let zero : keccak_state = vector_init(zeros());
  let out24 = keccak_p(zero, 0);
  assert(out24[ 0] == 0xF1258F7940E1DDE7);
  assert(out24[ 1] == 0x84D5CCF933C0478A);
  assert(out24[ 2] == 0xD598261EA65AA9EE);
  assert(out24[ 3] == 0xBD1547306F80494D);
  assert(out24[ 4] == 0x8B284E056253D057);
  assert(out24[ 5] == 0xFF97A42D7F8E6FD4);
  assert(out24[ 6] == 0x90FEE5A0A44647C4);
  assert(out24[ 7] == 0x8C5BDA0CD6192E76);
  assert(out24[ 8] == 0xAD30A6F71B19059C);
  assert(out24[ 9] == 0x30935AB7D08FFC64);
  assert(out24[10] == 0xEB5AA93F2317D635);
  assert(out24[11] == 0xA9A6E6260D712103);
  assert(out24[12] == 0x81A57C16DBCF555F);
  assert(out24[13] == 0x43B831CD0347C826);
  assert(out24[14] == 0x01F22F1A11A5569F);
  assert(out24[15] == 0x05E5635A21D9AE61);
  assert(out24[16] == 0x64BEFEF28CC970F2);
  assert(out24[17] == 0x613670957BC46611);
  assert(out24[18] == 0xB87C5A554FD00ECB);
  assert(out24[19] == 0x8C3EE88A1CCF32C8);
  assert(out24[20] == 0x940C7922AE3A2614);
  assert(out24[21] == 0x1841F924A2C509E4);
  assert(out24[22] == 0x16F53526E70465C2);
  assert(out24[23] == 0x75F644E97F30A13B);
  assert(out24[24] == 0xEAF1FF7B5CECA249);

  let out12 = keccak_p(zero, 12);
  assert(out12[ 0] == 0x8E5E5438B9A78617);
  assert(out12[ 1] == 0xD9CD6A50F259D01E);
  assert(out12[ 2] == 0x87B8E7C652A91F35);
  assert(out12[ 3] == 0x1093E067CDE4E0C5);
  assert(out12[ 4] == 0xB033AB90F2D95A45);
  assert(out12[ 5] == 0xE0A72F72A8DD1A45);
  assert(out12[ 6] == 0xC53780AA14672F9C);
  assert(out12[ 7] == 0x3EDD47F50051071D);
  assert(out12[ 8] == 0xB3A31D310C178ACC);
  assert(out12[ 9] == 0x79B586A59257AAA0);
  assert(out12[10] == 0xBC4A7C3DB3B1F99B);
  assert(out12[11] == 0x68874063E68A6793);
  assert(out12[12] == 0x5C6C03332E0E2566);
  assert(out12[13] == 0x9CAA1202B9F030DA);
  assert(out12[14] == 0x5F3B9A782BCF7A9F);
  assert(out12[15] == 0xE536C1E061AE7923);
  assert(out12[16] == 0x6DE9B618B73C87EC);
  assert(out12[17] == 0x2ABED1F170918AC2);
  assert(out12[18] == 0x6AABBD53DAED24B7);
  assert(out12[19] == 0xBFC1416A2C2EE15A);
  assert(out12[20] == 0xC6CFE036B90952AF);
  assert(out12[21] == 0x45503617DC7060D7);
  assert(out12[22] == 0x625611B2C29F7AE4);
  assert(out12[23] == 0xD43671DB2C30647A);
  assert(out12[24] == 0xCFFD0D76222CA01C);

  test_execute(0b00000, out24);
  print_endline("PASS: Keccak-p[1600,24], all 25 words and all 7 tail words");
  test_execute(0b00001, out12);
  print_endline("PASS: Keccak-p[1600,12], all 25 words and all 7 tail words");

  var imm5 : bits(5) = 0b00010;
  foreach (i from 2 to 31) {
    test_illegal(imm5, 0x0000000000000000);
    imm5 = imm5 + 1
  };
  print_endline("PASS: all 30 reserved immediates, no state changes");

  test_illegal(0b00000, 0x0000000000000001);
  test_illegal(0b00001, 0x0000000000000001);
  test_illegal(0b00000, 0x0000000000000020);
  test_illegal(0b00001, 0x0000000000000020);
  test_illegal(0b00000, 0xFFFFFFFFFFFFFFFF);
  test_illegal(0b00001, 0xFFFFFFFFFFFFFFFF);
  print_endline("PASS: nonzero vstart for both round counts, no state changes")
}
