// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
// vkeccak.vi vd, imm5
//
// Zvknhk: vector-immediate multi-round Keccak-p[1600] permutation.
//
// Each 2048-bit element group contains a 1600-bit state and seven untouched
// state-tail words. VLEN=128 uses the specification's fixed 16-register group.
// imm5 is a selector in the vs2 field, not a literal round count.

#define KECCAK_ROL(data, amt)  (((data) << (amt)) | ((data) >> (64 - (amt))))

// Round constants for the iota step (FIPS 202, Sec. 3.2.5).
static constexpr uint64_t KECCAK_RC[24] = {

    0x0000000000000001, // RC[0]
    0x0000000000008082, // RC[1]
    0x800000000000808A, // RC[2]
    0x8000000080008000, // RC[3]
    0x000000000000808B, // RC[4]
    0x0000000080000001, // RC[5]
    0x8000000080008081, // RC[6]
    0x8000000000008009, // RC[7]
    0x000000000000008A, // RC[8]
    0x0000000000000088, // RC[9]
    0x0000000080008009, // RC[10]
    0x000000008000000A, // RC[11]
    0x000000008000808B, // RC[12]
    0x800000000000008B, // RC[13]
    0x8000000000008089, // RC[14]
    0x8000000000008003, // RC[15]
    0x8000000000008002, // RC[16]
    0x8000000000000080, // RC[17]
    0x000000000000800A, // RC[18]
    0x800000008000000A, // RC[19]
    0x8000000080008081, // RC[20]
    0x8000000000008080, // RC[21]
    0x0000000080000001, // RC[22]
    0x8000000080008008, // RC[23]
};

// Reserved encodings (zvknhk.adoc, "Reserved Encodings").
// This instruction restarts at element-group boundaries even when Spike's
// generic ALU vstart option is disabled.
require_vector_vs;
require(!P.VU.vill);
WRITE_VSTATUS;
require_extension(EXT_ZVKNHK);
require(P.VU.vsew == 64);             // SEW other than 64 is reserved
require(insn.v_vm() == 1);            // vm=0 is reserved

const reg_t vd_num = insn.rd();
const bool fixed_group = P.VU.VLEN == 128;
const reg_t start = P.VU.vstart->read();
const reg_t vl = P.VU.vl->read();
if (fixed_group) {
  require_align(vd_num, 16);
  require(start == 0);
} else {
  require(P.VU.VLEN * P.VU.vflmul >= 2048);
  require_align(vd_num, P.VU.vflmul);
  require(vl % 32 == 0);
  require(start % 32 == 0);
}

// imm5 selects the round count: 0 -> 24 rounds (Keccak-f[1600]),
// 1 -> 12 rounds. Every other value is reserved. Keccak-p[1600, roundCnt]
// uses round constants RC[24 - roundCnt] .. RC[23].
const reg_t vkeccak_imm5 = insn.rs2();
require(vkeccak_imm5 == 0 || vkeccak_imm5 == 1);
const std::size_t roundCnt = (vkeccak_imm5 == 0) ? 24 : 12;
const std::size_t rc_offset = 24 - roundCnt;

// A group is 32 SEW=64 elements. elt() crosses vector-register boundaries.
const reg_t first_group = fixed_group ? 0 : start / 32;
const reg_t group_count = fixed_group ? 1 : vl / 32;
for (reg_t group = first_group; group < group_count; ++group) {
const reg_t base = group * 32;
#define VKECCAK_A(x, y) (P.VU.elt<uint64_t>(vd_num, base + (x) + 5 * (y)))
#define VKECCAK_WRITE(x, y) (P.VU.elt<uint64_t>(vd_num, base + (x) + 5 * (y), true))

uint64_t A_0_0 = VKECCAK_A(0, 0);
uint64_t A_0_1 = VKECCAK_A(0, 1);
uint64_t A_0_2 = VKECCAK_A(0, 2);
uint64_t A_0_3 = VKECCAK_A(0, 3);
uint64_t A_0_4 = VKECCAK_A(0, 4);
uint64_t A_1_0 = VKECCAK_A(1, 0);
uint64_t A_1_1 = VKECCAK_A(1, 1);
uint64_t A_1_2 = VKECCAK_A(1, 2);
uint64_t A_1_3 = VKECCAK_A(1, 3);
uint64_t A_1_4 = VKECCAK_A(1, 4);
uint64_t A_2_0 = VKECCAK_A(2, 0);
uint64_t A_2_1 = VKECCAK_A(2, 1);
uint64_t A_2_2 = VKECCAK_A(2, 2);
uint64_t A_2_3 = VKECCAK_A(2, 3);
uint64_t A_2_4 = VKECCAK_A(2, 4);
uint64_t A_3_0 = VKECCAK_A(3, 0);
uint64_t A_3_1 = VKECCAK_A(3, 1);
uint64_t A_3_2 = VKECCAK_A(3, 2);
uint64_t A_3_3 = VKECCAK_A(3, 3);
uint64_t A_3_4 = VKECCAK_A(3, 4);
uint64_t A_4_0 = VKECCAK_A(4, 0);
uint64_t A_4_1 = VKECCAK_A(4, 1);
uint64_t A_4_2 = VKECCAK_A(4, 2);
uint64_t A_4_3 = VKECCAK_A(4, 3);
uint64_t A_4_4 = VKECCAK_A(4, 4);

// The permutation itself. This round body is carried over verbatim from the
// original implementation by Nicolas Brunie, and is equivalent to the Sail
// operation in sail/zvknhk_insts.sail.
for (std::size_t ridx = 0; ridx < roundCnt; ++ridx) {

        uint64_t C_0= A_0_0 ^ A_0_1 ^ A_0_2 ^ A_0_3 ^ A_0_4;
        uint64_t C_1= A_1_0 ^ A_1_1 ^ A_1_2 ^ A_1_3 ^ A_1_4;
        uint64_t C_2= A_2_0 ^ A_2_1 ^ A_2_2 ^ A_2_3 ^ A_2_4;
        uint64_t C_3= A_3_0 ^ A_3_1 ^ A_3_2 ^ A_3_3 ^ A_3_4;
        uint64_t C_4= A_4_0 ^ A_4_1 ^ A_4_2 ^ A_4_3 ^ A_4_4;
        uint64_t D_0 = C_4 ^ KECCAK_ROL(C_1,1);
        A_0_0 ^= D_0;
        A_0_1 ^= D_0;
        A_0_2 ^= D_0;
        A_0_3 ^= D_0;
        A_0_4 ^= D_0;
        uint64_t D_1 = C_0 ^ KECCAK_ROL(C_2,1);
        A_1_0 ^= D_1;
        A_1_1 ^= D_1;
        A_1_2 ^= D_1;
        A_1_3 ^= D_1;
        A_1_4 ^= D_1;
        uint64_t D_2 = C_1 ^ KECCAK_ROL(C_3,1);
        A_2_0 ^= D_2;
        A_2_1 ^= D_2;
        A_2_2 ^= D_2;
        A_2_3 ^= D_2;
        A_2_4 ^= D_2;
        uint64_t D_3 = C_2 ^ KECCAK_ROL(C_4,1);
        A_3_0 ^= D_3;
        A_3_1 ^= D_3;
        A_3_2 ^= D_3;
        A_3_3 ^= D_3;
        A_3_4 ^= D_3;
        uint64_t D_4 = C_3 ^ KECCAK_ROL(C_0,1);
        A_4_0 ^= D_4;
        A_4_1 ^= D_4;
        A_4_2 ^= D_4;
        A_4_3 ^= D_4;
        A_4_4 ^= D_4;
        uint64_t T_0 = A_1_0;
        uint64_t T_1 = A_0_2;
        A_0_2 = KECCAK_ROL(T_0, 1);
        uint64_t T_2 = A_2_1;
        A_2_1 = KECCAK_ROL(T_1, 3);
        uint64_t T_3 = A_1_2;
        A_1_2 = KECCAK_ROL(T_2, 6);
        uint64_t T_4 = A_2_3;
        A_2_3 = KECCAK_ROL(T_3, 10);
        uint64_t T_5 = A_3_3;
        A_3_3 = KECCAK_ROL(T_4, 15);
        uint64_t T_6 = A_3_0;
        A_3_0 = KECCAK_ROL(T_5, 21);
        uint64_t T_7 = A_0_1;
        A_0_1 = KECCAK_ROL(T_6, 28);
        uint64_t T_8 = A_1_3;
        A_1_3 = KECCAK_ROL(T_7, 36);
        uint64_t T_9 = A_3_1;
        A_3_1 = KECCAK_ROL(T_8, 45);
        uint64_t T_10 = A_1_4;
        A_1_4 = KECCAK_ROL(T_9, 55);
        uint64_t T_11 = A_4_4;
        A_4_4 = KECCAK_ROL(T_10, 2);
        uint64_t T_12 = A_4_0;
        A_4_0 = KECCAK_ROL(T_11, 14);
        uint64_t T_13 = A_0_3;
        A_0_3 = KECCAK_ROL(T_12, 27);
        uint64_t T_14 = A_3_4;
        A_3_4 = KECCAK_ROL(T_13, 41);
        uint64_t T_15 = A_4_3;
        A_4_3 = KECCAK_ROL(T_14, 56);
        uint64_t T_16 = A_3_2;
        A_3_2 = KECCAK_ROL(T_15, 8);
        uint64_t T_17 = A_2_2;
        A_2_2 = KECCAK_ROL(T_16, 25);
        uint64_t T_18 = A_2_0;
        A_2_0 = KECCAK_ROL(T_17, 43);
        uint64_t T_19 = A_0_4;
        A_0_4 = KECCAK_ROL(T_18, 62);
        uint64_t T_20 = A_4_2;
        A_4_2 = KECCAK_ROL(T_19, 18);
        uint64_t T_21 = A_2_4;
        A_2_4 = KECCAK_ROL(T_20, 39);
        uint64_t T_22 = A_4_1;
        A_4_1 = KECCAK_ROL(T_21, 61);
        uint64_t T_23 = A_1_1;
        A_1_1 = KECCAK_ROL(T_22, 20);
        A_1_0 = KECCAK_ROL(T_23, 44);
        uint64_t C_0_0 = A_0_0;
        uint64_t C_0_1 = A_1_0;
        uint64_t C_0_2 = A_2_0;
        uint64_t C_0_3 = A_3_0;
        uint64_t C_0_4 = A_4_0;
        A_0_0 = C_0_0 ^ (~C_0_1 & C_0_2);
        A_1_0 = C_0_1 ^ (~C_0_2 & C_0_3);
        A_2_0 = C_0_2 ^ (~C_0_3 & C_0_4);
        A_3_0 = C_0_3 ^ (~C_0_4 & C_0_0);
        A_4_0 = C_0_4 ^ (~C_0_0 & C_0_1);
        uint64_t C_1_0 = A_0_1;
        uint64_t C_1_1 = A_1_1;
        uint64_t C_1_2 = A_2_1;
        uint64_t C_1_3 = A_3_1;
        uint64_t C_1_4 = A_4_1;
        A_0_1 = C_1_0 ^ (~C_1_1 & C_1_2);
        A_1_1 = C_1_1 ^ (~C_1_2 & C_1_3);
        A_2_1 = C_1_2 ^ (~C_1_3 & C_1_4);
        A_3_1 = C_1_3 ^ (~C_1_4 & C_1_0);
        A_4_1 = C_1_4 ^ (~C_1_0 & C_1_1);
        uint64_t C_2_0 = A_0_2;
        uint64_t C_2_1 = A_1_2;
        uint64_t C_2_2 = A_2_2;
        uint64_t C_2_3 = A_3_2;
        uint64_t C_2_4 = A_4_2;
        A_0_2 = C_2_0 ^ (~C_2_1 & C_2_2);
        A_1_2 = C_2_1 ^ (~C_2_2 & C_2_3);
        A_2_2 = C_2_2 ^ (~C_2_3 & C_2_4);
        A_3_2 = C_2_3 ^ (~C_2_4 & C_2_0);
        A_4_2 = C_2_4 ^ (~C_2_0 & C_2_1);
        uint64_t C_3_0 = A_0_3;
        uint64_t C_3_1 = A_1_3;
        uint64_t C_3_2 = A_2_3;
        uint64_t C_3_3 = A_3_3;
        uint64_t C_3_4 = A_4_3;
        A_0_3 = C_3_0 ^ (~C_3_1 & C_3_2);
        A_1_3 = C_3_1 ^ (~C_3_2 & C_3_3);
        A_2_3 = C_3_2 ^ (~C_3_3 & C_3_4);
        A_3_3 = C_3_3 ^ (~C_3_4 & C_3_0);
        A_4_3 = C_3_4 ^ (~C_3_0 & C_3_1);
        uint64_t C_4_0 = A_0_4;
        uint64_t C_4_1 = A_1_4;
        uint64_t C_4_2 = A_2_4;
        uint64_t C_4_3 = A_3_4;
        uint64_t C_4_4 = A_4_4;
        A_0_4 = C_4_0 ^ (~C_4_1 & C_4_2);
        A_1_4 = C_4_1 ^ (~C_4_2 & C_4_3);
        A_2_4 = C_4_2 ^ (~C_4_3 & C_4_4);
        A_3_4 = C_4_3 ^ (~C_4_4 & C_4_0);
        A_4_4 = C_4_4 ^ (~C_4_0 & C_4_1);
        /*iota*/
        A_0_0 ^= KECCAK_RC[rc_offset + ridx];
}

// Write back only the 25 state elements; 25..31 remain untouched.

VKECCAK_WRITE(0, 0) = A_0_0;
VKECCAK_WRITE(0, 1) = A_0_1;
VKECCAK_WRITE(0, 2) = A_0_2;
VKECCAK_WRITE(0, 3) = A_0_3;
VKECCAK_WRITE(0, 4) = A_0_4;
VKECCAK_WRITE(1, 0) = A_1_0;
VKECCAK_WRITE(1, 1) = A_1_1;
VKECCAK_WRITE(1, 2) = A_1_2;
VKECCAK_WRITE(1, 3) = A_1_3;
VKECCAK_WRITE(1, 4) = A_1_4;
VKECCAK_WRITE(2, 0) = A_2_0;
VKECCAK_WRITE(2, 1) = A_2_1;
VKECCAK_WRITE(2, 2) = A_2_2;
VKECCAK_WRITE(2, 3) = A_2_3;
VKECCAK_WRITE(2, 4) = A_2_4;
VKECCAK_WRITE(3, 0) = A_3_0;
VKECCAK_WRITE(3, 1) = A_3_1;
VKECCAK_WRITE(3, 2) = A_3_2;
VKECCAK_WRITE(3, 3) = A_3_3;
VKECCAK_WRITE(3, 4) = A_3_4;
VKECCAK_WRITE(4, 0) = A_4_0;
VKECCAK_WRITE(4, 1) = A_4_1;
VKECCAK_WRITE(4, 2) = A_4_2;
VKECCAK_WRITE(4, 3) = A_4_3;
VKECCAK_WRITE(4, 4) = A_4_4;

#undef VKECCAK_A
#undef VKECCAK_WRITE
}
P.VU.vstart->write(0);
#undef KECCAK_ROL
