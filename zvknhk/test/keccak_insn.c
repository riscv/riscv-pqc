// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
//  keccak_insn.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>. Credit: Nicolas Brunie.
//  === Single-instruction Keccak-p[1600]

#include "plat_local.h"

//  The assembler does not know `vkeccak.vi` yet, so the instruction is emitted
//  with `.insn`. Only two of the five R-type fields are real operands; see
//  the Encoding section of zvknhk.adoc:
//
//      rd  = vd    -- the vector register holding the 1600-bit state
//      rs1 = x18   -- NOT an operand: 0b10010 is a fixed part of the opcode
//      rs2 = imm5  -- the round-count selector: 0 -> 24 rounds, 1 -> 12 rounds
//
//  At VLEN>=256 the instruction uses ordinary LMUL groups. We use LMUL=8,
//  vd=v0 and vl=32 for exactly one 2048-bit element group. At VLEN=128 it
//  uses the fixed 16-register group and ignores vl.
//
//  The surrounding vle64/vse64 move only the 25 active state words. At
//  LMUL=8 the largest usable vl is VLMAX = 8*VLEN/64, which
//  is >= 25 for VLEN >= 256 but only 16 at VLEN=128 -- so there the transfer
//  is split in two: elements 0..15 into v0..v7, then 16..24 into v8..v12.
//  Both halves stay inside the 16-register group that vd=v0 spans at VLEN=128.

#define KECCAK_INSN(name, imm5)                                     \
void name(void *state)                                              \
{                                                                   \
    if (rv_get_vlenb() >= 32) {         /*  VLEN >= 256  */         \
        __asm volatile (                                            \
            "vsetivli x0, 25, e64, m8, tu, mu\n"                    \
            "vle64.v v0, 0(%[s])\n"                                 \
            /*  vkeccak.vi v0, imm5                              */  \
            /*  .insn r opc, func3, func7, rd, rs1, rs2          */  \
            "li t0, 32\n"                                          \
            "vsetvli x0, t0, e64, m8, tu, mu\n"                    \
            ".insn r 0x77, 0x2, 0x53, x0, x18, " imm5 "\n"          \
            "vsetivli x0, 25, e64, m8, tu, mu\n"                    \
            "vse64.v v0, 0(%[s])\n"                                 \
            :                                                       \
            : [s]"r"(state)                                         \
            : "memory", "t0"                                        \
        );                                                          \
    } else {                            /*  VLEN == 128  */         \
        void *hi = (void *) ((char *) state + 16 * 8);              \
        __asm volatile (                                            \
            "vsetivli x0, 16, e64, m8, tu, mu\n"                    \
            "vle64.v v0, 0(%[s])\n"                                 \
            "vsetivli x0, 9, e64, m8, tu, mu\n"                     \
            "vle64.v v8, 0(%[h])\n"                                 \
            ".insn r 0x77, 0x2, 0x53, x0, x18, " imm5 "\n"          \
            "vsetivli x0, 16, e64, m8, tu, mu\n"                    \
            "vse64.v v0, 0(%[s])\n"                                 \
            "vsetivli x0, 9, e64, m8, tu, mu\n"                     \
            "vse64.v v8, 0(%[h])\n"                                 \
            :                                                       \
            : [s]"r"(state), [h]"r"(hi)                             \
            : "memory"                                              \
        );                                                          \
    }                                                               \
}

//  Keccak-p[1600,24] = Keccak-f[1600]; used by SHA-3 and SHAKE.
KECCAK_INSN(keccak_f1600, "x0")

//  Keccak-p[1600,12]; used by TurboSHAKE and KangarooTwelve. Uses round
//  constants RC[12..23], which the instruction selects on its own.
KECCAK_INSN(keccak_p1600_12, "x1")
