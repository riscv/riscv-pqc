/*
 * SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*
 * vkeccak.vi vd, imm5
 *
 * Zvknhk: vector-immediate multi-round Keccak-p[1600] permutation.
 *
 * Included at the end of target/riscv/tcg/vcrypto_helper.c by
 * scripts/apply-qemu-patch.sh. Edit it here, in qemu/vkeccak_vi.c.inc.
 *
 * This follows the normative definition in zvknhk.adoc. The round body below
 * is character-for-character the one in spike/vkeccak_vi.h, so the two
 * reference implementations cannot drift apart.
 *
 * Points where this deliberately differs from an ordinary vector-crypto
 * helper, and why none of QEMU's vext scaffolding is used:
 *
 *   - The state is ONE fixed element group designated by 'vd', with
 *     EMUL = NREG = ceil(EGW/VLEN), independent of vl and LMUL. It is not
 *     strip-mined, so there is no loop over element groups, no
 *     vext_get_total_elems()/vext_vta() tail handling, and no
 *     VSTART_CHECK_EARLY_EXIT() -- that macro treats vstart >= vl as a
 *     completed instruction, which is wrong for an operation that ignores vl.
 *   - QEMU lays the vector register file out as one flat, contiguous byte
 *     array, so element i of the group is simply vd[i]: byte offset i*8 lands
 *     in register vd + floor(i*8/vlenb) at element position i mod (vlenb/8),
 *     which is exactly the layout the specification defines for the
 *     concatenated registers. Nothing here needs to know NREG.
 *   - Elements 25..31 (the state tail) and every bit outside the fixed group
 *     are simply never written. The state tail is not the architectural
 *     vector tail, so vta does not apply to it.
 *
 * The reserved encodings that are static in vtype -- SEW != 64, a reserved
 * imm5, a misaligned or out-of-range vd -- are rejected at translation time
 * in trans_vkeccak_vi.c.inc; vm=0 simply does not match the decode pattern.
 * Only vstart is dynamic, so only vstart is checked here.
 */

#define KECCAK_ROL(data, amt)  (((data) << (amt)) | ((data) >> (64 - (amt))))

/* Round constants for the iota step (FIPS 202, Sec. 3.2.5). */
static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, /* RC[0],  RC[1]  */
    0x800000000000808AULL, 0x8000000080008000ULL, /* RC[2],  RC[3]  */
    0x000000000000808BULL, 0x0000000080000001ULL, /* RC[4],  RC[5]  */
    0x8000000080008081ULL, 0x8000000000008009ULL, /* RC[6],  RC[7]  */
    0x000000000000008AULL, 0x0000000000000088ULL, /* RC[8],  RC[9]  */
    0x0000000080008009ULL, 0x000000008000000AULL, /* RC[10], RC[11] */
    0x000000008000808BULL, 0x800000000000008BULL, /* RC[12], RC[13] */
    0x8000000000008089ULL, 0x8000000000008003ULL, /* RC[14], RC[15] */
    0x8000000000008002ULL, 0x8000000000000080ULL, /* RC[16], RC[17] */
    0x000000000000800AULL, 0x800000008000000AULL, /* RC[18], RC[19] */
    0x8000000080008081ULL, 0x8000000000008080ULL, /* RC[20], RC[21] */
    0x0000000080000001ULL, 0x8000000080008008ULL, /* RC[22], RC[23] */
};

void HELPER(vkeccak_vi)(void *vd_vptr, CPURISCVState *env, uint32_t imm5)
{
    uint64_t *vd = vd_vptr;
    uint32_t roundCnt, rc_offset;

    /*
     * The permutation is not element-restartable: a nonzero vstart is an
     * illegal instruction rather than a resumption point.
     */
    if (env->vstart != 0) {
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }

    /*
     * imm5 selects the round count: 0 -> 24 rounds (Keccak-f[1600]),
     * 1 -> 12 rounds. Keccak-p[1600, roundCnt] uses round constants
     * RC[24 - roundCnt] .. RC[23]. Every other imm5 is reserved and was
     * already rejected at translation time.
     */
    roundCnt = (imm5 == 0) ? 24 : 12;
    rc_offset = 24 - roundCnt;

    /*
     * Read the 25 active state words of the fixed group. H8() is the identity
     * on both host endiannesses; it is spelled out for consistency with the
     * rest of the vector helpers.
     */
#define VKECCAK_A(x, y) (vd[H8((x) + 5 * (y))])

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

    /*
     * The permutation itself. Carried over verbatim from the original
     * implementation by Nicolas Brunie, and identical to the round body in
     * spike/vkeccak_vi.h. It is equivalent to the Sail operation in
     * sail/zvknhk_insts.sail.
     */
    for (uint32_t ridx = 0; ridx < roundCnt; ++ridx) {

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

    /* Write back only the 25 state elements; 25..31 remain untouched. */

    VKECCAK_A(0, 0) = A_0_0;
    VKECCAK_A(0, 1) = A_0_1;
    VKECCAK_A(0, 2) = A_0_2;
    VKECCAK_A(0, 3) = A_0_3;
    VKECCAK_A(0, 4) = A_0_4;
    VKECCAK_A(1, 0) = A_1_0;
    VKECCAK_A(1, 1) = A_1_1;
    VKECCAK_A(1, 2) = A_1_2;
    VKECCAK_A(1, 3) = A_1_3;
    VKECCAK_A(1, 4) = A_1_4;
    VKECCAK_A(2, 0) = A_2_0;
    VKECCAK_A(2, 1) = A_2_1;
    VKECCAK_A(2, 2) = A_2_2;
    VKECCAK_A(2, 3) = A_2_3;
    VKECCAK_A(2, 4) = A_2_4;
    VKECCAK_A(3, 0) = A_3_0;
    VKECCAK_A(3, 1) = A_3_1;
    VKECCAK_A(3, 2) = A_3_2;
    VKECCAK_A(3, 3) = A_3_3;
    VKECCAK_A(3, 4) = A_3_4;
    VKECCAK_A(4, 0) = A_4_0;
    VKECCAK_A(4, 1) = A_4_1;
    VKECCAK_A(4, 2) = A_4_2;
    VKECCAK_A(4, 3) = A_4_3;
    VKECCAK_A(4, 4) = A_4_4;

    env->vstart = 0;

#undef VKECCAK_A
}

#undef KECCAK_ROL
