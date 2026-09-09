/*
 * SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*
 * vkeccak.vi vd, imm5 -- translation.
 *
 * Zvknhk: vector-immediate multi-round Keccak-p[1600] permutation.
 *
 * Included at the end of target/riscv/tcg/insn_trans/trans_rvvk.c.inc by
 * scripts/apply-qemu-patch.sh. Edit it here, in qemu/trans_vkeccak_vi.c.inc.
 *
 * This does not use GEN_V_UNMASKED_TRANS()/GEN_VI_UNMASKED_TRANS(), the
 * macros the other Zvk instructions share, because both are built around
 * strip-mining: they emit gen_helper_egs_check(), which requires vl to be a
 * multiple of EGS, and they pass VDATA fields (LMUL, VTA, VMA) that have no
 * meaning for an operand whose extent is fixed. zvknhk.adoc makes
 * vkeccak.vi an explicit exception to both rules -- every value of vl is
 * permitted, including 0 -- so the sequence is spelled out instead.
 */

/* Element group width in bits; the group spans NREG = ceil(EGW/VLEN) regs. */
#define ZVKNHK_EGW 2048

static inline uint32_t vkeccak_nreg(DisasContext *s)
{
    uint32_t vlen = s->cfg_ptr->vlenb << 3;

    return (ZVKNHK_EGW + vlen - 1) / vlen;
}

/*
 * Reserved encodings (zvknhk.adoc, "Reserved Encodings"). Everything here is
 * known at translation time, so a reserved encoding simply fails to decode
 * and raises an illegal instruction. vm=0 needs no check: the decode pattern
 * fixes bit 25, so a masked encoding never reaches this function.
 *
 * Deliberately absent, because zvknhk.adoc exempts this instruction from
 * them: require_align(a->rd, s->lmul) -- alignment follows NREG, not LMUL --
 * and MAXSZ(s) >= egw_bytes -- EGS > VLMAX is not reserved here.
 */
static bool vkeccak_vi_check(DisasContext *s, arg_vkeccak_vi *a)
{
    uint32_t nreg = vkeccak_nreg(s);

    return s->cfg_ptr->ext_zvknhk == true &&
           require_rvv(s) &&
           vext_check_isa_ill(s) &&
           s->sew == MO_64 &&                   /* SEW != 64 is reserved     */
           (a->rs2 == 0 || a->rs2 == 1) &&      /* imm5: 0 and 1 are defined */
           (a->rd % nreg) == 0 &&               /* vd is NREG-aligned ...    */
           (a->rd + nreg) <= 32;                /* ... and fits in v0..v31   */
}

static bool trans_vkeccak_vi(DisasContext *s, arg_vkeccak_vi *a)
{
    TCGv_ptr rd_v;

    if (!vkeccak_vi_check(s, a)) {
        return false;
    }

    if (!s->vstart_eq_zero) {
        /*
         * A nonzero vstart is an illegal instruction, raised from the helper.
         * Save the opcode so the exception can be unwound.
         */
        decode_save_opc(s, 0);
    }

    /*
     * Only vd is an operand. The helper walks the fixed element group from
     * this base pointer alone, so it needs neither a descriptor nor vl.
     */
    rd_v = tcg_temp_new_ptr();
    tcg_gen_addi_ptr(rd_v, tcg_env, vreg_ofs(s, a->rd));
    gen_helper_vkeccak_vi(rd_v, tcg_env, tcg_constant_i32(a->rs2));
    finalize_rvv_inst(s);

    return true;
}
