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
 * The VLEN=128 exception uses a fixed 16-register group; larger VLENs use
 * ordinary vector groups. The helper handles the dynamic vl/vstart checks.
 */

static bool vkeccak_vi_check(DisasContext *s, arg_vkeccak_vi *a)
{
    bool fixed_group = s->cfg_ptr->vlenb == 16;

    return s->cfg_ptr->ext_zvknhk == true &&
           require_rvv(s) &&
           vext_check_isa_ill(s) &&
           s->sew == MO_64 &&                   /* SEW != 64 is reserved     */
           (a->rs2 == 0 || a->rs2 == 1) &&
           (fixed_group ? (a->rd % 16 == 0) :
            (MAXSZ(s) >= 256 && require_align(a->rd, s->lmul)));
}

static bool trans_vkeccak_vi(DisasContext *s, arg_vkeccak_vi *a)
{
    TCGv_ptr rd_v;

    if (!vkeccak_vi_check(s, a)) {
        return false;
    }

    if (!s->vstart_eq_zero || s->cfg_ptr->vlenb != 16) {
        /* The helper can reject dynamic vl/vstart values. */
        decode_save_opc(s, 0);
    }

    rd_v = tcg_temp_new_ptr();
    tcg_gen_addi_ptr(rd_v, tcg_env, vreg_ofs(s, a->rd));
    gen_helper_vkeccak_vi(rd_v, tcg_env,
                         tcg_constant_i32(a->rs2 |
                                          (s->cfg_ptr->vlenb == 16 ? 0x100 : 0)));
    finalize_rvv_inst(s);

    return true;
}
