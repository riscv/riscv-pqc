#!/bin/bash
#
# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
set -euo pipefail

# Patch the Zvknhk (Vector Keccak) extension into the upstream QEMU sources.
# QEMU is a pristine upstream submodule; this script is the single point where
# our local change is layered on top:
#
#   1. Copy qemu/vkeccak_vi.c.inc into target/riscv/tcg/ and
#      qemu/trans_vkeccak_vi.c.inc into target/riscv/tcg/insn_trans/, then
#      #include each from the file that owns that compilation unit.
#   2. Insert the glue that registers the instruction: the decode pattern, the
#      helper declaration, the ext_zvknhk config field, the ISA-string entry,
#      the implied-extension rule, and the TCG validation.
#
# The two .c.inc files hold everything specific to the instruction; the glue
# below is seven small insertions. Nothing in QEMU's strip-mining scaffolding
# (vector_internals.h, the GEN_*_UNMASKED_TRANS macros) is touched, for the
# same reason as in Spike: zvknhk.adoc defines the state as a single fixed
# element group that is not strip-mined.
#
# Every edit is a pure insertion anchored on a nearby upstream line, and every
# site is guarded by a token that only this patch introduces -- so the script
# is idempotent and safe to run on every build.
#
# WHY ANCHORS AND NOT A DIFF: same reasoning as scripts/apply-spike-patch.sh.
# insn32.decode, helper.h, cpu.c and cpu_cfg_fields.h.inc are long, frequently
# edited lists; unified-diff context rots against them within weeks, while a
# single stable neighbour line survives.
#
# NOTE ON UPSTREAM LAYOUT: if a future QEMU bump moves or renames any anchor,
# the corresponding check below fails loudly -- update the anchor here.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
QEMU_DIR="$REPO_ROOT/qemu-src"
SRC_DIR="$REPO_ROOT/qemu"

HELPER_SRC="$SRC_DIR/vkeccak_vi.c.inc"
TRANS_SRC="$SRC_DIR/trans_vkeccak_vi.c.inc"
HELPER_DST="$QEMU_DIR/target/riscv/tcg/vkeccak_vi.c.inc"
TRANS_DST="$QEMU_DIR/target/riscv/tcg/insn_trans/trans_vkeccak_vi.c.inc"

for f in "$HELPER_SRC" "$TRANS_SRC"; do
    if [ ! -f "$f" ]; then
        echo "error: $(basename "$f") not found in $SRC_DIR" >&2
        exit 1
    fi
done

if [ ! -f "$QEMU_DIR/target/riscv/insn32.decode" ]; then
    echo "error: expected QEMU source $QEMU_DIR/target/riscv/insn32.decode" >&2
    echo "       not found. Either the submodule is not initialized (run" >&2
    echo "       'git submodule update --init zvknhk/qemu-src'), or the upstream" >&2
    echo "       source layout changed -- update the paths in $0." >&2
    exit 1
fi

BLOCKS="$(mktemp -d)"
trap 'rm -rf "$BLOCKS"' EXIT

# ---------------------------------------------------------------- helpers ---

# patch_file <file> <mode> <anchor> <terminator|-> <guard-token> <block-file>
#
#   mode = after       : insert the block after the line matching <anchor>
#          before      : insert the block before the line matching <anchor>
#          after_term  : find <anchor>, then insert after the next line
#                        matching <terminator> (used to land after the close
#                        of the block the anchor sits in)
#          append      : append the block to the end of the file; <anchor> is
#                        ignored (used for the two #include lines, which have
#                        no meaningful neighbour to anchor on)
#
# <guard-token> is a string that only this patch introduces; if it is already
# present the site is left alone, which is what makes the script idempotent.
patch_file() {
    local rel="$1" mode="$2" anchor="$3" term="$4" guard="$5" block="$6"
    local file="$QEMU_DIR/$rel"

    if [ ! -f "$file" ]; then
        echo "error: $rel not found -- upstream layout changed; update $0" >&2
        exit 1
    fi

    if grep -qF -- "$guard" "$file"; then
        echo "    $rel: already patched"
        return 0
    fi

    if [ "$mode" = "append" ]; then
        cat "$block" >> "$file"
    else
        if ! grep -qF -- "$anchor" "$file"; then
            echo "error: anchor not found in $rel:" >&2
            echo "         $anchor" >&2
            echo "       upstream layout changed -- update the anchor in $0" >&2
            exit 1
        fi

        MODE="$mode" ANCHOR="$anchor" TERM="$term" BLOCK="$block" awk '
            BEGIN {
                while ((getline l < ENVIRON["BLOCK"]) > 0) blk = blk l "\n"
                mode = ENVIRON["MODE"]
            }
            mode == "before" && !done && index($0, ENVIRON["ANCHOR"]) {
                printf "%s", blk; done = 1
            }
            { print }
            mode == "after" && !done && index($0, ENVIRON["ANCHOR"]) {
                printf "%s", blk; done = 1
            }
            mode == "after_term" && !armed && !done && index($0, ENVIRON["ANCHOR"]) {
                armed = 1; next
            }
            mode == "after_term" && armed && !done && index($0, ENVIRON["TERM"]) {
                printf "%s", blk; armed = 0; done = 1
            }
        ' "$file" > "$file.tmp"

        mv "$file.tmp" "$file"
    fi

    if ! grep -qF -- "$guard" "$file"; then
        echo "error: insertion into $rel did not take effect; update $0" >&2
        exit 1
    fi
    echo "    $rel: patched"
}

# ----------------------------------------------------------------- blocks ---

# 1. Decode. The encoding falls straight out of zvknhk.adoc: funct6=101001,
#    vm=1, imm5 in the vs2 field, 10010 fixed in the vs1 field, funct3=OPMVV,
#    opcode=OP-VE. @r2_vm_1 extracts exactly vd and vs2 and ignores the vs1
#    field, which is what we want since 10010 is a fixed part of the opcode.
cat > "$BLOCKS/insn32.decode" <<'EOF'
# *** Zvknhk vector Keccak extension ***
# applied by scripts/apply-qemu-patch.sh
vkeccak_vi  101001 1 ..... 10010 010 ..... 1110111 @r2_vm_1

EOF

# 2. Helper declaration. Only vd is an operand; imm5 rides in as an i32
#    constant. No descriptor: the helper needs neither vl nor LMUL.
cat > "$BLOCKS/helper.h" <<'EOF'
/* Zvknhk (vkeccak.vi) -- applied by scripts/apply-qemu-patch.sh */
DEF_HELPER_3(vkeccak_vi, void, ptr, env, i32)

EOF

# 3./4. Pull the two instruction files into their compilation units.
cat > "$BLOCKS/vcrypto_helper.c" <<'EOF'

/* Zvknhk (vkeccak.vi) -- applied by scripts/apply-qemu-patch.sh */
#include "vkeccak_vi.c.inc"
EOF

cat > "$BLOCKS/trans_rvvk.c.inc" <<'EOF'

/* Zvknhk (vkeccak.vi) -- applied by scripts/apply-qemu-patch.sh */
#include "trans_vkeccak_vi.c.inc"
EOF

# 5. The config field that gates the extension.
cat > "$BLOCKS/cpu_cfg_fields.h.inc" <<'EOF'
BOOL_FIELD(ext_zvknhk)  /* Zvknhk -- applied by scripts/apply-qemu-patch.sh */
EOF

# 6a. ISA-string entry. This one table drives both the ISA string and the
#     "zvknhk=on" CPU property, so no separate property registration is
#     needed. Inserted after zvknhb, which keeps the list alphabetical.
cat > "$BLOCKS/cpu.c.isa" <<'EOF'
    /* Zvknhk (vkeccak.vi) -- applied by scripts/apply-qemu-patch.sh */
    ISA_EXT_DATA_ENTRY(zvknhk, PRIV_VERSION_1_12_0, ext_zvknhk),
EOF

# 6b. Implied extensions. zvknhk.adoc: "Zvknhk depends on Zve64x and requires
#     VLEN to be at least 128 bits (Zvl128b)." QEMU has no zvl* extension
#     booleans -- VLEN is the "vlen" property -- so only the Zve64x half is
#     expressible here; the VLEN floor is enforced in tcg-cpu.c below.
cat > "$BLOCKS/cpu.c.implied" <<'EOF'
/* Zvknhk (vkeccak.vi) -- applied by scripts/apply-qemu-patch.sh */
static RISCVCPUImpliedExtsRule ZVKNHK_IMPLIED = {
    .ext = CPU_CFG_OFFSET(ext_zvknhk),
    .implied_multi_exts = {
        CPU_CFG_OFFSET(ext_zve64x),

        RISCV_IMPLIED_EXTS_RULE_END
    },
};

EOF

cat > "$BLOCKS/cpu.c.rules" <<'EOF'
    &ZVKNHK_IMPLIED, /* applied by scripts/apply-qemu-patch.sh */
EOF

# 7. TCG validation. A separate block rather than an edit to the existing
#    Zvbc/Zvknhb condition, so that every site stays a pure insertion.
cat > "$BLOCKS/tcg-cpu.c" <<'EOF'

    /* Zvknhk (vkeccak.vi) -- applied by scripts/apply-qemu-patch.sh */
    if (cpu->cfg.ext_zvknhk) {
        if (!cpu->cfg.ext_zve64x) {
            error_setg(errp,
                       "Zvknhk extension requires V or Zve64x extension");
            return;
        }
        if ((cpu->cfg.vlenb << 3) < 128) {
            error_setg(errp,
                       "Zvknhk extension requires VLEN to be at least 128");
            return;
        }
    }
EOF

# ------------------------------------------------------------------ apply ---

copy_if_changed() {
    local src="$1" dst="$2"
    if cmp -s "$src" "$dst"; then
        echo "==> $(basename "$src") unchanged"
    else
        echo "==> Copying $(basename "$src") into ${dst%/*}"
        cp "$src" "$dst"
    fi
}

copy_if_changed "$HELPER_SRC" "$HELPER_DST"
copy_if_changed "$TRANS_SRC" "$TRANS_DST"

echo "==> Registering the instruction in the QEMU sources"

patch_file target/riscv/insn32.decode before \
    '# *** Zvkned vector crypto extension ***' - \
    'vkeccak_vi' "$BLOCKS/insn32.decode"

patch_file target/riscv/helper.h before \
    'DEF_HELPER_4(vaesef_vv, void, ptr, ptr, env, i32)' - \
    'DEF_HELPER_3(vkeccak_vi' "$BLOCKS/helper.h"

patch_file target/riscv/tcg/vcrypto_helper.c append \
    - - '#include "vkeccak_vi.c.inc"' "$BLOCKS/vcrypto_helper.c"

patch_file target/riscv/tcg/insn_trans/trans_rvvk.c.inc append \
    - - '#include "trans_vkeccak_vi.c.inc"' "$BLOCKS/trans_rvvk.c.inc"

patch_file target/riscv/cpu_cfg_fields.h.inc after \
    'BOOL_FIELD(ext_zvknhb)' - \
    'BOOL_FIELD(ext_zvknhk)' "$BLOCKS/cpu_cfg_fields.h.inc"

patch_file target/riscv/cpu.c after \
    '    ISA_EXT_DATA_ENTRY(zvknhb, PRIV_VERSION_1_12_0, ext_zvknhb),' - \
    'ISA_EXT_DATA_ENTRY(zvknhk' "$BLOCKS/cpu.c.isa"

patch_file target/riscv/cpu.c before \
    'static RISCVCPUImpliedExtsRule ZVKS_IMPLIED = {' - \
    'ZVKNHK_IMPLIED = {' "$BLOCKS/cpu.c.implied"

patch_file target/riscv/cpu.c after \
    '    &ZVKNC_IMPLIED, &ZVKNG_IMPLIED, &ZVKNHB_IMPLIED,' - \
    '&ZVKNHK_IMPLIED,' "$BLOCKS/cpu.c.rules"

# Land after the close of the existing Zvbc/Zvknhb validation block.
patch_file target/riscv/tcg/tcg-cpu.c after_term \
    '    if ((cpu->cfg.ext_zvbc || cpu->cfg.ext_zvknhb) && !cpu->cfg.ext_zve64x) {' '    }' \
    'cpu->cfg.ext_zvknhk' "$BLOCKS/tcg-cpu.c"

echo "==> Patch applied."
