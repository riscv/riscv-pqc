#!/bin/bash
#
# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
set -euo pipefail

# Patch the Zvknhk (Vector Keccak) extension into the upstream Spike
# (riscv-isa-sim) sources. Spike is a pristine upstream submodule; this script
# is the single point where our local change is layered on top:
#
#   1. Copy spike/vkeccak_vi.h into the simulator's riscv/insns/ directory.
#   2. Insert the small amount of glue that registers the instruction: the
#      EXT_ZVKNHK extension id, its ISA-string name ("zvknhk"), the encoding, the
#      build-system entry, and the disassembler entry.
#
# The instruction body is self-contained: because zvknhk.adoc defines the state
# as a single fixed element group that is not strip-mined, the implementation
# needs neither the Zvk element-group loop macros nor a new element-group type,
# so riscv/vector_unit.h, riscv/zvk_ext_macros.h and riscv/zvkned_ext_macros.h
# are left untouched.
#
# Every edit is a pure insertion anchored on a nearby upstream line, and every
# site is guarded by a token that only this patch introduces — so the script is
# idempotent and safe to run on every build.
#
# WHY ANCHORS AND NOT A DIFF: the original change lives in the dev-keccak
# branch of a Spike fork, taken from upstream at 55b4658d (2026-06-25). Two of
# its nine hunks (disasm/isa_parser.cc, riscv/riscv.mk.in) already fail to
# apply against upstream a couple of months later, because they insert lines
# into long, frequently-edited lists. Anchoring on a single stable neighbour
# line survives that churn; unified-diff context does not.
#
# NOTE ON UPSTREAM LAYOUT: if a future Spike bump moves or renames any anchor,
# the corresponding check below fails loudly — update the anchor here.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SIM_DIR="$REPO_ROOT/riscv-isa-sim"
CHAPTER_SRC="$REPO_ROOT/spike/vkeccak_vi.h"
INSN_DST="$SIM_DIR/riscv/insns/vkeccak_vi.h"

if [ ! -f "$CHAPTER_SRC" ]; then
    echo "error: spike/vkeccak_vi.h not found under ($REPO_ROOT)" >&2
    exit 1
fi

if [ ! -f "$SIM_DIR/riscv/riscv.mk.in" ]; then
    echo "error: expected Spike source $SIM_DIR/riscv/riscv.mk.in not found." >&2
    echo "       Either the submodule is not initialized (run" >&2
    echo "       'git submodule update --init zvknhk/riscv-isa-sim'), or the upstream" >&2
    echo "       source layout changed — update the paths in $0." >&2
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
#
# <guard-token> is a string that only this patch introduces; if it is already
# present the site is left alone, which is what makes the script idempotent.
patch_file() {
    local rel="$1" mode="$2" anchor="$3" term="$4" guard="$5" block="$6"
    local file="$SIM_DIR/$rel"

    if [ ! -f "$file" ]; then
        echo "error: $rel not found — upstream layout changed; update $0" >&2
        exit 1
    fi

    if grep -qF -- "$guard" "$file"; then
        echo "    $rel: already patched"
        return 0
    fi

    if ! grep -qF -- "$anchor" "$file"; then
        echo "error: anchor not found in $rel:" >&2
        echo "         $anchor" >&2
        echo "       upstream layout changed — update the anchor in $0" >&2
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

    if ! grep -qF -- "$guard" "$file"; then
        echo "error: insertion into $rel did not take effect; update $0" >&2
        exit 1
    fi
    echo "    $rel: patched"
}

# ----------------------------------------------------------------- blocks ---

cat > "$BLOCKS/disasm.cc" <<'EOF'

  // Zvknhk (vkeccak.vi) -- applied by scripts/apply-spike-patch.sh
  //
  // The Zvknhk encoding carries imm5 in the vs2 field (bits 24:20), and the
  // vs1 field is a fixed part of the opcode. The generic .vi helpers read the
  // immediate from bits 19:15 and print a vs2 register, so using one here
  // would render `vkeccak.vi vd, imm5` as `vkeccak.vi vd, v<imm5>, 18`.
  if (ext_enabled(EXT_ZVKNHK)) {
    static struct : public arg_t {
      std::string to_string(insn_t insn) const {
        return std::to_string(insn.rs2());
      }
    } vkeccak_imm5;
    add_insn(new disasm_insn_t("vkeccak.vi", match_vkeccak_vi, mask_vkeccak_vi,
                               {&vd, &vkeccak_imm5}));
  }
EOF

cat > "$BLOCKS/isa_parser.cc" <<'EOF'
  // Zvknhk (vkeccak.vi) -- applied by scripts/apply-spike-patch.sh
  // zvknhk.adoc: "Zvknhk depends on Zve64x and requires VLEN to be at least
  // 128 bits (Zvl128b)." Declaring those as implied keeps a bare
  // --isa=rv64i_zvknhk from being accepted as a vector-less nonsense string;
  // zvl128b only raises VLEN, so an explicit larger zvl still wins.
  {"zvknhk", {EXT_ZVKNHK}, {"zve64x", "zvl128b"}},
EOF

cat > "$BLOCKS/encoding_match.h" <<'EOF'
/* Zvknhk (vkeccak.vi) -- applied by scripts/apply-spike-patch.sh */
#define MATCH_VKECCAK_VI 0xa6092077
#define MASK_VKECCAK_VI 0xfe0ff07f
EOF

cat > "$BLOCKS/encoding_declare.h" <<'EOF'
DECLARE_INSN(vkeccak_vi, MATCH_VKECCAK_VI, MASK_VKECCAK_VI)
EOF

cat > "$BLOCKS/isa_parser.h" <<'EOF'
  EXT_ZVKNHK,  /* Zvknhk (vkeccak.vi) */
EOF

# NOTE: tabs are significant in the two riscv.mk.in blocks below.
printf '%s\n' \
    '# Zvknhk (vkeccak.vi) -- applied by scripts/apply-spike-patch.sh' \
    'riscv_insn_ext_zvknhk = \' \
    "$(printf '\tvkeccak_vi \\')" \
    '' > "$BLOCKS/riscv.mk.in.list"

printf '%s\n' "$(printf '\t$(riscv_insn_ext_zvknhk) \\')" > "$BLOCKS/riscv.mk.in.use"

# ------------------------------------------------------------------ apply ---

if cmp -s "$CHAPTER_SRC" "$INSN_DST"; then
    echo "==> vkeccak_vi.h unchanged"
else
    echo "==> Copying vkeccak_vi.h into riscv/insns"
    cp "$CHAPTER_SRC" "$INSN_DST"
fi

echo "==> Registering the instruction in the Spike sources"

patch_file riscv/isa_parser.h after \
    '  EXT_ZICFISS,' - \
    'EXT_ZVKNHK' "$BLOCKS/isa_parser.h"

patch_file disasm/isa_parser.cc after \
    '  {"zvkt"},' - \
    '{"zvknhk"' "$BLOCKS/isa_parser.cc"

patch_file riscv/encoding.h after \
    '#define MASK_VIOTA_M 0xfc0ff07f' - \
    'MATCH_VKECCAK_VI' "$BLOCKS/encoding_match.h"

patch_file riscv/encoding.h after \
    'DECLARE_INSN(viota_m, MATCH_VIOTA_M, MASK_VIOTA_M)' - \
    'DECLARE_INSN(vkeccak_vi' "$BLOCKS/encoding_declare.h"

patch_file riscv/riscv.mk.in before \
    'riscv_insn_ext_p = \' - \
    'riscv_insn_ext_zvknhk = ' "$BLOCKS/riscv.mk.in.list"

patch_file riscv/riscv.mk.in after \
    '$(riscv_insn_ext_zicfiss) \' - \
    '$(riscv_insn_ext_zvknhk)' "$BLOCKS/riscv.mk.in.use"

# The disassembler entry goes next to the other Zvk* blocks. The upstream fork
# nested it inside `if (ext_enabled(EXT_ZICFISS))`, which only shows up under
# `spike-dasm --strict` but is wrong regardless. Anchor on the Zvksh block.
patch_file disasm/disasm.cc after_term \
    '    DEFINE_VECTOR_VV(vsm3me_vv);' '  }' \
    'vkeccak_imm5' "$BLOCKS/disasm.cc"

echo "==> Patch applied."
