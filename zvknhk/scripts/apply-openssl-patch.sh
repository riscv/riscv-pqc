#!/bin/bash
#
# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
set -euo pipefail

# Patch the Zvknhk (Vector Keccak) extension into the upstream OpenSSL sources.
# OpenSSL is a pristine upstream submodule; this script is the single point
# where our local change is layered on top:
#
#   1. Register a ZVKNHK capability bit in the RISC-V capability table, so that
#      RISCV_HAS_ZVKNHK() exists and OPENSSL_riscvcap=..._zvknhk turns it on.
#   2. Copy openssl/keccak1600_zvknhk.c.inc into crypto/sha/ and #include it
#      from crypto/sha/keccak1600.c, just above SHA3_absorb().
#
# That is the whole patch: one table line and one #include. Everything specific
# to the instruction lives in the .c.inc, including the
#
#     #define KeccakF1600 KeccakF1600_zvknhk_dispatch
#
# that redirects the two call sites -- see the comment at the top of that file
# for why the include has to land where it does.
#
# Hooking KeccakF1600() rather than PROV_SHA3_METHOD in sha3_prov.c is
# deliberate: absorb, final and squeeze all funnel through the permutation, so
# a single site covers SHA-3, SHAKE, KMAC, ML-KEM, ML-DSA and SLH-DSA in both
# the default and the FIPS provider. sha3_prov.c would cover only the digest
# provider, and only the half of it that the per-architecture hook reaches.
#
# Every edit is a pure insertion anchored on a nearby upstream line, and every
# site is guarded by a token that only this patch introduces -- so the script
# is idempotent and safe to run on every build.
#
# WHY ANCHORS AND NOT A DIFF: same reasoning as scripts/apply-spike-patch.sh.
#
# NOTE ON UPSTREAM LAYOUT: OpenSSL moves these files around. In 4.0.2 the
# capability table is include/crypto/riscv_arch.def; on master it has moved to
# include/arch/riscv_arch.def. If a future bump moves or renames any anchor,
# the corresponding check below fails loudly -- update the anchor here.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$REPO_ROOT/demo/openssl"
SRC_DIR="$REPO_ROOT/openssl"

KECCAK_SRC="$SRC_DIR/keccak1600_zvknhk.c.inc"
KECCAK_DST="$SSL_DIR/crypto/sha/keccak1600_zvknhk.c.inc"
KECCAK_C="$SSL_DIR/crypto/sha/keccak1600.c"

if [ ! -f "$KECCAK_SRC" ]; then
    echo "error: $(basename "$KECCAK_SRC") not found in $SRC_DIR" >&2
    exit 1
fi

if [ ! -f "$KECCAK_C" ]; then
    echo "error: expected OpenSSL source $KECCAK_C" >&2
    echo "       not found. Either the submodule is not initialized (run" >&2
    echo "       'git submodule update --init zvknhk/demo/openssl'), or the upstream" >&2
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
#                        of the comment block the anchor sits in)
#
# <guard-token> is a string that only this patch introduces; if it is already
# present the site is left alone, which is what makes the script idempotent.
patch_file() {
    local rel="$1" mode="$2" anchor="$3" term="$4" guard="$5" block="$6"
    local file="$SSL_DIR/$rel"

    if [ ! -f "$file" ]; then
        echo "error: $rel not found -- upstream layout changed; update $0" >&2
        exit 1
    fi

    if grep -qF -- "$guard" "$file"; then
        echo "    $rel: already patched"
        return 0
    fi

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

    if ! grep -qF -- "$guard" "$file"; then
        echo "error: insertion into $rel did not take effect; update $0" >&2
        exit 1
    fi
    echo "    $rel: patched"
}

# ----------------------------------------------------------------- blocks ---

# 1. The capability bit. Word 0 bit 24 is the first free slot after ZVKSH.
#
#    The hwprobe key is -1, i.e. "no hwprobe key", exactly as ZKR does: Zvknhk
#    is not an upstream extension, so the kernel has no bit for it and never
#    will. That leaves OPENSSL_riscvcap as the way to turn it on, which is what
#    we want on an emulator anyway. riscv_arch.h derives everything else from
#    this one line -- the RISCV_HAS_ZVKNHK() inline, the array sizing, and the
#    RISCV_capabilities[] entry that makes parse_env() recognise "_ZVKNHK".
cat > "$BLOCKS/riscv_arch.def" <<'EOF'
/* Zvknhk (vkeccak.vi) -- applied by scripts/apply-openssl-patch.sh.
 * hwprobe key -1: not an upstream extension, so it has no kernel bit; set it
 * with e.g. OPENSSL_riscvcap=rv64gc_v_zvknhk. */
RISCV_DEFINE_CAP(ZVKNHK, 0, 24, -1, 0)
EOF

# 2. Pull the permutation into keccak1600.c. The anchor is the first line of
#    the comment block that opens SHA3_absorb(); the block is inserted after
#    that comment closes, which puts the include after every KeccakF1600()
#    definition and before both of its call sites -- the placement the .c.inc
#    relies on. Anchoring on the prose rather than on the function signature is
#    deliberate: `size_t SHA3_absorb(uint64_t A[5][5], ...` appears twice in
#    the file, once as the prototype at the top and once here. (Inserting at
#    the top would put the #define above the KeccakF1600() definitions, which
#    would rename those too and make the fallback recurse.) The include lands
#    between that comment and the function it documents; that is the price of
#    keeping every site a pure insertion.
cat > "$BLOCKS/keccak1600.c" <<'EOF'

/* Zvknhk (vkeccak.vi) -- applied by scripts/apply-openssl-patch.sh */
#include "keccak1600_zvknhk.c.inc"

EOF

# ------------------------------------------------------------------ apply ---

# Copy the .c.inc, and touch keccak1600.c when it changes: the build tracks
# dependencies with -MMD from the compiler, which has never seen the file if
# the object is already up to date from a previous build.
if cmp -s "$KECCAK_SRC" "$KECCAK_DST"; then
    echo "==> keccak1600_zvknhk.c.inc unchanged"
else
    echo "==> Copying keccak1600_zvknhk.c.inc into crypto/sha"
    cp "$KECCAK_SRC" "$KECCAK_DST"
    touch "$KECCAK_C"
fi

echo "==> Registering the instruction in the OpenSSL sources"

patch_file include/crypto/riscv_arch.def after \
    'RISCV_DEFINE_CAP(ZVKSH, 0, 23, 4, (1 << 25))' - \
    'RISCV_DEFINE_CAP(ZVKNHK' "$BLOCKS/riscv_arch.def"

patch_file crypto/sha/keccak1600.c after_term \
    ' * SHA3_absorb can be called multiple times, but at each invocation' ' */' \
    'keccak1600_zvknhk.c.inc' "$BLOCKS/keccak1600.c"

echo "==> Patch applied."
