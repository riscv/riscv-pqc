#!/bin/bash
#
# SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
# SPDX-License-Identifier: BSD-3-Clause
#
#
#   count.sh -- instruction counting for the Zvknhk OpenSSL backend, under QEMU
#
#   QEMU has no timing model and its in-guest counter CSRs are the host cpu's
#   tick counter, so cycles cannot be measured here. What QEMU does do exactly
#   is count executed instructions, via a TCG plugin. Each operation is run at
#   1 and at N iterations and differenced, which cancels process startup.
#
#   The instructions-per-permutation figures are NOT hardcoded. They are
#   calibrated at the start of every run, with this binary at this VLEN, by
#   hashing a file whose permutation count follows from FIPS 202: SHA3-256 has
#   a rate of 136 bytes, so a file of S bytes costs floor(S/136) absorb
#   permutations plus one for the padded final block. An earlier version
#   hardcoded 5790, which was both stale and VLEN-dependent.
#
#   Configuration comes from the environment; see the Makefile.

set -u

: "${QEMU:?}" "${QEMUFL:?}" "${OPENSSL:?}" "${PLUGIN:?}"
: "${CAP:?}" "${NOCAP:?}" "${N:?}" "${OPS:?}"

if [ "$N" -le 1 ]; then
    echo "error: N must be greater than 1 (differencing needs two points)" >&2
    exit 2
fi

#   Run one command under the plugin and echo its instruction count. Every
#   failure is fatal and loud: a previous version piped straight into awk and
#   so reported a crashed process, or a mistyped operation name, as a
#   successful sample of zero instructions.
insns() {
    local cap="$1"; shift
    local out st n

    out=$(OPENSSL_riscvcap="$cap" $QEMU $QEMUFL -plugin "$PLUGIN" -d plugin \
          "$@" 2>&1)
    st=$?
    if [ $st -ne 0 ]; then
        echo "error: exited $st: $*" >&2
        printf '%s\n' "$out" | grep -v '^total insns\|^cpu ' | tail -3 >&2
        exit 1
    fi
    n=$(printf '%s\n' "$out" | grep -c '^total insns')
    if [ "$n" -ne 1 ]; then
        echo "error: wanted exactly one 'total insns' record, got $n: $*" >&2
        exit 1
    fi
    printf '%s\n' "$out" | awk '/^total insns/{print $3}'
}

# ------------------------------------------------------------- calibrate ---

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

SIZE=1048576                        # 1 MiB
RATE=136                            # SHA3-256
PERMS=$(( SIZE / RATE + 1 ))        # full blocks, plus the padded final one

head -c "$SIZE" /dev/zero > "$TMP/blob"

cal_sw=$(insns "$NOCAP" "$OPENSSL" dgst -sha3-256 "$TMP/blob")
cal_vk=$(insns "$CAP"   "$OPENSSL" dgst -sha3-256 "$TMP/blob")
nul_sw=$(insns "$NOCAP" "$OPENSSL" dgst -sha3-256 /dev/null)
nul_vk=$(insns "$CAP"   "$OPENSSL" dgst -sha3-256 /dev/null)

#   Hashing an empty input still costs one permutation, so the difference
#   between the two isolates PERMS-1 of them along with the file I/O.
perm_delta=$(( ( (cal_sw - cal_vk) - (nul_sw - nul_vk) ) / (PERMS - 1) ))
perm_sw=$(( (cal_sw - nul_sw) / (PERMS - 1) ))

if [ "$perm_delta" -le 0 ] || [ "$perm_sw" -le 0 ]; then
    echo "error: calibration produced nonsense (delta=$perm_delta sw=$perm_sw)" >&2
    exit 1
fi

printf 'calibration: %d permutations of SHA3-256 over %d bytes\n' "$PERMS" "$SIZE"
printf '             %d instructions each in software, %d removed by vkeccak.vi\n\n' \
    "$perm_sw" "$perm_delta"

# ----------------------------------------------------------------- table ---

printf '%-16s %10s %12s %12s %7s %8s\n' \
    op software vkeccak delta perms keccak%
for op in $OPS; do
    a=$(insns "$NOCAP" ./pqcbench "$op" 1)
    b=$(insns "$NOCAP" ./pqcbench "$op" "$N")
    c=$(insns "$CAP"   ./pqcbench "$op" 1)
    d=$(insns "$CAP"   ./pqcbench "$op" "$N")

    awk -v o="$op" -v s="$(( (b - a) / (N - 1) ))" -v v="$(( (d - c) / (N - 1) ))" \
        -v pd="$perm_delta" -v ps="$perm_sw" 'BEGIN {
            dl = s - v; p = dl / pd;
            printf "%-16s %10d %12d %12d %7.0f %7.1f%%\n", o, s, v, dl, p,
                   100.0 * p * ps / s
        }'
done
