#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Run each instruction encoding in a fresh process: illegal instructions must
# terminate the process before edge_probe.c can print a RESULT line.
set -u
ulimit -c 0

mode=$1
sim=$2
pk=$3
vlens=$4
cases='0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19'

expectation() {
    n=$1
    v=$2
    case "$n" in
        0|8|14) echo legal ;;
        1|2|7|16) if [ "$v" -ge 256 ]; then echo legal; else echo illegal; fi ;;
        5) if [ "$v" -eq 128 ]; then echo legal; else echo illegal; fi ;;
        12) if [ "$v" -eq 128 ] || [ "$v" -ge 2048 ]; then echo legal; else echo illegal; fi ;;
        13) if [ "$v" -eq 128 ] || [ "$v" -ge 512 ]; then echo legal; else echo illegal; fi ;;
        17) if [ "$v" -eq 128 ] || [ "$v" -ge 1024 ]; then echo legal; else echo illegal; fi ;;
        18) if [ "$v" -eq 128 ] || [ "$v" -ge 4096 ]; then echo either; else echo illegal; fi ;;
        *) echo illegal ;;
    esac
}

result_ok() {
    [ "$rc" -eq 0 ] && printf '%s\n' "$out" |
        grep -Eq '^RESULT ok vl=[0-9]+ vstart_after=0 bad=0 '
}

trap_ok() {
    if [ "$mode" = spike ]; then
        [ "$rc" -eq 255 ] && printf '%s\n' "$out" |
            grep -q 'An illegal instruction was executed!'
    else
        [ "$rc" -eq 132 ] && printf '%s\n' "$out" |
            grep -q 'uncaught target signal 4 (Illegal instruction)'
    fi
}

failed=0
for vlen in $vlens; do
    passed=0
    for n in $cases; do
        bin="./edge_probe$n"
        if [ "$mode" = spike ]; then
            if out=$("$sim" "--isa=rv64gcv_zvl${vlen}b_zvknhk_zicntr_zihpm" "$pk" "$bin" 2>&1); then
                rc=0
            else
                rc=$?
            fi
        else
            if out=$("$sim" -cpu "rv64,v=true,vlen=$vlen,elen=64,zvknhk=true,zicntr=true,zihpm=true" "$bin" 2>&1) 2>/dev/null; then
                rc=0
            else
                rc=$?
            fi
        fi
        want=$(expectation "$n" "$vlen")
        if { [ "$want" = legal ] || [ "$want" = either ]; } && result_ok; then
            passed=$((passed + 1))
        elif { [ "$want" = illegal ] || [ "$want" = either ]; } && trap_ok; then
            passed=$((passed + 1))
        else
            echo "VLEN=$vlen case=$n FAIL: expected $want, exit=$rc"
            printf '%s\n' "$out" | tail -n 6
            failed=1
        fi
    done
    echo "VLEN=$vlen edge cases: $passed/20 passed"
done
exit "$failed"
