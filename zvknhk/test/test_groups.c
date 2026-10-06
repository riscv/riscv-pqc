// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
// Exercise independent element groups and restart at an element-group boundary.
#include <stdint.h>
#include <stdio.h>
#include "plat_local.h"

static const uint64_t zero24[25] = {
    0xF1258F7940E1DDE7ULL, 0x84D5CCF933C0478AULL, 0xD598261EA65AA9EEULL,
    0xBD1547306F80494DULL, 0x8B284E056253D057ULL, 0xFF97A42D7F8E6FD4ULL,
    0x90FEE5A0A44647C4ULL, 0x8C5BDA0CD6192E76ULL, 0xAD30A6F71B19059CULL,
    0x30935AB7D08FFC64ULL, 0xEB5AA93F2317D635ULL, 0xA9A6E6260D712103ULL,
    0x81A57C16DBCF555FULL, 0x43B831CD0347C826ULL, 0x01F22F1A11A5569FULL,
    0x05E5635A21D9AE61ULL, 0x64BEFEF28CC970F2ULL, 0x613670957BC46611ULL,
    0xB87C5A554FD00ECBULL, 0x8C3EE88A1CCF32C8ULL, 0x940C7922AE3A2614ULL,
    0x1841F924A2C509E4ULL, 0x16F53526E70465C2ULL, 0x75F644E97F30A13BULL,
    0xEAF1FF7B5CECA249ULL
};

static uint64_t words[64] __attribute__((aligned(64)));
static void fill(void);

static int test_fixed_v16(void)
{
    uint64_t *state = words + 32;
    uint64_t *hi = state + 16;
    int fail = 0;

    fill();
    __asm volatile (
        "vsetivli x0, 16, e64, m8, tu, mu\n"
        "vle64.v v16, 0(%[lo])\n"
        "vle64.v v24, 0(%[hi])\n"
        ".insn r 0x77, 0x2, 0x53, x16, x18, x0\n"
        "vse64.v v16, 0(%[lo])\n"
        "vse64.v v24, 0(%[hi])\n"
        : : [lo]"r"(state), [hi]"r"(hi) : "memory");
    for (int i = 0; i < 64; ++i) {
        uint64_t expected = i < 32 ? ((i < 25) ? 0 :
            0xA5A5000000000000ULL + i) :
            ((i < 57) ? zero24[i - 32] : 0xA5A5000000000000ULL + i);
        fail += words[i] != expected;
    }
    printf("[%s]\tVLEN=128 fixed group at v16\n", fail ? "FAIL" : "PASS");
    return fail;
}

static void fill(void)
{
    for (int i = 0; i < 64; ++i) {
        words[i] = (i % 32 < 25) ? 0 : 0xA5A5000000000000ULL + i;
    }
}

#define RUN_MIN(lmul) __asm volatile (                              \
    "li t0, 32\n"                                                 \
    "vsetvli x0, t0, e64, " lmul ", tu, mu\n"                    \
    "vle64.v v0, 0(%[buf])\n"                                      \
    ".insn r 0x77, 0x2, 0x53, x0, x18, x0\n"                    \
    "vse64.v v0, 0(%[buf])\n"                                      \
    : : [buf]"r"(words) : "memory", "t0")

static int test_min_lmul(void)
{
    unsigned long vlenb = rv_get_vlenb();
    int fail = 0;

    fill();
    if (vlenb == 64) {
        RUN_MIN("m4");
    } else if (vlenb == 128) {
        RUN_MIN("m2");
    } else if (vlenb == 256) {
        RUN_MIN("m1");
    } else if (vlenb == 512) {
        RUN_MIN("m1");
    } else {
        return 0;
    }
    for (int i = 0; i < 64; ++i) {
        uint64_t expected = i < 25 ? zero24[i] :
            ((i % 32 < 25) ? 0 : 0xA5A5000000000000ULL + i);
        fail += words[i] != expected;
    }
    printf("[%s]\tminimum LMUL at VLEN=%lu\n", fail ? "FAIL" : "PASS",
           vlenb * 8);
    return fail;
}

static void run(unsigned start, int empty)
{
    unsigned long vstart = start;
    unsigned long avl = empty ? 0 : 64;
    __asm volatile (
        "li t0, 64\n"
        "vsetvli x0, t0, e64, m8, tu, mu\n"
        "vle64.v v0, 0(%[buf])\n"
        "vsetvli x0, %[avl], e64, m8, tu, mu\n"
        "csrw vstart, %[start]\n"
        ".insn r 0x77, 0x2, 0x53, x0, x18, x0\n"
        "li t0, 64\n"
        "vsetvli x0, t0, e64, m8, tu, mu\n"
        "vse64.v v0, 0(%[buf])\n"
        : : [buf]"r"(words), [avl]"r"(avl), [start]"r"(vstart)
        : "memory", "t0");
}

static void run_4096_m1(void)
{
    __asm volatile (
        "li t0, 64\n"
        "vsetvli x0, t0, e64, m1, tu, mu\n"
        "vle64.v v0, 0(%[buf])\n"
        ".insn r 0x77, 0x2, 0x53, x0, x18, x0\n"
        "vse64.v v0, 0(%[buf])\n"
        : : [buf]"r"(words) : "memory", "t0");
}

static int check(int first_permuted, int second_permuted)
{
    int fail = 0;
    for (int group = 0; group < 2; ++group) {
        int permuted = group ? second_permuted : first_permuted;
        for (int i = 0; i < 25; ++i) {
            uint64_t expected = permuted ? zero24[i] : 0;
            fail += words[32 * group + i] != expected;
        }
        for (int i = 25; i < 32; ++i) {
            int index = 32 * group + i;
            fail += words[index] != 0xA5A5000000000000ULL + index;
        }
    }
    return fail;
}

int test_groups(void)
{
    int fail = 0;
    if (rv_get_vlenb() == 16) {
        return test_fixed_v16();
    }
    if (rv_get_vlenb() < 64) {
        return 0;
    }
    fail += test_min_lmul();
    if (rv_get_vlenb() == 64) {
        unsigned long actual;
        __asm volatile (
            "li t0, 96\n"
            "vsetvli %[vl], t0, e64, m8, tu, mu\n"
            : [vl]"=r"(actual) : : "t0");
        fail += actual != 64;
    }
    fill();
    run(0, 0);
    fail += check(1, 1);
    fill();
    run(32, 0);
    fail += check(0, 1);
    fill();
    run(0, 1);
    fail += check(0, 0);
    if (rv_get_vlenb() == 512) {
        fill();
        run_4096_m1();
        fail += check(1, 1);
    }
    printf("[%s]\tmultiple groups, restart, vl=0\n", fail ? "FAIL" : "PASS");
    return fail;
}
