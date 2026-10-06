// SPDX-License-Identifier: BSD-3-Clause
// Edge-case probe for vkeccak.vi: one case per process, an illegal
// instruction kills the process (no RESULT line).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef CASE
#define CASE 0
#endif

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

// All 32 vector registers at the largest swept VLEN (4096 bits).
static uint64_t buf[2048] __attribute__((aligned(64)));

typedef void (*fn_t)(uint64_t *, unsigned long, unsigned long, unsigned long,
                     unsigned long *, unsigned long *);

#define VCLOB "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10",     \
    "v11","v12","v13","v14","v15","v16","v17","v18","v19","v20","v21",       \
    "v22","v23","v24","v25","v26","v27","v28","v29","v30","v31"

#define DEF(name, rd, rs2, f7)                                              \
static void name(uint64_t *b, unsigned long r8, unsigned long avl,          \
                 unsigned long vt, unsigned long *vl, unsigned long *vs)    \
{                                                                           \
    unsigned long o_vl, o_vs, i_vs = *vs;                                   \
    __asm volatile (                                                        \
        "vsetvli t0, x0, e64, m8, tu, mu\n"                                 \
        "mv t1, %[b]\n"                                                     \
        "vl8re64.v v0, (t1)\n add t1, t1, %[r8]\n"                         \
        "vl8re64.v v8, (t1)\n add t1, t1, %[r8]\n"                         \
        "vl8re64.v v16, (t1)\n add t1, t1, %[r8]\n"                        \
        "vl8re64.v v24, (t1)\n"                                             \
        "vsetvl %[ovl], %[avl], %[vt]\n"                                    \
        "csrw vstart, %[ivs]\n"                                             \
        ".insn r 0x77, 0x2, " f7 ", " rd ", x18, " rs2 "\n"                 \
        "csrr %[ovs], vstart\n"                                             \
        "mv t1, %[b]\n"                                                     \
        "vs8r.v v0, (t1)\n add t1, t1, %[r8]\n"                            \
        "vs8r.v v8, (t1)\n add t1, t1, %[r8]\n"                            \
        "vs8r.v v16, (t1)\n add t1, t1, %[r8]\n"                           \
        "vs8r.v v24, (t1)\n"                                                \
        : [ovl]"=&r"(o_vl), [ovs]"=&r"(o_vs)                                \
        : [b]"r"(b), [r8]"r"(r8), [avl]"r"(avl), [vt]"r"(vt),               \
          [ivs]"r"(i_vs)                                                    \
        : "t0", "t1", "memory", VCLOB);                                     \
    *vl = o_vl; *vs = o_vs;                                                 \
}

DEF(k_v0,   "x0",  "x0", "0x53")
DEF(k_v4,   "x4",  "x0", "0x53")
DEF(k_v8,   "x8",  "x0", "0x53")
DEF(k_v16,  "x16", "x0", "0x53")
DEF(k_v24,  "x24", "x0", "0x53")
DEF(k_imm2, "x0",  "x2", "0x53")
DEF(k_vm0,  "x0",  "x0", "0x52")

// vtype: vlmul[2:0], vsew[5:3]
#define M1 0
#define M2 1
#define M4 2
#define M8 3
#define MF2 7
#define E32 (2 << 3)
#define E64 (3 << 3)
#define VILL_VT 4               // reserved vlmul -> vill

struct pc {
    const char *name;
    fn_t f;
    int vd;
    unsigned long vt;
    long avl;                   // -1 = VLMAX
    unsigned long vstart;
};

static const struct pc cases[] = {
    /* 0 */ {"m8 vl=32 vd=v0",            k_v0,   0,  E64 | M8, 32, 0},
    /* 1 */ {"m8 vl=VLMAX vd=v8",         k_v8,   8,  E64 | M8, -1, 0},
    /* 2 */ {"m8 vl=VLMAX vd=v24",        k_v24,  24, E64 | M8, -1, 0},
    /* 3 */ {"SEW=32",                    k_v0,   0,  E32 | M8, -1, 0},
    /* 4 */ {"m8 vd=v4 misaligned",       k_v4,   4,  E64 | M8, 32, 0},
    /* 5 */ {"m8 vl=16 (not mult of 32)", k_v0,   0,  E64 | M8, 16, 0},
    /* 6 */ {"m8 vstart=16",              k_v0,   0,  E64 | M8, 32, 16},
    /* 7 */ {"m8 vstart=32 vl=32 (>=vl)", k_v0,   0,  E64 | M8, 32, 32},
    /* 8 */ {"m8 vl=0",                   k_v0,   0,  E64 | M8, 0, 0},
    /* 9 */ {"imm5=2",                    k_imm2, 0,  E64 | M8, 32, 0},
    /*10 */ {"vill",                      k_v0,   0,  VILL_VT, 32, 0},
    /*11 */ {"vm=0",                      k_vm0,  0,  E64 | M8, 32, 0},
    /*12 */ {"m1 vl=0 vd=v0",             k_v0,   0,  E64 | M1, 0, 0},
    /*13 */ {"m4 vl=0 vd=v0",             k_v0,   0,  E64 | M4, 0, 0},
    /*14 */ {"m8 vd=v16",                 k_v16,  16, E64 | M8, -1, 0},
    /*15 */ {"m8 vstart=1",               k_v0,   0,  E64 | M8, 32, 1},
    /*16 */ {"m8 vl=VLMAX vstart=32",     k_v0,   0,  E64 | M8, -1, 32},
    /*17 */ {"m2 vl=VLMAX vd=v0",         k_v0,   0,  E64 | M2, -1, 0},
    /*18 */ {"mf2 vl=VLMAX vd=v0",        k_v0,   0,  E64 | MF2, -1, 0},
    /*19 */ {"m8 vd=v8 vl=16 (VLEN128)",  k_v8,   8,  E64 | M8, 16, 0},
};

int main(int argc, char **argv)
{
    unsigned long vlenb;
    __asm volatile ("csrr %0, vlenb" : "=r"(vlenb));
    int n = argc > 1 ? atoi(argv[1]) : CASE;
    if (n < 0 || n >= (int)(sizeof(cases) / sizeof(cases[0])))
        return 2;
    const struct pc *c = &cases[n];
    unsigned long words = 4 * vlenb, per_reg = vlenb / 8;
    if (words > sizeof(buf) / sizeof(buf[0]))
        return 2;

    for (unsigned long i = 0; i < words; ++i)
        buf[i] = (i % 32 < 25) ? 0 : 0xA5A5000000000000ULL + i;

    unsigned long avl = c->avl < 0 ? ~0UL : (unsigned long)c->avl;
    unsigned long vl, vs = c->vstart;
    c->f(buf, 8 * vlenb, avl, c->vt, &vl, &vs);

    // expected groups, in units of 32 flat words
    int perm[64] = {0};
    if (vlenb == 16) {
        perm[c->vd / 16] = 1;
    } else {
        for (unsigned long g = c->vstart / 32; g < vl / 32; ++g)
            perm[c->vd * per_reg / 32 + g] = 1;
    }
    int bad = 0;
    for (unsigned long i = 0; i < words; ++i) {
        uint64_t e = (i % 32 < 25) ? (perm[i / 32] ? zero24[i % 32] : 0)
                                   : 0xA5A5000000000000ULL + i;
        if (buf[i] != e) {
            if (bad < 4) printf("  word %lu: %016llx want %016llx\n", i,
                                (unsigned long long)buf[i],
                                (unsigned long long)e);
            ++bad;
        }
    }
    printf("RESULT %s vl=%lu vstart_after=%lu bad=%d (%s)\n",
           (bad || vs) ? "bad" : "ok", vl, vs, bad, c->name);
    return bad || vs ? 1 : 0;
}
