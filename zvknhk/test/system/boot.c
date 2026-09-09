// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
//  boot.c -- system-mode smoke test for vkeccak.vi under qemu-system-riscv64.
//
//  The Linux-user suite in ../ is the real known-answer test. This one exists
//  to show that the instruction also works in full-system emulation, where the
//  vector unit is enabled by the running privileged code rather than by a
//  proxy kernel: it runs both round counts on an all-zero state and checks the
//  results, then reports over the virt machine's 16550 UART.
//
//  Freestanding: there is no libc here, so the types come from the compiler.

typedef __UINT64_TYPE__ u64;
typedef __UINT8_TYPE__  u8;

#define UART0 ((volatile u8 *)0x10000000)   // QEMU virt NS16550A, THR at +0

//  Keccak-p[1600,24] and Keccak-p[1600,12] of the all-zero state.
static const u64 exp24[25] = {
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

static const u64 exp12[25] = {
    0x8E5E5438B9A78617ULL, 0xD9CD6A50F259D01EULL, 0x87B8E7C652A91F35ULL,
    0x1093E067CDE4E0C5ULL, 0xB033AB90F2D95A45ULL, 0xE0A72F72A8DD1A45ULL,
    0xC53780AA14672F9CULL, 0x3EDD47F50051071DULL, 0xB3A31D310C178ACCULL,
    0x79B586A59257AAA0ULL, 0xBC4A7C3DB3B1F99BULL, 0x68874063E68A6793ULL,
    0x5C6C03332E0E2566ULL, 0x9CAA1202B9F030DAULL, 0x5F3B9A782BCF7A9FULL,
    0xE536C1E061AE7923ULL, 0x6DE9B618B73C87ECULL, 0x2ABED1F170918AC2ULL,
    0x6AABBD53DAED24B7ULL, 0xBFC1416A2C2EE15AULL, 0xC6CFE036B90952AFULL,
    0x45503617DC7060D7ULL, 0x625611B2C29F7AE4ULL, 0xD43671DB2C30647AULL,
    0xCFFD0D76222CA01CULL
};

//  The 32 elements of the fixed group: 25 state words plus the state tail.
static u64 buf[32];

static void uart_puts(const char *s)
{
    while (*s) {
        *UART0 = (u8)*s++;
    }
}

static u64 vlenb(void)
{
    u64 x;
    __asm volatile ("csrr %0, vlenb" : "=r"(x));
    return x;
}

//  Move all 32 elements of the group through v0 and run vkeccak.vi v0, imm5.
//  At VLEN=128 the group is v0..v15 and VLMAX at LMUL=8 is only 16, so the
//  transfer is split in two halves -- the same shape as ../keccak_insn.c.
#define RUN(imm5)                                                       \
do {                                                                    \
    if (vlenb() >= 32) {                    /* VLEN >= 256 */           \
        __asm volatile (                                                \
            "li t0, 32\n"                                               \
            "vsetvli x0, t0, e64, m8, tu, mu\n"                         \
            "vle64.v v0, 0(%[s])\n"                                     \
            ".insn r 0x77, 0x2, 0x53, x0, x18, " imm5 "\n"              \
            "vse64.v v0, 0(%[s])\n"                                     \
            : : [s]"r"(buf) : "memory", "t0");                          \
    } else {                                /* VLEN == 128 */           \
        void *hi = (void *)((char *)buf + 16 * 8);                      \
        __asm volatile (                                                \
            "vsetivli x0, 16, e64, m8, tu, mu\n"                        \
            "vle64.v v0, 0(%[s])\n"                                     \
            "vle64.v v8, 0(%[h])\n"                                     \
            ".insn r 0x77, 0x2, 0x53, x0, x18, " imm5 "\n"              \
            "vse64.v v0, 0(%[s])\n"                                     \
            "vse64.v v8, 0(%[h])\n"                                     \
            : : [s]"r"(buf), [h]"r"(hi) : "memory");                    \
    }                                                                   \
} while (0)

#define TAIL_PATTERN(i) (0xA5A5A5A500000000ULL + (i))

static void fill(void)
{
    for (int i = 0; i < 25; i++) {
        buf[i] = 0;
    }
    for (int i = 25; i < 32; i++) {
        buf[i] = TAIL_PATTERN(i);
    }
}

static int check(const u64 *exp)
{
    int fail = 0;

    for (int i = 0; i < 25; i++) {
        if (buf[i] != exp[i]) {
            fail++;
        }
    }
    //  Elements 25..31 are the state tail: bit-for-bit unchanged.
    for (int i = 25; i < 32; i++) {
        if (buf[i] != TAIL_PATTERN(i)) {
            fail++;
        }
    }
    return fail;
}

static int one(const char *name, const char *imm5_reg, const u64 *exp)
{
    int fail;

    fill();
    if (imm5_reg[1] == '0') {
        RUN("x0");                          //  imm5 = 0 -> 24 rounds
    } else {
        RUN("x1");                          //  imm5 = 1 -> 12 rounds
    }
    fail = check(exp);

    uart_puts(fail ? "[FAIL]\t" : "[PASS]\t");
    uart_puts(name);
    uart_puts("\n");
    return fail;
}

int boot_main(void)
{
    int fail = 0;

    uart_puts("[INFO]\t=== Zvknhk system-mode smoke test ===\n");
    fail += one("KECCAK-P    (imm5=0, 24 rounds)", "x0", exp24);
    fail += one("KECCAK-P12  (imm5=1, 12 rounds)", "x1", exp12);
    uart_puts(fail ? "[INFO]\tFAILED\n" : "[INFO]\tfail= 0\n");

    return fail;
}
