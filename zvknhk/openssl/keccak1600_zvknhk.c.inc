/*
 * SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*
 *  keccak1600_zvknhk.c.inc -- Zvknhk (vkeccak.vi) Keccak-p[1600] for OpenSSL
 *
 *  Copied into crypto/sha/ and #included from crypto/sha/keccak1600.c by
 *  scripts/apply-openssl-patch.sh.
 *
 *  WHERE IT LANDS.  The #include goes immediately before SHA3_absorb(), which
 *  is after every KeccakF1600() definition in the file and before the only two
 *  call sites -- one in SHA3_absorb(), one in SHA3_squeeze().  The
 *
 *      #define KeccakF1600 KeccakF1600_zvknhk_dispatch
 *
 *  at the bottom therefore redirects both.  Preprocessing is sequential, so
 *  the KeccakF1600() call inside the dispatcher -- written above the #define --
 *  is not itself replaced and the software fallback does not recurse.  That is
 *  what lets the whole thing be a single-line pure insertion into keccak1600.c
 *  instead of an edit of its call sites.
 *
 *  WHY THE PERMUTATION AND NOT THE PROVIDER.  OpenSSL's per-architecture SHA-3
 *  hook is PROV_SHA3_METHOD in providers/implementations/digests/sha3_prov.c,
 *  where s390x and ARMv8.2 install their own absorb().  Hooking there covers
 *  only what goes through the digest provider, and the ARM precedent shows the
 *  trap: shake_ARMSHA3_md accelerates absorb but leaves squeeze on the generic
 *  path, and ML-KEM's matrix expansion is squeeze-dominated (an ML-KEM-768
 *  keygen squeezes ~27 SHAKE128 blocks against ~9 absorbs).  KeccakF1600() is
 *  below all of that: absorb, final and squeeze all funnel through it, so
 *  SHA-3, SHAKE, KMAC, ML-KEM, ML-DSA and SLH-DSA are covered at once, in both
 *  the default and the FIPS provider.
 *
 *  STATE LAYOUT.  KECCAK1600_CTX.A is uint64_t[5][5] and SHA3_absorb() already
 *  treats it as flat (`A_flat = (uint64_t *)A`), so lane i is at byte offset
 *  8*i.  That is exactly the element order zvknhk.adoc defines for the fixed
 *  element group -- registers concatenated in increasing register-number order
 *  using the standard element layout -- so the state needs no marshalling.
 *
 *  COST.  A drop-in KeccakF1600() pays a 200-byte load and store around every
 *  permutation, because the state lives in memory between calls. The dispatch
 *  itself is kept off that path: VLEN is read once and passed down rather than
 *  fetched again inside the permutation, and the software fallback is behind a
 *  noinline wrapper so that the generic KeccakF1600() -- a large function --
 *  is not inlined into the dispatcher, where its stack frame would be set up
 *  on entry even when the instruction is the branch actually taken.  The way to
 *  avoid that is to keep the state in the vector registers across a whole
 *  absorb/squeeze, which means hooking SHA3_absorb()/SHA3_squeeze() instead.
 *  This file deliberately takes the simple route: it is the smallest change
 *  that makes every SHA-3 consumer in the library use the instruction.
 */

#if defined(__riscv) && __riscv_xlen == 64 && defined(OPENSSL_CPUID_OBJ)

# include "crypto/riscv_arch.h"

/*
 *  One Keccak-p[1600,24] permutation in a single instruction.
 *
 *  The assembler does not know `vkeccak.vi`, so it is emitted with `.insn`.
 *  Only two of the five R-type fields are real operands (see the Encoding
 *  section of zvknhk.adoc):
 *
 *      rd  = vd    -- the vector register holding the 1600-bit state
 *      rs1 = x18   -- NOT an operand: 0b10010 is a fixed part of the opcode
 *      rs2 = imm5  -- round-count selector; x0 => 0 => 24 rounds
 *
 *  imm5 is always 0 here: SHA-3, SHAKE and KMAC are all Keccak-f[1600].  The
 *  12-round form exists for TurboSHAKE/KangarooTwelve, which OpenSSL has no
 *  consumer for.
 *
 *  vd = v0 is an NREG-aligned group start at every VLEN.  vl and LMUL matter
 *  only to the surrounding vle64/vse64 that move the 25 live state words: at
 *  LMUL=8 the largest usable vl is VLMAX = 8*VLEN/64, which is >= 25 for
 *  VLEN >= 256 but only 16 at VLEN = 128, so there the transfer is split in
 *  two.  Both halves stay inside the 16-register group that vd=v0 spans.
 *
 *  OpenSSL passes no -march when cross-building RISC-V, so whether V is
 *  available to the assembler depends entirely on how the toolchain was
 *  configured.  `.option arch, +v` makes the block assemble either way; it
 *  costs nothing when V is already on.
 *
 *  The clobber list is not optional.  When the default -march does include V,
 *  GCC auto-vectorises the surrounding C -- SHA3_absorb() compiles to VLA
 *  vector code, `csrr vlenb` and all -- so vector state can be live across
 *  this asm once the permutation is inlined into it.  vl and vtype must be
 *  declared too: GCC tracks vtype to elide redundant vsetvli, and the
 *  vsetivli below invalidates that.  v0-v15 covers the widest element group,
 *  NREG = ceil(2048/VLEN) = 16 at the VLEN=128 floor; larger VLEN spans fewer
 *  registers, so one list is safe for both paths.
 */

#define VKECCAK_CLOBBERS                                        \
    "memory", "vl", "vtype",                                    \
    "v0", "v1", "v2",  "v3",  "v4",  "v5",  "v6",  "v7",        \
    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15"
static void KeccakF1600_zvknhk(uint64_t A[5][5], size_t vlen)
{
    uint64_t *S = (uint64_t *)A;

    if (vlen >= 256) {
        __asm volatile (
            ".option push\n"
            ".option arch, +v\n"
            "vsetivli x0, 25, e64, m8, tu, mu\n"
            "vle64.v  v0, 0(%[s])\n"
            /*  vkeccak.vi v0, 0                                  */
            /*  .insn r opc, func3, func7, rd, rs1, rs2           */
            ".insn r 0x77, 0x2, 0x53, x0, x18, x0\n"
            "vse64.v  v0, 0(%[s])\n"
            ".option pop\n"
            :
            : [s]"r"(S)
            : VKECCAK_CLOBBERS
        );
    } else {                                    /*  VLEN == 128  */
        uint64_t *hi = S + 16;

        __asm volatile (
            ".option push\n"
            ".option arch, +v\n"
            "vsetivli x0, 16, e64, m8, tu, mu\n"
            "vle64.v  v0, 0(%[s])\n"
            "vsetivli x0, 9, e64, m8, tu, mu\n"
            "vle64.v  v8, 0(%[h])\n"
            ".insn r 0x77, 0x2, 0x53, x0, x18, x0\n"
            "vsetivli x0, 16, e64, m8, tu, mu\n"
            "vse64.v  v0, 0(%[s])\n"
            "vsetivli x0, 9, e64, m8, tu, mu\n"
            "vse64.v  v8, 0(%[h])\n"
            ".option pop\n"
            :
            : [s]"r"(S), [h]"r"(hi)
            : VKECCAK_CLOBBERS
        );
    }
}

/*
 *  RISCV_HAS_ZVKNHK() reads OPENSSL_riscvcap_P[], filled in by
 *  OPENSSL_cpuid_setup() at library init.  Zvknhk has no hwprobe key -- it is
 *  not an upstream extension -- so on emulators it is turned on through the
 *  environment, e.g. OPENSSL_riscvcap=rv64gc_v_zvknhk.  The _v_ must be spelled
 *  separately: parse_env() looks for a literal "_V", and riscv_vlen() is only
 *  probed when RISCV_HAS_V() is set, so without it VLEN reads back as 0 and
 *  this test correctly declines.
 */
# if defined(__GNUC__)
#  define VKECCAK_NOINLINE __attribute__((noinline))
# else
#  define VKECCAK_NOINLINE
# endif

/*  Kept out of line: see COST above.  */
static VKECCAK_NOINLINE void KeccakF1600_generic(uint64_t A[5][5])
{
    KeccakF1600(A);             /*  still the real function here  */
}

static void KeccakF1600_zvknhk_dispatch(uint64_t A[5][5])
{
    size_t vlen = RISCV_HAS_ZVKNHK() ? riscv_vlen() : 0;

    if (vlen >= 128)
        KeccakF1600_zvknhk(A, vlen);
    else
        KeccakF1600_generic(A);
}

# undef VKECCAK_CLOBBERS
# undef VKECCAK_NOINLINE

# define KeccakF1600 KeccakF1600_zvknhk_dispatch

#endif  /*  __riscv && __riscv_xlen == 64 && OPENSSL_CPUID_OBJ  */
