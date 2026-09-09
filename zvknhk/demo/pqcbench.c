// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
/*
 *  pqcbench.c -- ML-KEM / ML-DSA driver for instruction and cycle counting
 *
 *  Two ways to get numbers out of this, because the two platforms we care
 *  about measure differently:
 *
 *    pqcbench <op> <n>            run the operation n times, print nothing.
 *                                 For emulators: count from the outside with
 *                                 QEMU's TCG plugin (see `make count`), then
 *                                 difference n against 2n to cancel startup.
 *
 *    pqcbench <op> <n> <reps>     read rdcycle/rdinstret around the loop and
 *                                 report the best of <reps> runs. For real
 *                                 hardware.
 *
 *  DO NOT TRUST THE CSRs UNDER QEMU. In user mode qemu answers every counter
 *  CSR -- cycle, instret and all the hpmcounters -- from read_hpmcounter() ->
 *  get_ticks() -> cpu_get_host_ticks(), i.e. the HOST cpu's cycle counter
 *  (target/riscv/tcg/csr.c). So both come back as host TSC ticks: a 1M-
 *  iteration loop measured 76,301,877 "instructions" in a process the TCG
 *  plugin counted at 5,149,196 in total, with `cycle` reporting 76,301,718 --
 *  the same quantity read twice. counter_note() checks instret against a
 *  probe of known length and says so.
 *
 *  Under Spike behind pk, use the two-argument form. pk does not permit
 *  rdcycle from user mode and aborts the process on the trap rather than
 *  delivering SIGILL, so the probe below cannot save it.
 *
 *  Everything is deterministic on purpose. ML-DSA signing is hedged and uses
 *  rejection sampling, so runs with different keys and per-signature
 *  randomness do genuinely different amounts of Keccak -- enough to swamp the
 *  effect being measured. Keys are grown from a fixed seed and signatures
 *  taken in deterministic mode, so two builds perform identical work.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static void die(const char *m) { fprintf(stderr, "fail: %s\n", m); exit(1); }

/*  ML-DSA takes a 32-byte seed (xi); ML-KEM takes 64 (d || z).  */
#define ML_DSA_SEEDLEN 32
#define ML_KEM_SEEDLEN 64

/*
 *  The seed is SINGLE USE. Both providers erase it once the key is generated
 *  -- ml_kem_kmgmt.c "Erase the single-use seed", and ml_dsa_kmgmt.c cleansing
 *  gctx->entropy -- so a generation context that is seeded once and then
 *  reused produces one deterministic key followed by random ones. That is not
 *  a subtle effect: it moved measured ML-KEM keygen from 2,093,960 insn/op at
 *  N=2 to 508,318 at N=41, because the second generation is the one that pays
 *  to initialise the DRBG. body() therefore re-applies the seed before every
 *  generation, from a master copy, so the provider is free to erase its own.
 */
static const unsigned char seed_master[ML_KEM_SEEDLEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

static unsigned char seed[ML_KEM_SEEDLEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};

static const OSSL_PARAM *seed_params(size_t seedlen)
{
    static OSSL_PARAM p[2];

    memcpy(seed, seed_master, sizeof(seed));    /*  see seed_master above  */
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                             seed, seedlen);
    p[1] = OSSL_PARAM_construct_end();
    return p;
}

static const OSSL_PARAM *det_params(void)
{
    static int one = 1;
    static OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &one);
    p[1] = OSSL_PARAM_construct_end();
    return p;
}

static EVP_PKEY_CTX *keygen_ctx(const char *alg, size_t seedlen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);

    if (c == NULL || EVP_PKEY_keygen_init(c) <= 0
        || EVP_PKEY_CTX_set_params(c, seed_params(seedlen)) <= 0)
        die("keygen init");
    return c;
}

static EVP_PKEY *keygen(const char *alg, size_t seedlen)
{
    EVP_PKEY_CTX *c = keygen_ctx(alg, seedlen);
    EVP_PKEY *k = NULL;

    if (EVP_PKEY_generate(c, &k) <= 0)
        die("keygen");
    EVP_PKEY_CTX_free(c);
    return k;
}

/* ------------------------------------------------------------ the ops --- */

enum op_id {
    OP_MLKEM_KEYGEN, OP_MLKEM_ENCAP, OP_MLKEM_DECAP,
    OP_MLDSA_KEYGEN, OP_MLDSA_SIGN,  OP_MLDSA_VERIFY, OP_NONE
};

static const char *op_names[] = {
    "mlkem-keygen", "mlkem-encap", "mlkem-decap",
    "mldsa-keygen", "mldsa-sign",  "mldsa-verify"
};

typedef struct {
    EVP_PKEY_CTX *gctx, *kctx;
    EVP_PKEY *key;
    size_t seedlen;
    unsigned char ct[4096], ss[64], sig[8192], msg[32];
    size_t ctl, ssl, sigl;
} bench;

static void setup(enum op_id op, bench *b)
{
    memset(b, 0, sizeof(*b));

    switch (op) {
    case OP_MLKEM_KEYGEN:
        b->seedlen = ML_KEM_SEEDLEN;
        b->gctx = keygen_ctx("ML-KEM-768", ML_KEM_SEEDLEN);
        break;

    case OP_MLKEM_ENCAP:
    case OP_MLKEM_DECAP:
        b->key = keygen("ML-KEM-768", ML_KEM_SEEDLEN);
        b->kctx = EVP_PKEY_CTX_new_from_pkey(NULL, b->key, NULL);
        if (b->kctx == NULL || EVP_PKEY_encapsulate_init(b->kctx, NULL) <= 0)
            die("encap init");
        b->ctl = sizeof(b->ct); b->ssl = sizeof(b->ss);
        if (EVP_PKEY_encapsulate(b->kctx, b->ct, &b->ctl, b->ss, &b->ssl) <= 0)
            die("encap");
        if (op == OP_MLKEM_DECAP
            && EVP_PKEY_decapsulate_init(b->kctx, NULL) <= 0)
            die("decap init");
        break;

    case OP_MLDSA_KEYGEN:
        b->seedlen = ML_DSA_SEEDLEN;
        b->gctx = keygen_ctx("ML-DSA-65", ML_DSA_SEEDLEN);
        break;

    case OP_MLDSA_SIGN:
        b->key = keygen("ML-DSA-65", ML_DSA_SEEDLEN);
        break;

    case OP_MLDSA_VERIFY: {
        EVP_MD_CTX *m = EVP_MD_CTX_new();

        b->key = keygen("ML-DSA-65", ML_DSA_SEEDLEN);
        if (EVP_DigestSignInit_ex(m, NULL, NULL, NULL, NULL, b->key,
                                  det_params()) <= 0)
            die("sign init");
        b->sigl = sizeof(b->sig);
        if (EVP_DigestSign(m, b->sig, &b->sigl, b->msg, sizeof(b->msg)) <= 0)
            die("sign");
        EVP_MD_CTX_free(m);
        break;
    }
    default:
        die("op");
    }
}

static void body(enum op_id op, bench *b, long n)
{
    EVP_PKEY *k;
    EVP_MD_CTX *m;
    size_t l1, l2;
    long i;

    for (i = 0; i < n; i++) {
        switch (op) {
        case OP_MLKEM_KEYGEN:
        case OP_MLDSA_KEYGEN:
            k = NULL;
            /*  Re-seed every time: the provider erased the last one.  */
            if (EVP_PKEY_CTX_set_params(b->gctx, seed_params(b->seedlen)) <= 0)
                die("re-seed");
            if (EVP_PKEY_generate(b->gctx, &k) <= 0)
                die("generate");
            EVP_PKEY_free(k);
            break;

        case OP_MLKEM_ENCAP:
            l1 = sizeof(b->ct); l2 = sizeof(b->ss);
            if (EVP_PKEY_encapsulate(b->kctx, b->ct, &l1, b->ss, &l2) <= 0)
                die("encap");
            break;

        case OP_MLKEM_DECAP:
            l2 = sizeof(b->ss);
            if (EVP_PKEY_decapsulate(b->kctx, b->ss, &l2, b->ct, b->ctl) <= 0)
                die("decap");
            break;

        case OP_MLDSA_SIGN:
            m = EVP_MD_CTX_new();
            if (EVP_DigestSignInit_ex(m, NULL, NULL, NULL, NULL, b->key,
                                      det_params()) <= 0)
                die("sign init");
            l1 = sizeof(b->sig);
            if (EVP_DigestSign(m, b->sig, &l1, b->msg, sizeof(b->msg)) <= 0)
                die("sign");
            EVP_MD_CTX_free(m);
            break;

        case OP_MLDSA_VERIFY:
            m = EVP_MD_CTX_new();
            if (EVP_DigestVerifyInit_ex(m, NULL, NULL, NULL, NULL, b->key,
                                        NULL) <= 0)
                die("verify init");
            if (EVP_DigestVerify(m, b->sig, b->sigl, b->msg,
                                 sizeof(b->msg)) <= 0)
                die("verify");
            EVP_MD_CTX_free(m);
            break;

        default:
            die("op");
        }
    }
}

static void teardown(bench *b)
{
    EVP_PKEY_CTX_free(b->gctx);
    EVP_PKEY_CTX_free(b->kctx);
    EVP_PKEY_free(b->key);
}

/* ------------------------------------------------------- the counters --- */

#define RDCYCLE()   ({ uint64_t x; __asm volatile("csrr %0, cycle"  : "=r"(x)); x; })
#define RDINSTRET() ({ uint64_t x; __asm volatile("csrr %0, instret": "=r"(x)); x; })

static sigjmp_buf probe_jb;
static volatile sig_atomic_t probe_ok;

static void on_sigill(int s) { (void)s; probe_ok = 0; siglongjmp(probe_jb, 1); }

/*
 *  cycle and instret are only readable from user mode if mcounteren grants it.
 *  Linux normally does; a bare FPGA image or a restricted kernel may not.
 *  Probe rather than assume, so the tool degrades to wall clock instead of
 *  dying. This works wherever the OS turns the trap into a SIGILL -- verified
 *  under Linux and qemu-riscv64, where an unassigned CSR is caught and the
 *  process survives. It cannot help under pk, which aborts on the trap itself.
 */
static int counters_readable(void)
{
    struct sigaction sa, old;
    volatile uint64_t x;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigill;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGILL, &sa, &old);

    probe_ok = 1;
    if (sigsetjmp(probe_jb, 1) == 0) {
        x = RDCYCLE();
        x = RDINSTRET();
        (void)x;
    }
    sigaction(SIGILL, &old, NULL);
    return probe_ok;
}

/*
 *  A probe with an exactly known retired-instruction count: two instructions
 *  per iteration, in asm so the compiler cannot change the number.
 *
 *  This replaces an earlier heuristic that flagged "cycle == instret" as proof
 *  of an emulator. That test is wrong on the hardware this tool is meant for:
 *  a simple in-order core running a tight ALU loop can legitimately retire at
 *  CPI 1.0, and would have been reported as fake. Matching instret against a
 *  known count is the property that actually distinguishes a retirement
 *  counter from a clock.
 */
static uint64_t spin(uint64_t iters)
{
    uint64_t k = iters;

    __asm volatile ("1:\n\t"
                    "addi %0, %0, -1\n\t"
                    "bnez %0, 1b\n"
                    : "+r"(k) : : );
    return iters * 2;
}

static uint64_t now_ns(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

/*
 *  Printed once, before the table. Advisory rather than a per-row verdict:
 *  the reader is told what the counter did on a known workload and can judge.
 */
static int counter_note(int have)
{
    uint64_t expect, i0, i1, n0, n1, got, ns;
    double ratio;

    if (!have) {
        printf("counter check: cycle/instret not readable from user mode; "
               "reporting wall clock only\n\n");
        return 0;
    }
    n0 = now_ns();
    i0 = RDINSTRET();
    expect = spin(2000000);
    i1 = RDINSTRET();
    n1 = now_ns();
    got = i1 - i0;
    ns = n1 - n0;
    ratio = (double)got / (double)expect;

    printf("counter check: instret %llu over a %llu-instruction probe "
           "(x%.2f), %llu ns\n",
           (unsigned long long)got, (unsigned long long)expect, ratio,
           (unsigned long long)ns);
    if (ratio < 0.9 || ratio > 1.1) {
        printf("  ** instret does not track retired instructions: this is not "
               "a hardware counter.\n"
               "  ** qemu-riscv64 answers every counter CSR from the host "
               "cpu's tick counter.\n"
               "  ** Run natively on the target; see `make count` for "
               "emulator measurement.\n");
        printf("\n");
        return 0;
    }
    printf("\n");
    return 1;
}

static void measure(enum op_id op, long n, int reps, int have)
{
    uint64_t bc = UINT64_MAX, bi = 0, bn = UINT64_MAX, bnc = UINT64_MAX;
    int r;
    bench b;

    setup(op, &b);
    body(op, &b, 1);                            /* warm caches and lazy init */

    for (r = 0; r < reps; r++) {
        uint64_t c0 = 0, i0 = 0, c1 = 0, i1 = 0, n0, n1;

        n0 = now_ns();
        if (have) { c0 = RDCYCLE(); i0 = RDINSTRET(); }
        body(op, &b, n);
        if (have) { i1 = RDINSTRET(); c1 = RDCYCLE(); }
        n1 = now_ns();

        /*
         *  Keep a whole tuple from one repetition. Minimising cycles,
         *  instructions and time independently would report a CPI that no
         *  single run ever produced.
         */
        if (have && c1 - c0 < bc) {
            bc = c1 - c0;
            bi = i1 - i0;
            bn = n1 - n0;
        }
        if (n1 - n0 < bnc)
            bnc = n1 - n0;
    }
    teardown(&b);

    if (!have) {
        printf("%-14s %12s %12s %7s %12.0f\n",
               op_names[op], "-", "-", "-", (double)bnc / n);
        return;
    }
    printf("%-14s %12.0f %12.0f %7.3f %12.0f\n",
           op_names[op], (double)bc / n, (double)bi / n,
           bi ? (double)bc / (double)bi : 0.0, (double)bn / n);
}

static long positive(const char *s, const char *what)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v <= 0) {
        fprintf(stderr, "fail: %s must be a positive integer, got \"%s\"\n",
                what, s);
        exit(2);
    }
    return v;
}

int main(int argc, char **argv)
{
    const char *op = argc > 1 ? argv[1] : "";
    long n = argc > 2 ? positive(argv[2], "n") : 1;
    int reps = argc > 3 ? (int)positive(argv[3], "reps") : 0;
    enum op_id id = OP_NONE;
    size_t i;

    for (i = 0; i < sizeof(op_names) / sizeof(op_names[0]); i++)
        if (!strcmp(op, op_names[i]))
            id = (enum op_id)i;

    /*  "all" measures every op in one process, so the header prints once.  */
    if (!strcmp(op, "all") && reps > 0) {
        int have = counters_readable();

        counter_note(have);
        printf("%-14s %12s %12s %7s %12s\n",
               "op", "cycles/op", "insns/op", "CPI", "ns/op");
        for (i = 0; i < sizeof(op_names) / sizeof(op_names[0]); i++)
            measure((enum op_id)i, n, reps, have);
        return 0;
    }

    if (!strcmp(op, "fingerprint")) {
        /*
         *  A differential oracle for the whole PQC path. Keys come from a
         *  fixed seed and the signature is deterministic, so these digests are
         *  a pure function of the Keccak implementation. Running this with the
         *  capability on and off and requiring identical output checks
         *  vkeccak.vi against the software path across matrix expansion,
         *  CBD/rejection sampling and the signing loop -- which the round-trip
         *  tests, being self-consistent, cannot do. SHA-256 is used for the
         *  digest precisely because it is not Keccak.
         */
        unsigned char buf[8192], md[32], msg[32] = { 0 }, sig[8192];
        unsigned int mdl;
        size_t bl = 0, sigl, j;
        EVP_PKEY *k;
        EVP_MD_CTX *m;

        k = keygen("ML-KEM-768", ML_KEM_SEEDLEN);
        if (EVP_PKEY_get_octet_string_param(k, "pub", buf, sizeof(buf), &bl) <= 0)
            die("ml-kem pub");
        EVP_Digest(buf, bl, md, &mdl, EVP_sha256(), NULL);
        printf("ml-kem-768-pub ");
        for (j = 0; j < mdl; j++) printf("%02x", md[j]);
        printf("\n");
        EVP_PKEY_free(k);

        k = keygen("ML-DSA-65", ML_DSA_SEEDLEN);
        if (EVP_PKEY_get_octet_string_param(k, "pub", buf, sizeof(buf), &bl) <= 0)
            die("ml-dsa pub");
        EVP_Digest(buf, bl, md, &mdl, EVP_sha256(), NULL);
        printf("ml-dsa-65-pub  ");
        for (j = 0; j < mdl; j++) printf("%02x", md[j]);
        printf("\n");

        m = EVP_MD_CTX_new();
        if (EVP_DigestSignInit_ex(m, NULL, NULL, NULL, NULL, k, det_params()) <= 0)
            die("sign init");
        sigl = sizeof(sig);
        if (EVP_DigestSign(m, sig, &sigl, msg, sizeof(msg)) <= 0)
            die("sign");
        EVP_MD_CTX_free(m);
        EVP_Digest(sig, sigl, md, &mdl, EVP_sha256(), NULL);
        printf("ml-dsa-65-sig  ");
        for (j = 0; j < mdl; j++) printf("%02x", md[j]);
        printf("\n");
        EVP_PKEY_free(k);
        return 0;
    }

    if (id == OP_NONE) {
        fprintf(stderr,
            "usage: %s <op> <n> [reps]\n"
            "  ops: mlkem-keygen mlkem-encap mlkem-decap\n"
            "       mldsa-keygen mldsa-sign  mldsa-verify\n"
            "       all (with reps)  fingerprint\n"
            "  two args : run n times, print nothing (count from outside)\n"
            "  three    : read rdcycle/rdinstret, best of <reps>\n", argv[0]);
        return 2;
    }

    if (reps > 0) {
        int have = counters_readable();

        counter_note(have);
        printf("%-14s %12s %12s %7s %12s\n",
               "op", "cycles/op", "insns/op", "CPI", "ns/op");
        measure(id, n, reps, have);
    } else {
        bench b;

        setup(id, &b);
        body(id, &b, n);
        teardown(&b);
    }
    return 0;
}
