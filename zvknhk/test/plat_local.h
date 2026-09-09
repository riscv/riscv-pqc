// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
//  plat_local.h
//  2023-10-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === Localization affecting all implementations can be inserted here.

#ifndef _PLAT_LOCAL_H_
#define _PLAT_LOCAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef PLAT_VERS_STR
#define PLAT_VERS_STR "dev version"
#define PLAT_VERS_MAJ 0
#define PLAT_VERS_MIN 0
#endif

//  === platform detection logic

#ifndef PLAT_XLEN

#if defined(__riscv) && (__riscv_xlen == 32)
#define PLAT_XLEN 32
#define PLAT_ARCH_STR "PLAT_ARCH_RV32"
#define PLAT_ARCH_RV32

#elif defined(__riscv)
#define PLAT_XLEN 64
#define PLAT_ARCH_STR "PLAT_ARCH_RV64"
#define PLAT_ARCH_RV64

#elif defined(__arm__)
#define PLAT_XLEN 32
#define PLAT_ARCH_STR "PLAT_ARCH_ARM32"
#define PLAT_ARCH_ARM32

#elif defined(__aarch64__)
#define PLAT_XLEN 64
#define PLAT_ARCH_STR "PLAT_ARCH_ARM64"
#define PLAT_ARCH_ARM64

#elif defined(__i386__)
#define PLAT_XLEN 32
#define PLAT_ARCH_STR "PLAT_ARCH_IA32"
#define PLAT_ARCH_IA32

#elif defined(__x86_64__)
#define PLAT_XLEN 64
#define PLAT_ARCH_STR "PLAT_ARCH_X64"
#define PLAT_ARCH_X64

#elif (__WORDSIZE == 32)
#define PLAT_XLEN 32
#define PLAT_ARCH_STR "PLAT_ARCH_GEN32"
#define PLAT_ARCH_GEN32

#else
//  fallback for everything
#define PLAT_XLEN 64
#define PLAT_ARCH_STR "PLAT_ARCH_GEN64"
#define PLAT_ARCH_GEN64
#endif

//  PLAT_XLEN signals that the rest of the macros are defined too
#endif

//  Byte alignment macro XALIGN

#if defined(__GNUC__)
#define XALIGN(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
#define XALIGN(x) __declspec(align(x))
#elif defined(__ARMCC_VERSION)
#define XALIGN(x) __align(x)
#else
#define XALIGN(x)
#endif

//  === Assume-Assert checks

//  No-op for production
#ifndef __CPROVER__

#ifndef XDEBUG
#define XASSERT(x)
#define XASSUME(x)
#define XTMPVAR(x)

//  Runtime checks in debug build
#else
#include <assert.h>
#define XASSERT(x) assert(x)
#define XASSUME(x) assert(x)
#define XTMPVAR(x) x
//  XDEBUG
#endif

//  For CBMC (formal checks)
#else
#include <stdio.h>
#include <assert.h>
#define XASSERT(x) assert(x)
#define XASSUME(x) __CPROVER_assume(x)
#define XTMPVAR(x) x
#define XPROOFS
#endif  //  __CPROVER__

#if defined(PLAT_ARCH_RV32)

//  Count cycles & instructions ESP32C6 with performance counters.

//  sel_counter(1):     count cycles
//  sel_counter(2):     count instructions
//  There are other possible counters; see documentation.

static inline void exp32c6_sel_counter(int val)
{
    __asm__ volatile ("csrw  0x7e0, %0"     //  mpcer = 0x7e0
                        : : "r" (val));     //  1: cycle, 2: inst
    __asm__ volatile ("csrw  0x7e1, 1");    //  mpcmr = 0x7e1, 1: enable
}

//  return counter

static inline uint32_t exp32c6_get_count()
{
    uint32_t cc;
    __asm__ volatile ("csrr %0, 0x7e2"      //  mpccr = 0x7e2
                        : "=r"(cc));
    return cc;
}
#endif

#if defined(PLAT_ARCH_RV64)

static inline uint64_t plat_get_instret()
{
    uint64_t r;
    __asm__ volatile("rdinstret %0" : "=r"(r));
    return r;
}

static inline uint64_t rv_get_mcycle()
{
    uint64_t r;
    __asm__ volatile ("csrr %0, 0xB00"      //  mcycle = 0xB00
                        : "=r"(r));
    return r;
}

static inline uint64_t rv_get_minstret()
{
    uint64_t r;
    __asm__ volatile ("csrr %0, 0xB02"      //  minstret = 0xB02
                        : "=r"(r));
    return r;
}

static inline uint64_t rv_get_vlenb()
{
    uint64_t r;
    __asm__ volatile ("csrr %0, 0xC22"      //  vlenb = 0xC22
                        : "=r"(r));
    return r;
}

#endif

//  get cycle counts

static inline uint64_t plat_get_cycle()
{

#if defined(PLAT_ARCH_RV64)

    uint64_t cnt = 0;
    __asm__ volatile("rdcycle %0" : "=r"(cnt));
    return cnt;

#elif defined(PLAT_ARCH_RV32)

    uint32_t lo, hi;
    __asm__ volatile("rdcycle %0" : "=r"(lo));
    __asm__ volatile("rdcycleh %0" : "=r"(hi));
    return (((uint64_t) hi) << 32) | ((uint64_t) lo);

#elif defined(PLAT_ARCH_IA32) || defined(PLAT_ARCH_X64)

    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (((uint64_t) hi) << 32) | ((uint64_t) lo);

#else

    //  ARM cycle counts may not be available in userland
    return 0;
#endif
}

//  revert if not big endian

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
//  nop
#define rev8_be32(x) (x)
#else
//  RISC-V: grev(x, 0x18) or rev8

static inline uint32_t rev8_be32(uint32_t x)
{
    return ((x & 0xFF000000) >> 24) | ((x & 0x00FF0000) >> 8) |
           ((x & 0x0000FF00) << 8) | ((x & 0x000000FF) << 24);
}
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define rev8_be64(x) (x)
#else
//  RISC-V: grev(x, 0x38) or rev8(x)
static inline uint64_t rev8_be64(uint64_t x)
{
    return (x << 56) | ((x & 0x000000000000FF00LL) << 40) |
           ((x & 0x0000000000FF0000LL) << 24) |
           ((x & 0x00000000FF000000LL) << 8) |
           ((x & 0x000000FF00000000LL) >> 8) |
           ((x & 0x0000FF0000000000LL) >> 24) |
           ((x & 0x00FF000000000000LL) >> 40) | (x >> 56);
}
#endif

//  rotate left (for convenience)

static inline uint32_t rol32(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

static inline uint64_t rol64(uint64_t x, uint64_t n)
{
    return (x << n) | (x >> (64 - n));
}

//  rotate right (RISC-V ROR or RORI)

static inline uint32_t ror32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32 - n));
}

static inline uint64_t ror64(uint64_t x, uint64_t n)
{
    return (x >> n) | (x << (64 - n));
}

//  and with negate (RISC-V ANDN)

static inline uint32_t andn32(uint32_t x, uint32_t y)
{
    return x & ~y;
}

static inline uint64_t andn64(uint64_t x, uint64_t y)
{
    return x & ~y;
}

//  little-endian loads and stores (unaligned)

static inline uint16_t get16u_le(const uint8_t* v)
{
    return (((uint16_t) v[1]) << 8) | ((uint16_t) v[0]);
}

static inline void put16u_le(uint8_t* v, uint16_t x)
{
    v[0] = x;
    v[1] = x >> 8;
}

static inline uint32_t get32u_le(const uint8_t* v)
{
    return ((uint32_t) v[0]) | (((uint32_t) v[1]) << 8) |
           (((uint32_t) v[2]) << 16) | (((uint32_t) v[3]) << 24);
}

static inline void put32u_le(uint8_t* v, uint32_t x)
{
    v[0] = x;
    v[1] = x >> 8;
    v[2] = x >> 16;
    v[3] = x >> 24;
}

static inline uint64_t get64u_le(const uint8_t* v)
{
    return ((uint64_t) v[0]) | (((uint64_t) v[1]) << 8) |
           (((uint64_t) v[2]) << 16) | (((uint64_t) v[3]) << 24) |
           (((uint64_t) v[4]) << 32) | (((uint64_t) v[5]) << 40) |
           (((uint64_t) v[6]) << 48) | (((uint64_t) v[7]) << 56);
}

static inline void put64u_le(uint8_t* v, uint64_t x)
{
    v[0] = x;
    v[1] = x >> 8;
    v[2] = x >> 16;
    v[3] = x >> 24;
    v[4] = x >> 32;
    v[5] = x >> 40;
    v[6] = x >> 48;
    v[7] = x >> 56;
}

//  big-endian loads and stores (unaligned)

static inline uint16_t get16u_be(const uint8_t* v)
{
    return (((uint16_t) v[0]) << 8) | ((uint16_t) v[1]);
}

static inline void put16u_be(uint8_t* v, uint16_t x)
{
    v[0] = x >> 8;
    v[1] = x;
}

static inline uint32_t get32u_be(const uint8_t* v)
{
    return (((uint32_t) v[0]) << 24) | (((uint32_t) v[1]) << 16) |
           (((uint32_t) v[2]) << 8) | ((uint32_t) v[3]);
}

static inline void put32u_be(uint8_t* v, uint32_t x)
{
    v[0] = x >> 24;
    v[1] = x >> 16;
    v[2] = x >> 8;
    v[3] = x;
}

static inline uint64_t get64u_be(const uint8_t* v)
{
    return (((uint64_t) v[0]) << 56) | (((uint64_t) v[1]) << 48) |
           (((uint64_t) v[2]) << 40) | (((uint64_t) v[3]) << 32) |
           (((uint64_t) v[4]) << 24) | (((uint64_t) v[5]) << 16) |
           (((uint64_t) v[6]) << 8) | ((uint64_t) v[7]);
}

static inline void put64u_be(uint8_t* v, uint64_t x)
{
    v[0] = x >> 56;
    v[1] = x >> 48;
    v[2] = x >> 40;
    v[3] = x >> 32;
    v[4] = x >> 24;
    v[5] = x >> 16;
    v[6] = x >> 8;
    v[7] = x;
}

#ifdef __cplusplus
}
#endif

//  _PLAT_LOCAL_H_
#endif
