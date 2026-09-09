// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
//  turbo_api.h
//  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === RFC 9861: TurboSHAKE eXtensible Output Functions (XOF)

#ifndef _TURBO_API_H_
#define _TURBO_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct {            //  state context
    union {
        uint8_t b[200];     //  8-bit bytes
        uint64_t d[25];     //  64-bit words
    } st;
    int pt, rsiz;
    uint8_t dsep;           //  domain separation byte, 0x01..0x7F
    int fin;                //  padding has been applied
} turbo_ctx_t;

//  incremental interface; "cap" is the capacity in bytes, "dsep" the
//  domain separation byte D
void turbo_init(turbo_ctx_t *c, int cap, uint8_t dsep);
void turbo_update(turbo_ctx_t *c, const void *data, size_t len);

//  squeeze output (can call repeatedly); pads on the first call
void turbo_out(turbo_ctx_t *c, uint8_t *out, size_t len);

//  TurboSHAKE128 has a 256-bit capacity, TurboSHAKE256 a 512-bit one
#define turboshake128_init(c, d) turbo_init(c, 32, d)
#define turboshake256_init(c, d) turbo_init(c, 64, d)

//  one-shot: TurboSHAKE(M=in, D=dsep, outlen) -> out
void *turboshake(uint8_t *out, size_t outlen, const void *in, size_t inlen,
                 int cap, uint8_t dsep);

//  core permutation, Keccak-p[1600,12]
void keccak_p1600_12(void *st);

#ifdef __cplusplus
}
#endif

#endif  //  _TURBO_API_H_
