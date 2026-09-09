// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
//  turbo_api.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === RFC 9861: TurboSHAKE eXtensible Output Functions (XOF)
//      Sponge padding mode code for testing permutation implementations.

#ifndef NO_TURBO
#include "turbo_api.h"

//  As with sha3_api.c, these functions are not optimized -- they exist to
//  exercise the permutation. TurboSHAKE is the SHAKE sponge with the
//  reduced-round Keccak-p[1600,12] permutation and a caller-chosen domain
//  separation byte.

//  initialize the context

void turbo_init(turbo_ctx_t *c, int cap, uint8_t dsep)
{
    int i;

    for (i = 0; i < 25; i++)
        c->st.d[i] = 0;
    c->rsiz = 200 - cap;
    c->pt = 0;
    c->dsep = dsep;
    c->fin = 0;
}

//  update state with more data

void turbo_update(turbo_ctx_t *c, const void *data, size_t len)
{
    size_t i;
    int j;

    j = c->pt;
    for (i = 0; i < len; i++) {
        c->st.b[j++] ^= ((const uint8_t *) data)[i];
        if (j >= c->rsiz) {
            keccak_p1600_12(c->st.d);
            j = 0;
        }
    }
    c->pt = j;
}

//  squeeze output

void turbo_out(turbo_ctx_t *c, uint8_t *out, size_t len)
{
    size_t i;
    int j;

    //  add padding on the first call: the domain separation byte, then
    //  pad10*1 finished off with 0x80 in the last byte of the rate
    if (!c->fin) {
        c->st.b[c->pt] ^= c->dsep;
        c->st.b[c->rsiz - 1] ^= 0x80;
        keccak_p1600_12(c->st.d);
        c->pt = 0;
        c->fin = 1;
    }

    j = c->pt;
    for (i = 0; i < len; i++) {
        if (j >= c->rsiz) {
            keccak_p1600_12(c->st.d);
            j = 0;
        }
        out[i] = c->st.b[j++];
    }
    c->pt = j;
}

//  one-shot

void *turboshake(uint8_t *out, size_t outlen, const void *in, size_t inlen,
                 int cap, uint8_t dsep)
{
    turbo_ctx_t turbo;

    turbo_init(&turbo, cap, dsep);
    turbo_update(&turbo, in, inlen);
    turbo_out(&turbo, out, outlen);

    return out;
}

//  !NO_TURBO
#endif
