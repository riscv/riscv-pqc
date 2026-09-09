// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
#include <stdio.h>
#include "plat_local.h"

void hex(const char *lab, const void *dat, size_t len)
{
    size_t i;

    printf("%24s =", lab);
    for (i = 0; i < len; i++) {
        printf(" %02X", ((const uint8_t *) dat)[i]);
    }
    printf("\n");
}

int test_sha3();
int test_turbo();
int rij256_test();

int main()
{
    int fail = 0;
    //  standard tests

    const uint32_t c32 = 0x01020304;
    const uint64_t c64 = 0x0102030405060708;

    printf("%24s = %s\n", "PLAT_ARCH_STR", PLAT_ARCH_STR);
    printf("%24s = %d\n", "PLAT_XLEN", (int) PLAT_XLEN);
    hex("0x01020304", &c32, sizeof(c32));
    hex("0x0102030405060708", &c64, sizeof(c64));

    printf("%24s = %d\n", "sizeof(char)",           (int) sizeof(char));
    printf("%24s = %d\n", "sizeof(short)",          (int) sizeof(short));
    printf("%24s = %d\n", "sizeof(int)",            (int) sizeof(int));
    printf("%24s = %d\n", "sizeof(void *)",         (int) sizeof(void *));
    printf("%24s = %d\n", "sizeof(long)",           (int) sizeof(long));
    printf("%24s = %d\n", "sizeof(long long)",      (int) sizeof(long long));
    printf("%24s = %d\n", "sizeof(size_t)",         (int) sizeof(size_t));
    printf("%24s = %d\n", "((char) 0xFF)",          (int) ((char) 0xFF));
    printf("%24s = %d\n", "((unsigned char) 0xFF)", (int) ((unsigned char) 0xFF));

    printf("%24s = %ld\n", "vlen",      8 * rv_get_vlenb());
    printf("%24s = %lu\n", "cycle",     plat_get_cycle());
    printf("%24s = %lu\n", "instret",   plat_get_instret());

    fail += test_sha3();
    fail += test_turbo();

    printf("[INFO] fail= %d\n", fail);

    return fail;
}
