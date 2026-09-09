// SPDX-FileCopyrightText: 2026 Markku-Juhani O. Saarinen <mjos@iki.fi>
// SPDX-License-Identifier: BSD-3-Clause
//
//  test_turbo.c
//  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === Unit tests for RFC 9861 -- TurboSHAKE XOF.
//
//  These exercise the 12-round form of the instruction, vkeccak.vi with
//  imm5=1, which SHA-3 and SHAKE never reach. The vectors are taken verbatim
//  from RFC 9861 Section 5.
#ifndef NO_TEST_TURBO

#include "plat_local.h"
#include "test_rvkat.h"
#include "turbo_api.h"

#include <string.h>

//  Test the Keccak-p[1600,12](S) permutation on its own, so that a failure
//  in the permutation is distinguishable from one in the sponge padding.
//  RFC 9861 has no bare-permutation vector; this one is the same input the
//  24-round KECCAK-P test uses, and is cross-checked against an independent
//  implementation of Keccak-p[1600,12].

int test_p1600_12_tv()
{
    int i;
    uint64_t st[25];
    int fail = 0;

    memset(st, 0, sizeof(st));
    for (i = 0; i < 25; i++) {
        st[i] = i;
    }
    keccak_p1600_12(st);

    fail += rvkat_chkhex(
        "KECCAK-P12", st, sizeof(st),
        "FECCEEE8FEB6CC31E742D7A8CC3DBF572DFDD5008E3CC2337D9913C2858B4027"
        "AE91B50585502B44D0D998867F95F3E7F3BD3DB84CCEE924BA98490FE114EDC6"
        "410ED34D8C7145A44BC1F4C4DDC418A6D09E0B6C38AB2D867C974FEC9DDEDA0F"
        "3112FF061A03AA385CFCECFFA948B7F4195F3AC39358AFD0469CFAF51EFFC14D"
        "6BC25654DF805DB15BC3A0409470663A23A2E7F210D4BDEB3D739A183BA72070"
        "01F6A8B9F21DEAA32562A781BC525DD1C16A2FE85830ACEA5E4E54E58AC3E01D"
        "DD65C52D9D1AFA72");

    return fail;
}

//  Absorb ptn(n): the pattern `00 01 02 .. F9 FA` repeated as many times as
//  needed and truncated to n bytes (RFC 9861, Section 5). Fed incrementally
//  so that the larger vectors need no multi-kilobyte buffer.

static void turbo_update_ptn(turbo_ctx_t *c, size_t n)
{
    uint8_t buf[251];
    size_t i, k;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = (uint8_t) i;           //  `00` .. `FA`
    }
    while (n > 0) {
        k = n < sizeof(buf) ? n : sizeof(buf);
        turbo_update(c, buf, k);
        n -= k;
    }
}

//  A TurboSHAKE test vector. Either "msg" holds the message in hex, or it is
//  NULL and the message is ptn(ptn_len). When "last32" is set the vector
//  covers only the final 32 bytes of a long output.

typedef struct {
    const char *lab;
    int cap;                //  capacity in bytes: 32 = TS128, 64 = TS256
    uint8_t dsep;           //  domain separation byte D
    const char *msg;
    size_t ptn_len;
    size_t outlen;
    int last32;
    const char *md;
} turbo_tv_t;

//  RFC 9861, Section 5. The ptn(17**5) and ptn(17**6) vectors are omitted:
//  at 1.4 MB and 24 MB they take minutes to absorb under a simulator.

static const turbo_tv_t turbo_tv[] = {
    {"TurboSHAKE128", 32, 0x1F, "", 0, 32, 0,
     "1E415F1C5983AFF2169217277D17BB538CD945A397DDEC541F1CE41AF2C1B74C"},   //  D=`1F`, M=empty
    {"TurboSHAKE128", 32, 0x1F, "", 0, 64, 0,
     "1E415F1C5983AFF2169217277D17BB538CD945A397DDEC541F1CE41AF2C1B74C"
     "3E8CCAE2A4DAE56C84A04C2385C03C15E8193BDF58737363321691C05462C8DF"},   //  D=`1F`, M=empty
    {"TurboSHAKE128", 32, 0x1F, "", 0, 10032, 1,
     "A3B9B0385900CE761F22AED548E754DA10A5242D62E8C658E3F3A923A7555607"},   //  D=`1F`, M=empty
    {"TurboSHAKE128", 32, 0x1F, NULL, 1, 32, 0,
     "55CEDD6F60AF7BB29A4042AE832EF3F58DB7299F893EBB9247247D856958DAA9"},   //  D=`1F`, M=ptn(17**0 bytes)
    {"TurboSHAKE128", 32, 0x1F, NULL, 17, 32, 0,
     "9C97D036A3BAC819DB70EDE0CA554EC6E4C2A1A4FFBFD9EC269CA6A111161233"},   //  D=`1F`, M=ptn(17**1 bytes)
    {"TurboSHAKE128", 32, 0x1F, NULL, 289, 32, 0,
     "96C77C279E0126F7FC07C9B07F5CDAE1E0BE60BDBE10620040E75D7223A624D2"},   //  D=`1F`, M=ptn(17**2 bytes)
    {"TurboSHAKE128", 32, 0x1F, NULL, 4913, 32, 0,
     "D4976EB56BCF118520582B709F73E1D6853E001FDAF80E1B13E0D0599D5FB372"},   //  D=`1F`, M=ptn(17**3 bytes)
    {"TurboSHAKE128", 32, 0x1F, NULL, 83521, 32, 0,
     "DA67C7039E98BF530CF7A37830C6664E14CBAB7F540F58403B1B82951318EE5C"},   //  D=`1F`, M=ptn(17**4 bytes)
    {"TurboSHAKE128", 32, 0x01, "FFFFFF", 0, 32, 0,
     "BF323F940494E88EE1C540FE660BE8A0C93F43D15EC006998462FA994EED5DAB"},   //  D=`01`, M=FF FF FF
    {"TurboSHAKE128", 32, 0x06, "FF", 0, 32, 0,
     "8EC9C66465ED0D4A6C35D13506718D687A25CB05C74CCA1E42501ABD83874A67"},   //  D=`06`, M=FF
    {"TurboSHAKE128", 32, 0x07, "FFFFFF", 0, 32, 0,
     "B658576001CAD9B1E5F399A9F77723BBA05458042D68206F7252682DBA3663ED"},   //  D=`07`, M=FF FF FF
    {"TurboSHAKE128", 32, 0x0B, "FFFFFFFFFFFFFF", 0, 32, 0,
     "8DEEAA1AEC47CCEE569F659C21DFA8E112DB3CEE37B18178B2ACD805B799CC37"},   //  D=`0B`, M=FF FF FF FF FF FF FF
    {"TurboSHAKE128", 32, 0x30, "FF", 0, 32, 0,
     "553122E2135E363C3292BED2C6421FA232BAB03DAA07C7D6636603286506325B"},   //  D=`30`, M=FF
    {"TurboSHAKE128", 32, 0x7F, "FFFFFF", 0, 32, 0,
     "16274CC656D44CEFD422395D0F9053BDA6D28E122ABA15C765E5AD0E6EAF26F9"},   //  D=`7F`, M=FF FF FF
    {"TurboSHAKE256", 64, 0x1F, "", 0, 64, 0,
     "367A329DAFEA871C7802EC67F905AE13C57695DC2C6663C61035F59A18F8E7DB"
     "11EDC0E12E91EA60EB6B32DF06DD7F002FBAFABB6E13EC1CC20D995547600DB0"},   //  D=`1F`, M=empty
    {"TurboSHAKE256", 64, 0x1F, "", 0, 10032, 1,
     "ABEFA11630C661269249742685EC082F207265DCCF2F43534E9C61BA0C9D1D75"},   //  D=`1F`, M=empty
    {"TurboSHAKE256", 64, 0x1F, NULL, 1, 64, 0,
     "3E1712F928F8EAF1054632B2AA0A246ED8B0C378728F60BC970410155C28820E"
     "90CC90D8A3006AA2372C5C5EA176B0682BF22BAE7467AC94F74D43D39B0482E2"},   //  D=`1F`, M=ptn(17**0 bytes)
    {"TurboSHAKE256", 64, 0x1F, NULL, 17, 64, 0,
     "B3BAB0300E6A191FBE6137939835923578794EA54843F5011090FA2F3780A9E5"
     "CB22C59D78B40A0FBFF9E672C0FBE0970BD2C845091C6044D687054DA5D8E9C7"},   //  D=`1F`, M=ptn(17**1 bytes)
    {"TurboSHAKE256", 64, 0x1F, NULL, 289, 64, 0,
     "66B810DB8E90780424C0847372FDC95710882FDE31C6DF75BEB9D4CD9305CFCA"
     "E35E7B83E8B7E6EB4B78605880116316FE2C078A09B94AD7B8213C0A738B65C0"},   //  D=`1F`, M=ptn(17**2 bytes)
    {"TurboSHAKE256", 64, 0x1F, NULL, 4913, 64, 0,
     "C74EBC919A5B3B0DD1228185BA02D29EF442D69D3D4276A93EFE0BF9A16A7DC0"
     "CD4EABADAB8CD7A5EDD96695F5D360ABE09E2C6511A3EC397DA3B76B9E1674FB"},   //  D=`1F`, M=ptn(17**3 bytes)
    {"TurboSHAKE256", 64, 0x1F, NULL, 83521, 64, 0,
     "02CC3A8897E6F4F6CCB6FD46631B1F5207B66C6DE9C7B55B2D1A23134A170AFD"
     "AC234EABA9A77CFF88C1F020B73724618C5687B362C430B248CD38647F848A1D"},   //  D=`1F`, M=ptn(17**4 bytes)
    {"TurboSHAKE256", 64, 0x01, "FFFFFF", 0, 64, 0,
     "D21C6FBBF587FA2282F29AEA620175FB0257413AF78A0B1B2A87419CE031D933"
     "AE7A4D383327A8A17641A34F8A1D1003AD7DA6B72DBA84BB62FEF28F62F12424"},   //  D=`01`, M=FF FF FF
    {"TurboSHAKE256", 64, 0x06, "FF", 0, 64, 0,
     "738D7B4E37D18B7F22AD1B5313E357E3DD7D07056A26A303C433FA3533455280"
     "F4F5A7D4F700EFB437FE6D281405E07BE32A0A972E22E63ADC1B090DAEFE004B"},   //  D=`06`, M=FF
    {"TurboSHAKE256", 64, 0x07, "FFFFFF", 0, 64, 0,
     "18B3B5B7061C2E67C1753A00E6AD7ED7BA1C906CF93EFB7092EAF27FBEEBB755"
     "AE6E292493C110E48D260028492B8E09B5500612B8F2578985DED5357D00EC67"},   //  D=`07`, M=FF FF FF
    {"TurboSHAKE256", 64, 0x0B, "FFFFFFFFFFFFFF", 0, 64, 0,
     "BB36764951EC97E9D85F7EE9A67A7718FC005CF42556BE79CE12C0BDE50E5736"
     "D6632B0D0DFB202D1BBB8FFE3DD74CB00834FA756CB03471BAB13A1E2C16B3C0"},   //  D=`0B`, M=FF FF FF FF FF FF FF
    {"TurboSHAKE256", 64, 0x30, "FF", 0, 64, 0,
     "F3FE12873D34BCBB2E608779D6B70E7F86BEC7E90BF113CBD4FDD0C4E2F4625E"
     "148DD7EE1A52776CF77F240514D9CCFC3B5DDAB8EE255E39EE389072962C111A"},   //  D=`30`, M=FF
    {"TurboSHAKE256", 64, 0x7F, "FFFFFF", 0, 64, 0,
     "ABE569C1F77EC340F02705E7D37C9AB7E155516E4A6A150021D70B6FAC0BB40C"
     "069F9A9828A0D575CD99F9BAE435AB1ACF7ED9110BA97CE0388D074BAC768776"},   //  D=`7F`, M=FF FF FF
};

int test_turbo_tv()
{
    turbo_ctx_t c;
    uint8_t md[64], in[16];
    size_t i, n, left, k;
    int fail = 0;

    for (i = 0; i < sizeof(turbo_tv) / sizeof(turbo_tv[0]); i++) {
        const turbo_tv_t *tv = &turbo_tv[i];

        turbo_init(&c, tv->cap, tv->dsep);
        if (tv->msg != NULL) {
            n = rvkat_gethex(in, sizeof(in), tv->msg);
            turbo_update(&c, in, n);
        } else {
            turbo_update_ptn(&c, tv->ptn_len);
        }

        if (tv->last32) {
            //  squeeze and discard everything but the final 32 bytes
            left = tv->outlen - 32;
            while (left > 0) {
                k = left < sizeof(md) ? left : sizeof(md);
                turbo_out(&c, md, k);
                left -= k;
            }
            turbo_out(&c, md, 32);
            fail += rvkat_chkhex(tv->lab, md, 32, tv->md);
        } else {
            turbo_out(&c, md, tv->outlen);
            fail += rvkat_chkhex(tv->lab, md, tv->outlen, tv->md);
        }
    }

    return fail;
}

//  RFC 9861: algorithm tests

int test_turbo()
{
    int fail = 0;

    rvkat_info("=== TurboSHAKE ===");
    fail += test_p1600_12_tv();
    fail += test_turbo_tv();

    return fail;
}

//  !NO_TEST_TURBO
#endif
