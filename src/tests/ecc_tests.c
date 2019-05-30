/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "ecc_tests.h"
#include <kryptos_ec_utils.h>
#include <kryptos_curves.h>
#include <kryptos_mp.h>
#include <kryptos_memory.h>
#include <string.h>

CUTE_TEST_CASE(kryptos_ec_set_point_tests)
    kryptos_ec_pt_t *p = NULL;
    kryptos_mp_value_t *x = NULL, *y = NULL;
    x = kryptos_hex_value_as_mp("DEADBEEF", 8);
    CUTE_ASSERT(x != NULL);
    y = kryptos_hex_value_as_mp("CACACACA", 8);
    CUTE_ASSERT(y != NULL);
    CUTE_ASSERT(kryptos_ec_set_point(&p, x, y) == 1);
    CUTE_ASSERT(p != NULL);
    CUTE_ASSERT(kryptos_mp_eq(p->x, x) == 1);
    CUTE_ASSERT(kryptos_mp_eq(p->y, y) == 1);
    kryptos_del_mp_value(x);
    kryptos_del_mp_value(y);
    kryptos_ec_del_point(p); // INFO(Rafael): In case of any memory leak, the memory leak check system will warn us.
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ec_set_curve_tests)
    kryptos_ec_t *ec = NULL;
    kryptos_mp_value_t *a = NULL, *b = NULL, *p = NULL;
    a = kryptos_hex_value_as_mp("0123456789", 10);
    CUTE_ASSERT(a != NULL);
    b = kryptos_hex_value_as_mp("9876543210", 10);
    CUTE_ASSERT(b != NULL);
    p = kryptos_hex_value_as_mp("0123456789ABCDEFFEDCBA9876543210", 32);
    CUTE_ASSERT(p != NULL);
    CUTE_ASSERT(kryptos_ec_set_curve(&ec, a, b, p) == 1);
    CUTE_ASSERT(ec != NULL);
    CUTE_ASSERT(kryptos_mp_eq(ec->a, a) == 1);
    CUTE_ASSERT(kryptos_mp_eq(ec->b, b) == 1);
    CUTE_ASSERT(kryptos_mp_eq(ec->p, p) == 1);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);
    kryptos_del_mp_value(p);
    kryptos_ec_del_curve(ec); // INFO(Rafael): In case of any memory leak, the memory leak check system will warn us.
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ec_dbl_tests)
    struct test_ctx {
        kryptos_u8_t *a;
        size_t a_size;
        kryptos_u8_t *b;
        size_t b_size;
        kryptos_u8_t *p;
        size_t p_size;
        kryptos_u8_t *x;
        size_t x_size;
        kryptos_u8_t *y;
        size_t y_size;
        kryptos_u8_t *ex;
        size_t ex_size;
        kryptos_u8_t *ey;
        size_t ey_size;
    };
    struct test_ctx test_vector[] = {
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "06", 2, "03", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_ec_pt_t *P = NULL, *R = NULL;
    kryptos_ec_t *EC = NULL;
    kryptos_mp_value_t *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *ex = NULL, *ey = NULL;

    for (t = 0; t < tv_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        CUTE_ASSERT(a != NULL);

        b = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        CUTE_ASSERT(b != NULL);

        p = kryptos_hex_value_as_mp(test_vector[t].p, test_vector[t].p_size);
        CUTE_ASSERT(p != NULL);

        x = kryptos_hex_value_as_mp(test_vector[t].x, test_vector[t].x_size);
        CUTE_ASSERT(x != NULL);

        y = kryptos_hex_value_as_mp(test_vector[t].y, test_vector[t].y_size);
        CUTE_ASSERT(y != NULL);

        ex = kryptos_hex_value_as_mp(test_vector[t].ex, test_vector[t].ex_size);
        CUTE_ASSERT(ex != NULL);

        ey = kryptos_hex_value_as_mp(test_vector[t].ey, test_vector[t].ey_size);
        CUTE_ASSERT(ey != NULL);

        CUTE_ASSERT(kryptos_ec_set_curve(&EC, a, b, p) == 1);

        CUTE_ASSERT(kryptos_ec_set_point(&P, x, y) == 1);

        kryptos_ec_dbl(&R, P, EC);

        CUTE_ASSERT(R != NULL);

        CUTE_ASSERT(kryptos_mp_eq(R->x, ex) == 1);
        CUTE_ASSERT(kryptos_mp_eq(R->y, ey) == 1);

        kryptos_ec_del_curve(EC);
        kryptos_ec_del_point(P);
        kryptos_ec_del_point(R);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(ex);
        kryptos_del_mp_value(ey);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ec_add_tests)
    struct test_ctx {
        kryptos_u8_t *a;
        size_t a_size;
        kryptos_u8_t *b;
        size_t b_size;
        kryptos_u8_t *p;
        size_t p_size;
        kryptos_u8_t *x1;
        size_t x1_size;
        kryptos_u8_t *y1;
        size_t y1_size;
        kryptos_u8_t *x2;
        size_t x2_size;
        kryptos_u8_t *y2;
        size_t y2_size;
        kryptos_u8_t *ex;
        size_t ex_size;
        kryptos_u8_t *ey;
        size_t ey_size;
    };
    struct test_ctx test_vector[] = {
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "05", 2, "01", 2, "06", 2, "03", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "02", 2, "04", 2, "0B", 2, "05", 2 },
        { "02", 2, "02", 2, "11", 2, "00", 2, "00", 2, "00", 2, "00", 2, "00", 2, "00", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "00", 2, "00", 2, "05", 2, "01", 2 },
        { "02", 2, "02", 2, "11", 2, "00", 2, "00", 2, "05", 2, "01", 2, "05", 2, "01", 2 },
        { "02", 2, "02", 2, "11", 2, "12", 2, "09", 2, "07", 2, "14", 2, "0A", 2, "00", 2 },
        { "02", 2, "02", 2, "11", 2, "18", 2, "09", 2, "07", 2, "14", 2, "03", 2, "08", 2 },
        { "02", 2, "02", 2, "11", 2, "4E", 2, "63", 2, "0F", 2, "22", 2, "08", 2, "0B", 2 },
        { "02", 2, "02", 2, "11", 2, "04", 2, "1E", 2, "1E", 2, "04", 2, "01", 2, "01", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_ec_pt_t *P = NULL, *Q = NULL, *R = NULL;
    kryptos_ec_t *EC = NULL;
    kryptos_mp_value_t *p = NULL, *a = NULL, *b = NULL, *x1 = NULL, *y1 = NULL, *x2 = NULL, *y2 = NULL, *ex = NULL, *ey = NULL;

    for (t = 0; t < tv_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        CUTE_ASSERT(a != NULL);

        b = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        CUTE_ASSERT(b != NULL);

        p = kryptos_hex_value_as_mp(test_vector[t].p, test_vector[t].p_size);
        CUTE_ASSERT(p != NULL);

        x1 = kryptos_hex_value_as_mp(test_vector[t].x1, test_vector[t].x1_size);
        CUTE_ASSERT(x1 != NULL);

        y1 = kryptos_hex_value_as_mp(test_vector[t].y1, test_vector[t].y1_size);
        CUTE_ASSERT(y1 != NULL);

        x2 = kryptos_hex_value_as_mp(test_vector[t].x2, test_vector[t].x2_size);
        CUTE_ASSERT(x2 != NULL);

        y2 = kryptos_hex_value_as_mp(test_vector[t].y2, test_vector[t].y2_size);
        CUTE_ASSERT(y2 != NULL);

        ex = kryptos_hex_value_as_mp(test_vector[t].ex, test_vector[t].ex_size);
        CUTE_ASSERT(ex != NULL);

        ey = kryptos_hex_value_as_mp(test_vector[t].ey, test_vector[t].ey_size);
        CUTE_ASSERT(ey != NULL);

        CUTE_ASSERT(kryptos_ec_set_curve(&EC, a, b, p) == 1);

        CUTE_ASSERT(kryptos_ec_set_point(&P, x1, y1) == 1);

        CUTE_ASSERT(kryptos_ec_set_point(&Q, x2, y2) == 1);

        kryptos_ec_add(&R, P, Q, EC);

        CUTE_ASSERT(R != NULL);

        CUTE_ASSERT(kryptos_mp_eq(R->x, ex) == 1);
        CUTE_ASSERT(kryptos_mp_eq(R->y, ey) == 1);

        kryptos_ec_del_curve(EC);
        kryptos_ec_del_point(P);
        kryptos_ec_del_point(Q);
        kryptos_ec_del_point(R);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(x1);
        kryptos_del_mp_value(y1);
        kryptos_del_mp_value(x2);
        kryptos_del_mp_value(y2);
        kryptos_del_mp_value(ex);
        kryptos_del_mp_value(ey);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ec_mul_tests)
    struct test_ctx {
        kryptos_u8_t *a;
        size_t a_size;
        kryptos_u8_t *b;
        size_t b_size;
        kryptos_u8_t *p;
        size_t p_size;
        kryptos_u8_t *x;
        size_t x_size;
        kryptos_u8_t *y;
        size_t y_size;
        kryptos_u8_t *d;
        size_t d_size;
        kryptos_u8_t *ex;
        size_t ex_size;
        kryptos_u8_t *ey;
        size_t ey_size;
    };
    struct test_ctx test_vector[] = {
        { "02", 2, "02", 2, "11", 2, "02", 2, "02", 2, "00", 2, "00", 2, "00", 2 },
        { "02", 2, "02", 2, "11", 2, "04", 2, "1E", 2, "02", 2, "0D", 2, "05", 2 },
        { "02", 2, "02", 2, "11", 2, "04", 2, "1E", 2, "03", 2, "01", 2, "07", 2 },
        { "02", 2, "02", 2, "11", 2, "02", 2, "02", 2, "14", 2, "02", 2, "0F", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "01", 2, "05", 2, "01", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "02", 2, "06", 2, "03", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "03", 2, "0A", 2, "06", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "04", 2, "03", 2, "01", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "05", 2, "09", 2, "10", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "06", 2, "10", 2, "0D", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "07", 2, "00", 2, "06", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "08", 2, "0D", 2, "07", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "09", 2, "07", 2, "06", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "0A", 2, "07", 2, "0B", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "0B", 2, "0D", 2, "0A", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "0C", 2, "00", 2, "0B", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "0D", 2, "10", 2, "04", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "0E", 2, "09", 2, "01", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "0F", 2, "03", 2, "10", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "10", 2, "0A", 2, "0B", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "11", 2, "06", 2, "0E", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "12", 2, "05", 2, "10", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "13", 2, "00", 2, "00", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_ec_pt_t *P = NULL, *R = NULL;
    kryptos_ec_t *EC = NULL;
    kryptos_mp_value_t *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *ex = NULL, *ey = NULL, *d = NULL;

    for (t = 0; t < tv_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        CUTE_ASSERT(a != NULL);

        b = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        CUTE_ASSERT(b != NULL);

        p = kryptos_hex_value_as_mp(test_vector[t].p, test_vector[t].p_size);
        CUTE_ASSERT(p != NULL);

        x = kryptos_hex_value_as_mp(test_vector[t].x, test_vector[t].x_size);
        CUTE_ASSERT(x != NULL);

        y = kryptos_hex_value_as_mp(test_vector[t].y, test_vector[t].y_size);
        CUTE_ASSERT(y != NULL);

        d = kryptos_hex_value_as_mp(test_vector[t].d, test_vector[t].d_size);
        CUTE_ASSERT(d != NULL);

        ex = kryptos_hex_value_as_mp(test_vector[t].ex, test_vector[t].ex_size);
        CUTE_ASSERT(ex != NULL);

        ey = kryptos_hex_value_as_mp(test_vector[t].ey, test_vector[t].ey_size);
        CUTE_ASSERT(ey != NULL);

        CUTE_ASSERT(kryptos_ec_set_curve(&EC, a, b, p) == 1);

        CUTE_ASSERT(kryptos_ec_set_point(&P, x, y) == 1);

        kryptos_ec_mul(&R, P, d, EC);

        CUTE_ASSERT(R != NULL);

        CUTE_ASSERT(kryptos_mp_eq(R->x, ex) == 1);
        CUTE_ASSERT(kryptos_mp_eq(R->y, ey) == 1);

        kryptos_ec_del_curve(EC);
        kryptos_ec_del_point(P);
        kryptos_ec_del_point(R);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(d);
        kryptos_del_mp_value(ex);
        kryptos_del_mp_value(ey);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_new_standard_curve_tests)
    struct test_ctx {
        kryptos_curve_id_t id;
        size_t bits;
        char *p, *a, *b, *x, *y, *q;
    };
#define KRYPTOS_REGISTER_STANDARD_CURVE(id, bits, p, a, b, x, y, q)\
    { (id), (bits), (p), (a), (b), (x), (y), (q) }
    struct test_ctx test_vector[] = {
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP160R1,
                                        160,
                                        "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
                                        "340E7BE2A280EB74E2BE61BADA745D97E8F7C300",
                                        "1E589A8595423412134FAA2DBDEC95C8D8675E58",
                                        "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3",
                                        "1667CB477A1A8EC338F94741669C976316DA6321",
                                        "E95E4A5F737059DC60DF5991D45029409E60FC09"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP160T1,
                                        160,
                                        "E95E4A5F737059DC60DFC7AD95B3D8139515620F",
                                        "E95E4A5F737059DC60DFC7AD95B3D8139515620C",
                                        "7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380",
                                        "B199B13B9B34EFC1397E64BAEB05ACC265FF2378",
                                        "ADD6718B7C7C1961F0991B842443772152C9E0AD",
                                        "E95E4A5F737059DC60DF5991D45029409E60FC09"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP192R1,
                                        192,
                                        "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
                                        "6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF",
                                        "469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9",
                                        "C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6",
                                        "14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F",
                                        "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP192T1,
                                        192,
                                        "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297",
                                        "C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86294",
                                        "13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79",
                                        "3AE9E58C82F63C30282E1FE7BBF43FA72C446AF6F4618129",
                                        "097E2C5667C2223A902AB5CA449D0084B7E5B3DE7CCC01C9",
                                        "C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP224R1,
                                        224,
                                        "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
                                        "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
                                        "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
                                        "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
                                        "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD",
                                        "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP224T1,
                                        224,
                                        "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
                                        "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC",
                                        "4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D",
                                        "6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580",
                                        "0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C",
                                        "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP256R1,
                                        256,
                                        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
                                        "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
                                        "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
                                        "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
                                        "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
                                        "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP256T1,
                                        256,
                                        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
                                        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374",
                                        "662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04",
                                        "A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4",
                                        "2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE",
                                        "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP320R1,
                                        320,
                                        "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
                                        "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
                                        "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
                                        "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
                                        "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
                                        "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP320T1,
                                        320,
                                        "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
                                        "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E24",
                                        "A7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CEB5B4FEF422340353",
                                        "925BE9FB01AFC6FB4D3E7D4990010F813408AB106C4F09CB7EE07868CC136FFF3357F624A21BED52",
                                        "63BA3A7A27483EBF6671DBEF7ABB30EBEE084E58A0B077AD42A5A0989D1EE71B1B9BC0455FB0D2C3",
                                        "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP384R1,
                                        384,
                                        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71"
                                        "874700133107EC53",
                                        "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB"
                                        "04A8C7DD22CE2826",
                                        "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC994"
                                        "3AB78696FA504C11",
                                        "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AA"
                                        "EF87B2E247D4AF1E",
                                        "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E46462177918111"
                                        "42820341263C5315",
                                        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC310"
                                        "883202E9046565"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP384T1,
                                        384,
                                        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71"
                                        "874700133107EC53",
                                        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71"
                                        "874700133107EC50",
                                        "7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805C"
                                        "ED70355A33B471EE",
                                        "18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946A5F54"
                                        "D8D0AA2F418808CC",
                                        "25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC2B291"
                                        "2675BF5B9E582928",
                                        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC310"
                                        "3B883202E9046565"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP512R1,
                                        512,
                                        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842"
                                        "AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
                                        "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA1"
                                        "0A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
                                        "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D"
                                        "77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
                                        "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D"
                                        "50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
                                        "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E"
                                        "5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
                                        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619"
                                        "8661197FAC10471DB1D381085DDADDB58796829CA90069"),
        KRYPTOS_REGISTER_STANDARD_CURVE(kBrainPoolP512T1,
                                        512,
                                        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842"
                                        "AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
                                        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842"
                                        "AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F0",
                                        "7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA2304976540"
                                        "F6450085F2DAE145C22553B465763689180EA2571867423E",
                                        "640ECE5C12788717B9C1BA06CBC2A6FEBA85842458C56DDE9DB1758D39C0313D82BA51735CDB3EA4"
                                        "99AA77A7D6943A64F7A3F25FE26F06B51BAA2696FA9035DA",
                                        "5B534BD595F5AF0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEEF216B"
                                        "D71DF2DADF86A627306ECFF96DBB8BACE198B61E00F8B332",
                                        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619"
                                        "418661197FAC10471DB1D381085DDADDB58796829CA90069")
    }, *tp, *tp_end;
#undef KRYPTOS_REGISTER_STANDARD_CURVE
    kryptos_mp_value_t *p, *a, *b, *x, *y, *q;
    kryptos_curve_ctx  *curve;

    tp = &test_vector[0];
    tp_end = tp + sizeof(test_vector) / sizeof(test_vector[0]);

    while (tp != tp_end) {
        p = kryptos_hex_value_as_mp((kryptos_u8_t *)tp->p, strlen(tp->p));
        CUTE_ASSERT(p != NULL);
        a = kryptos_hex_value_as_mp((kryptos_u8_t *)tp->a, strlen(tp->a));
        CUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp((kryptos_u8_t *)tp->b, strlen(tp->b));
        CUTE_ASSERT(b != NULL);
        x = kryptos_hex_value_as_mp((kryptos_u8_t *)tp->x, strlen(tp->x));
        CUTE_ASSERT(x != NULL);
        y = kryptos_hex_value_as_mp((kryptos_u8_t *)tp->y, strlen(tp->y));
        CUTE_ASSERT(y != NULL);
        q = kryptos_hex_value_as_mp((kryptos_u8_t *)tp->q, strlen(tp->q));
        curve = kryptos_new_standard_curve(tp->id);
        CUTE_ASSERT(curve != NULL);
        CUTE_ASSERT(curve->bits == tp->bits);
        CUTE_ASSERT(kryptos_mp_eq(curve->ec->p, p) == 1);
        CUTE_ASSERT(kryptos_mp_eq(curve->ec->a, a) == 1);
        CUTE_ASSERT(kryptos_mp_eq(curve->ec->b, b) == 1);
        CUTE_ASSERT(kryptos_mp_eq(curve->g->x, x) == 1);
        CUTE_ASSERT(kryptos_mp_eq(curve->g->y, y) == 1);
        CUTE_ASSERT(kryptos_mp_eq(curve->q, q) == 1);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(q);
        kryptos_del_curve_ctx(curve);
        tp++;
    }
CUTE_TEST_CASE_END
