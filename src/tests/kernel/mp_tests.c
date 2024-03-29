/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <mp_tests.h>
#include <kryptos_mp.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <kryptos.h>
#include <kryptos_endianness_utils.h>
#include <kstring.h>

// WARN(Rafael): Almost all stuff tested here probably will not executed in kernel mode (or at least should not). But if everything
//               is okay nothing can explode. In this case let's test...

KUTE_TEST_CASE(kryptos_mp_new_value_tests)
    kryptos_mp_value_t *mp;
    size_t d;
    mp = kryptos_new_mp_value(1024);
    KUTE_ASSERT(mp != NULL);
    KUTE_ASSERT(mp->data != NULL);
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 1024);
    for (d = 0; d < mp->data_size; d++) {
        KUTE_ASSERT(mp->data[d] == 0);
    }
    kryptos_del_mp_value(mp);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_hex_value_as_mp_tests)
    kryptos_mp_value_t *mp;
    mp = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    KUTE_ASSERT(mp != NULL);
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 128);
#ifndef KRYPTOS_MP_U32_DIGIT
    KUTE_ASSERT(mp->data[ 0] == 0x99);
    KUTE_ASSERT(mp->data[ 1] == 0x88);
    KUTE_ASSERT(mp->data[ 2] == 0x77);
    KUTE_ASSERT(mp->data[ 3] == 0x66);
    KUTE_ASSERT(mp->data[ 4] == 0x55);
    KUTE_ASSERT(mp->data[ 5] == 0x44);
    KUTE_ASSERT(mp->data[ 6] == 0x33);
    KUTE_ASSERT(mp->data[ 7] == 0x22);
    KUTE_ASSERT(mp->data[ 8] == 0x11);
    KUTE_ASSERT(mp->data[ 9] == 0x00);
    KUTE_ASSERT(mp->data[10] == 0xAA);
    KUTE_ASSERT(mp->data[11] == 0xBB);
    KUTE_ASSERT(mp->data[12] == 0xCC);
    KUTE_ASSERT(mp->data[13] == 0xDD);
    KUTE_ASSERT(mp->data[14] == 0xEE);
    KUTE_ASSERT(mp->data[15] == 0xFF);
#else
# if !defined(KRYPTOS_MP_EXTENDED_RADIX)
    KUTE_ASSERT(mp->data[0] == 0x66778899);
    KUTE_ASSERT(mp->data[1] == 0x22334455);
    KUTE_ASSERT(mp->data[2] == 0xBBAA0011);
    KUTE_ASSERT(mp->data[3] == 0xFFEEDDCC);
# else
    KUTE_ASSERT(mp->data[0] == 0x2233445566778899);
    KUTE_ASSERT(mp->data[1] == 0xFFEEDDCCBBAA0011);
# endif
#endif
    kryptos_del_mp_value(mp);

    mp = kryptos_hex_value_as_mp("-FFEEDDCCBBAA00112233445566778899", 33);
    KUTE_ASSERT(mp != NULL);
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 128);
    KUTE_ASSERT(mp->neg == 1);
#ifndef KRYPTOS_MP_U32_DIGIT
    KUTE_ASSERT(mp->data[ 0] == 0x99);
    KUTE_ASSERT(mp->data[ 1] == 0x88);
    KUTE_ASSERT(mp->data[ 2] == 0x77);
    KUTE_ASSERT(mp->data[ 3] == 0x66);
    KUTE_ASSERT(mp->data[ 4] == 0x55);
    KUTE_ASSERT(mp->data[ 5] == 0x44);
    KUTE_ASSERT(mp->data[ 6] == 0x33);
    KUTE_ASSERT(mp->data[ 7] == 0x22);
    KUTE_ASSERT(mp->data[ 8] == 0x11);
    KUTE_ASSERT(mp->data[ 9] == 0x00);
    KUTE_ASSERT(mp->data[10] == 0xAA);
    KUTE_ASSERT(mp->data[11] == 0xBB);
    KUTE_ASSERT(mp->data[12] == 0xCC);
    KUTE_ASSERT(mp->data[13] == 0xDD);
    KUTE_ASSERT(mp->data[14] == 0xEE);
    KUTE_ASSERT(mp->data[15] == 0xFF);
#else
# if !defined(KRYPTOS_MP_EXTENDED_RADIX)
    KUTE_ASSERT(mp->data[0] == 0x66778899);
    KUTE_ASSERT(mp->data[1] == 0x22334455);
    KUTE_ASSERT(mp->data[2] == 0xBBAA0011);
    KUTE_ASSERT(mp->data[3] == 0xFFEEDDCC);
    kryptos_del_mp_value(mp);
    mp = kryptos_hex_value_as_mp("1FFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFFFFFF"
                                 "FFFEE600", 117);
    KUTE_ASSERT(mp->data[ 0] == 0xFFFEE600);
    KUTE_ASSERT(mp->data[ 1] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[ 2] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[ 3] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[ 4] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[ 5] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[ 6] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[ 7] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[ 8] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[ 9] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[10] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[11] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[12] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[13] == 0xFFFFFFFF);
    KUTE_ASSERT(mp->data[14] == 0x0001FFFF);
# else
    KUTE_ASSERT(mp->data[0] == 0x2233445566778899);
    KUTE_ASSERT(mp->data[1] == 0xFFEEDDCCBBAA0011);
    kryptos_del_mp_value(mp);
    mp = kryptos_hex_value_as_mp("1FFFF"
                                 "FFFFFFFFFFFFFFFF"
                                 "FFFFFFFFFFFFFFFF"
                                 "FFFFFFFFFFFFFFFF"
                                 "FFFFFFFFFFFFFFFF"
                                 "FFFFFFFFFFFFFFFF"
                                 "FFFFFFFFFFFFFFFF"
                                 "FFFFFFFFFFFEE600", 117);
    KUTE_ASSERT(mp->data[0] == 0xFFFFFFFFFFFEE600);
    KUTE_ASSERT(mp->data[1] == 0xFFFFFFFFFFFFFFFF);
    KUTE_ASSERT(mp->data[2] == 0xFFFFFFFFFFFFFFFF);
    KUTE_ASSERT(mp->data[3] == 0xFFFFFFFFFFFFFFFF);
    KUTE_ASSERT(mp->data[4] == 0xFFFFFFFFFFFFFFFF);
    KUTE_ASSERT(mp->data[5] == 0xFFFFFFFFFFFFFFFF);
    KUTE_ASSERT(mp->data[6] == 0xFFFFFFFFFFFFFFFF);
    KUTE_ASSERT(mp->data[7] == 0x000000000001FFFF);
    kryptos_del_mp_value(mp);

    mp = kryptos_hex_value_as_mp("0000000000000000DEADBEEF", 24);
    KUTE_ASSERT(mp->data[0] == 0x00000000DEADBEEF);
    KUTE_ASSERT(mp->data[1] == 0x0000000000000000);
    kryptos_del_mp_value(mp);

    mp = kryptos_hex_value_as_mp("00000000DEADBEEFDEADBEEF", 24);
    KUTE_ASSERT(mp->data[0] == 0xDEADBEEFDEADBEEF);
    KUTE_ASSERT(mp->data[1] == 0x0000000000000000);
# endif
#endif
    kryptos_del_mp_value(mp);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_value_as_hex_tests)
    kryptos_mp_value_t *mp;
    kryptos_u8_t *x;
    size_t x_size;
    mp = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    KUTE_ASSERT(mp != NULL);
    x = kryptos_mp_value_as_hex(mp, &x_size);
    KUTE_ASSERT(x != NULL);
    KUTE_ASSERT(x_size == 32);
    KUTE_ASSERT(memcmp(x, "FFEEDDCCBBAA00112233445566778899", x_size) == 0);
    kryptos_del_mp_value(mp);
    kryptos_freeseg(x, x_size);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_assign_mp_value_tests)
    kryptos_mp_value_t *a = NULL, *b;
    size_t d;

    // INFO(Rafael): with a equals to NULL.
    b = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    KUTE_ASSERT(b != NULL);

    a = kryptos_assign_mp_value(&a, b);
    KUTE_ASSERT(a != NULL);

    KUTE_ASSERT(a->data_size == b->data_size);

    KUTE_ASSERT(memcmp(a->data, b->data, a->data_size) == 0);

    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    // INFO(Rafael): with a->data_size < b->data_size.
    b = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    KUTE_ASSERT(b != NULL);

    a = kryptos_new_mp_value(16);
    KUTE_ASSERT(a != NULL);

    a = kryptos_assign_mp_value(&a, b);
    KUTE_ASSERT(a != NULL);

    KUTE_ASSERT(a->data_size == b->data_size);

    KUTE_ASSERT(memcmp(a->data, b->data, a->data_size) == 0);

    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    // INFO(Rafael): with a->data_size > b->data_size.
    b = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    KUTE_ASSERT(b != NULL);

#if !defined(KRYPTOS_MP_EXTENDED_RADIX)
    a = kryptos_new_mp_value(160);
    KUTE_ASSERT(a != NULL);

    memset(a->data, 0xf, a->data_size);
    a = kryptos_assign_mp_value(&a, b);
    KUTE_ASSERT(a != NULL);

    KUTE_ASSERT(kryptos_mp_byte2bit(a->data_size) == 160);
#else
    a = kryptos_new_mp_value(256);
    KUTE_ASSERT(a != NULL);

    memset(a->data, 0xf, a->data_size);
    a = kryptos_assign_mp_value(&a, b);
    KUTE_ASSERT(a != NULL);

    KUTE_ASSERT(kryptos_mp_byte2bit(a->data_size) == 256);
#endif

    KUTE_ASSERT(memcmp(a->data, b->data, b->data_size) == 0);
    for (d = b->data_size; d < a->data_size; d++) {
        KUTE_ASSERT(a->data[d] == 0);
    }

    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_assign_hex_value_to_mp_tests)
    kryptos_mp_value_t *mp = NULL;
    // INFO(Rafael): mp == NULL.
    mp = kryptos_assign_hex_value_to_mp(&mp, "DEADBEEF", 8);
    KUTE_ASSERT(mp != NULL);
# if !defined(KRYPTOS_MP_EXTENDED_RADIX)
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 32);
# else
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 64);
# endif
#ifndef KRYPTOS_MP_U32_DIGIT
    KUTE_ASSERT(mp->data[0] == 0xEF);
    KUTE_ASSERT(mp->data[1] == 0xBE);
    KUTE_ASSERT(mp->data[2] == 0xAD);
    KUTE_ASSERT(mp->data[3] == 0xDE);
#else
    KUTE_ASSERT(mp->data[0] == 0xDEADBEEF);
#endif
    kryptos_del_mp_value(mp);

    // INFO(Rafael): mp != NULL && mp->data_size < hex-value-bitsize
    mp = kryptos_new_mp_value(16);
    KUTE_ASSERT(mp != NULL);
#ifndef KRYPTOS_MP_U32_DIGIT
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 16);
#else
# if !defined(KRYPTOS_MP_EXTENDED_RADIX)
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 32);
# else
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 64);
# endif
#endif
#ifndef KRYPTOS_MP_U32_DIGIT
    mp = kryptos_assign_hex_value_to_mp(&mp, "DEADBEEF", 8);
    KUTE_ASSERT(mp->data[0] == 0xAD);
    KUTE_ASSERT(mp->data[1] == 0xDE);
#else
    mp = kryptos_assign_hex_value_to_mp(&mp, "DEADDEADBEEF", 8);
    KUTE_ASSERT(mp->data[0] == 0xDEADDEAD);
#endif
    kryptos_del_mp_value(mp);

    // INFO(Rafael): mp != NULL && mp->data_size > hex-value-bitsize
    mp = kryptos_new_mp_value(64);
    KUTE_ASSERT(mp != NULL);
    KUTE_ASSERT(kryptos_mp_byte2bit(mp->data_size) == 64);
    mp = kryptos_assign_hex_value_to_mp(&mp, "DEADBEEF", 8);
#ifndef KRYPTOS_MP_U32_DIGIT
    KUTE_ASSERT(mp->data[0] == 0xEF);
    KUTE_ASSERT(mp->data[1] == 0xBE);
    KUTE_ASSERT(mp->data[2] == 0xAD);
    KUTE_ASSERT(mp->data[3] == 0xDE);
    KUTE_ASSERT(mp->data[4] == 0x00);
    KUTE_ASSERT(mp->data[5] == 0x00);
    KUTE_ASSERT(mp->data[6] == 0x00);
    KUTE_ASSERT(mp->data[7] == 0x00);
#else
#if !defined(KRYPTOS_MP_EXTENDED_RADIX)
    KUTE_ASSERT(mp->data[1] == 0xDEADBEEF);
    KUTE_ASSERT(mp->data[0] == 0x0);
# else
    KUTE_ASSERT(mp->data[0] == 0xDEADBEEF);
    kryptos_del_mp_value(mp);

    mp = kryptos_new_mp_value(128);
    KUTE_ASSERT(mp != NULL);
    mp = kryptos_assign_hex_value_to_mp(&mp, "DEADBEEFDEADBEEF", 16);
    KUTE_ASSERT(mp->data[1] == 0xDEADBEEFDEADBEEF);
    KUTE_ASSERT(mp->data[0] == 0x0);
# endif
#endif
    kryptos_del_mp_value(mp);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_eq_tests)
    char *values[] = {
        "01010100",

        "0202020202020200",

        "030303030303030303030303030A0A00",

        "0B0C0D000000A000010010000000000000000000000000000920000000000001",

        "FFFFFFFFFFDEABCD514272388123881293192378129319238129312312312300"
        "0000000128381238172387123102301023012030120310239192399231200000",

        "018239128381293192381283129319293982834872377283487238748239ABC0"
        "CBCBCBCBCBDBEDBDBEDBDBC7C7363817BCBE2123162631723712371236162631"
        "1111111111111111111111111111111111111111111111111112231231231231"
        "9999992391293912931923919239129319239129391231231626316236126362"
    };
    char *same_values[] = {
        "DEADBEEF",
        "00000000DEADBEEF",
        "0000000000000000DEADBEEF",
        "000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000DEADBEEF",
        "0000000000000000000000000000000000000000DEADBEEF",
        "000000000000000000000000000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000000000000000000000000000DEADBEEF",
        "0000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF"
    };
    char *almost_same_values[] = {
        "DEADBEEF",
        "80000000DEADBEEF",
        "0000000000000000DEADBEE1",
        "000000000000000000000000DEADBEE2",
        "00000000000000000000000000000000DEADBEE3",
        "0000000000000000000000000000000000000000DEADBEE4",
        "000000000008000000000000000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000000000000000000000000000DEADBEE6",
        "0000000000000000000000000000000000000000000000000000000000000000DEADBEE7",
        "000000000000000000000000000000000000000000000000000000000000000000000000DEADBEE8",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEE9",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEA",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEB",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEC"
    };
    struct eq_tests_ctx {
        char *a, *b;
        int expected;
    };
    struct eq_tests_ctx test_vector[] = {
        {values[0], values[0], 1}, {values[0], values[1], 0}, {values[0], values[2], 0}, {values[0], values[3], 0},
        {values[0], values[4], 0}, {values[0], values[5], 0}, {values[1], values[0], 0}, {values[1], values[1], 1},
        {values[1], values[2], 0}, {values[1], values[3], 0}, {values[1], values[4], 0}, {values[1], values[5], 0},
        {values[2], values[0], 0}, {values[2], values[1], 0}, {values[2], values[2], 1}, {values[2], values[3], 0},
        {values[2], values[4], 0}, {values[2], values[5], 0}, {values[3], values[0], 0}, {values[3], values[1], 0},
        {values[3], values[2], 0}, {values[3], values[3], 1}, {values[3], values[4], 0}, {values[3], values[5], 0},
        {values[4], values[0], 0}, {values[4], values[1], 0}, {values[4], values[2], 0}, {values[4], values[3], 0},
        {values[4], values[4], 1}, {values[4], values[5], 0}, {values[5], values[0], 0}, {values[5], values[1], 0},
        {values[5], values[2], 0}, {values[5], values[3], 0}, {values[5], values[4], 0}, {values[5], values[5], 1},

        {same_values[ 0], same_values[ 0], 1}, {same_values[ 0], same_values[ 1], 1}, {same_values[ 0], same_values[ 2], 1},
        {same_values[ 0], same_values[ 3], 1}, {same_values[ 0], same_values[ 4], 1}, {same_values[ 0], same_values[ 5], 1},
        {same_values[ 0], same_values[ 6], 1}, {same_values[ 0], same_values[ 7], 1}, {same_values[ 0], same_values[ 8], 1},
        {same_values[ 0], same_values[ 9], 1}, {same_values[ 0], same_values[10], 1}, {same_values[ 0], same_values[11], 1},
        {same_values[ 0], same_values[12], 1}, {same_values[ 0], same_values[13], 1}, {same_values[ 1], same_values[ 0], 1},
        {same_values[ 1], same_values[ 1], 1}, {same_values[ 1], same_values[ 2], 1}, {same_values[ 1], same_values[ 3], 1},
        {same_values[ 1], same_values[ 4], 1}, {same_values[ 1], same_values[ 5], 1}, {same_values[ 1], same_values[ 6], 1},
        {same_values[ 1], same_values[ 7], 1}, {same_values[ 1], same_values[ 8], 1}, {same_values[ 1], same_values[ 9], 1},
        {same_values[ 1], same_values[10], 1}, {same_values[ 1], same_values[11], 1}, {same_values[ 1], same_values[12], 1},
        {same_values[ 1], same_values[13], 1}, {same_values[ 2], same_values[ 0], 1}, {same_values[ 2], same_values[ 1], 1},
        {same_values[ 2], same_values[ 2], 1}, {same_values[ 2], same_values[ 3], 1}, {same_values[ 2], same_values[ 4], 1},
        {same_values[ 2], same_values[ 5], 1}, {same_values[ 2], same_values[ 6], 1}, {same_values[ 2], same_values[ 7], 1},
        {same_values[ 2], same_values[ 8], 1}, {same_values[ 2], same_values[ 9], 1}, {same_values[ 2], same_values[10], 1},
        {same_values[ 2], same_values[11], 1}, {same_values[ 2], same_values[12], 1}, {same_values[ 2], same_values[13], 1},
        {same_values[ 3], same_values[ 0], 1}, {same_values[ 3], same_values[ 1], 1}, {same_values[ 3], same_values[ 2], 1},
        {same_values[ 3], same_values[ 3], 1}, {same_values[ 3], same_values[ 4], 1}, {same_values[ 3], same_values[ 5], 1},
        {same_values[ 3], same_values[ 6], 1}, {same_values[ 3], same_values[ 7], 1}, {same_values[ 3], same_values[ 8], 1},
        {same_values[ 3], same_values[ 9], 1}, {same_values[ 3], same_values[10], 1}, {same_values[ 3], same_values[11], 1},
        {same_values[ 3], same_values[12], 1}, {same_values[ 3], same_values[13], 1}, {same_values[ 4], same_values[ 0], 1},
        {same_values[ 4], same_values[ 1], 1}, {same_values[ 4], same_values[ 2], 1}, {same_values[ 4], same_values[ 3], 1},
        {same_values[ 4], same_values[ 4], 1}, {same_values[ 4], same_values[ 5], 1}, {same_values[ 4], same_values[ 6], 1},
        {same_values[ 4], same_values[ 7], 1}, {same_values[ 4], same_values[ 8], 1}, {same_values[ 4], same_values[ 9], 1},
        {same_values[ 4], same_values[10], 1}, {same_values[ 4], same_values[11], 1}, {same_values[ 4], same_values[12], 1},
        {same_values[ 4], same_values[13], 1}, {same_values[ 5], same_values[ 0], 1}, {same_values[ 5], same_values[ 1], 1},
        {same_values[ 5], same_values[ 2], 1}, {same_values[ 5], same_values[ 3], 1}, {same_values[ 5], same_values[ 4], 1},
        {same_values[ 5], same_values[ 5], 1}, {same_values[ 5], same_values[ 6], 1}, {same_values[ 5], same_values[ 7], 1},
        {same_values[ 5], same_values[ 8], 1}, {same_values[ 5], same_values[ 9], 1}, {same_values[ 5], same_values[10], 1},
        {same_values[ 5], same_values[11], 1}, {same_values[ 5], same_values[12], 1}, {same_values[ 5], same_values[13], 1},
        {same_values[ 6], same_values[ 0], 1}, {same_values[ 6], same_values[ 1], 1}, {same_values[ 6], same_values[ 2], 1},
        {same_values[ 6], same_values[ 3], 1}, {same_values[ 6], same_values[ 4], 1}, {same_values[ 6], same_values[ 5], 1},
        {same_values[ 6], same_values[ 6], 1}, {same_values[ 6], same_values[ 7], 1}, {same_values[ 6], same_values[ 8], 1},
        {same_values[ 6], same_values[ 9], 1}, {same_values[ 6], same_values[10], 1}, {same_values[ 6], same_values[11], 1},
        {same_values[ 6], same_values[12], 1}, {same_values[ 6], same_values[13], 1}, {same_values[ 7], same_values[ 0], 1},
        {same_values[ 7], same_values[ 1], 1}, {same_values[ 7], same_values[ 2], 1}, {same_values[ 7], same_values[ 3], 1},
        {same_values[ 7], same_values[ 4], 1}, {same_values[ 7], same_values[ 5], 1}, {same_values[ 7], same_values[ 6], 1},
        {same_values[ 7], same_values[ 7], 1}, {same_values[ 7], same_values[ 8], 1}, {same_values[ 7], same_values[ 9], 1},
        {same_values[ 7], same_values[10], 1}, {same_values[ 7], same_values[11], 1}, {same_values[ 7], same_values[12], 1},
        {same_values[ 7], same_values[13], 1}, {same_values[ 8], same_values[ 0], 1}, {same_values[ 8], same_values[ 1], 1},
        {same_values[ 8], same_values[ 2], 1}, {same_values[ 8], same_values[ 3], 1}, {same_values[ 8], same_values[ 4], 1},
        {same_values[ 8], same_values[ 5], 1}, {same_values[ 8], same_values[ 6], 1}, {same_values[ 8], same_values[ 7], 1},
        {same_values[ 8], same_values[ 8], 1}, {same_values[ 8], same_values[ 9], 1}, {same_values[ 8], same_values[10], 1},
        {same_values[ 8], same_values[11], 1}, {same_values[ 8], same_values[12], 1}, {same_values[ 8], same_values[13], 1},
        {same_values[ 9], same_values[ 0], 1}, {same_values[ 9], same_values[ 1], 1}, {same_values[ 9], same_values[ 2], 1},
        {same_values[ 9], same_values[ 3], 1}, {same_values[ 9], same_values[ 4], 1}, {same_values[ 9], same_values[ 5], 1},
        {same_values[ 9], same_values[ 6], 1}, {same_values[ 9], same_values[ 7], 1}, {same_values[ 9], same_values[ 8], 1},
        {same_values[ 9], same_values[ 9], 1}, {same_values[ 9], same_values[10], 1}, {same_values[ 9], same_values[11], 1},
        {same_values[ 9], same_values[12], 1}, {same_values[ 9], same_values[13], 1}, {same_values[10], same_values[ 0], 1},
        {same_values[10], same_values[ 1], 1}, {same_values[10], same_values[ 2], 1}, {same_values[10], same_values[ 3], 1},
        {same_values[10], same_values[ 4], 1}, {same_values[10], same_values[ 5], 1}, {same_values[10], same_values[ 6], 1},
        {same_values[10], same_values[ 7], 1}, {same_values[10], same_values[ 8], 1}, {same_values[10], same_values[ 9], 1},
        {same_values[10], same_values[10], 1}, {same_values[10], same_values[11], 1}, {same_values[10], same_values[12], 1},
        {same_values[10], same_values[13], 1}, {same_values[11], same_values[ 0], 1}, {same_values[11], same_values[ 1], 1},
        {same_values[11], same_values[ 2], 1}, {same_values[11], same_values[ 3], 1}, {same_values[11], same_values[ 4], 1},
        {same_values[11], same_values[ 5], 1}, {same_values[11], same_values[ 6], 1}, {same_values[11], same_values[ 7], 1},
        {same_values[11], same_values[ 8], 1}, {same_values[11], same_values[ 9], 1}, {same_values[11], same_values[10], 1},
        {same_values[11], same_values[11], 1}, {same_values[11], same_values[12], 1}, {same_values[11], same_values[13], 1},
        {same_values[12], same_values[ 0], 1}, {same_values[12], same_values[ 1], 1}, {same_values[12], same_values[ 2], 1},
        {same_values[12], same_values[ 3], 1}, {same_values[12], same_values[ 4], 1}, {same_values[12], same_values[ 5], 1},
        {same_values[12], same_values[ 6], 1}, {same_values[12], same_values[ 7], 1}, {same_values[12], same_values[ 8], 1},
        {same_values[12], same_values[ 9], 1}, {same_values[12], same_values[10], 1}, {same_values[12], same_values[11], 1},
        {same_values[12], same_values[12], 1}, {same_values[12], same_values[13], 1}, {same_values[13], same_values[ 0], 1},
        {same_values[13], same_values[ 1], 1}, {same_values[13], same_values[ 2], 1}, {same_values[13], same_values[ 3], 1},
        {same_values[13], same_values[ 4], 1}, {same_values[13], same_values[ 5], 1}, {same_values[13], same_values[ 6], 1},
        {same_values[13], same_values[ 7], 1}, {same_values[13], same_values[ 8], 1}, {same_values[13], same_values[ 9], 1},
        {same_values[13], same_values[10], 1}, {same_values[13], same_values[11], 1}, {same_values[13], same_values[12], 1},
        {same_values[13], same_values[13], 1},

        {almost_same_values[ 0], almost_same_values[ 1], 0}, {almost_same_values[ 0], almost_same_values[ 2], 0},
        {almost_same_values[ 0], almost_same_values[ 3], 0}, {almost_same_values[ 0], almost_same_values[ 4], 0},
        {almost_same_values[ 0], almost_same_values[ 5], 0}, {almost_same_values[ 0], almost_same_values[ 6], 0},
        {almost_same_values[ 0], almost_same_values[ 7], 0}, {almost_same_values[ 0], almost_same_values[ 8], 0},
        {almost_same_values[ 0], almost_same_values[ 9], 0}, {almost_same_values[ 0], almost_same_values[10], 0},
        {almost_same_values[ 0], almost_same_values[11], 0}, {almost_same_values[ 0], almost_same_values[12], 0},
        {almost_same_values[ 0], almost_same_values[13], 0}, {almost_same_values[ 1], almost_same_values[ 0], 0},
        {almost_same_values[ 1], almost_same_values[ 2], 0}, {almost_same_values[ 1], almost_same_values[ 3], 0},
        {almost_same_values[ 1], almost_same_values[ 4], 0}, {almost_same_values[ 1], almost_same_values[ 5], 0},
        {almost_same_values[ 1], almost_same_values[ 6], 0}, {almost_same_values[ 1], almost_same_values[ 7], 0},
        {almost_same_values[ 1], almost_same_values[ 8], 0}, {almost_same_values[ 1], almost_same_values[ 9], 0},
        {almost_same_values[ 1], almost_same_values[10], 0}, {almost_same_values[ 1], almost_same_values[11], 0},
        {almost_same_values[ 1], almost_same_values[12], 0}, {almost_same_values[ 1], almost_same_values[13], 0},
        {almost_same_values[ 2], almost_same_values[ 0], 0}, {almost_same_values[ 2], almost_same_values[ 1], 0},
        {almost_same_values[ 2], almost_same_values[ 3], 0}, {almost_same_values[ 2], almost_same_values[ 4], 0},
        {almost_same_values[ 2], almost_same_values[ 5], 0}, {almost_same_values[ 2], almost_same_values[ 6], 0},
        {almost_same_values[ 2], almost_same_values[ 7], 0}, {almost_same_values[ 2], almost_same_values[ 8], 0},
        {almost_same_values[ 2], almost_same_values[ 9], 0}, {almost_same_values[ 2], almost_same_values[10], 0},
        {almost_same_values[ 2], almost_same_values[11], 0}, {almost_same_values[ 2], almost_same_values[12], 0},
        {almost_same_values[ 2], almost_same_values[13], 0}, {almost_same_values[ 3], almost_same_values[ 0], 0},
        {almost_same_values[ 3], almost_same_values[ 1], 0}, {almost_same_values[ 3], almost_same_values[ 2], 0},
        {almost_same_values[ 3], almost_same_values[ 4], 0}, {almost_same_values[ 3], almost_same_values[ 5], 0},
        {almost_same_values[ 3], almost_same_values[ 6], 0}, {almost_same_values[ 3], almost_same_values[ 7], 0},
        {almost_same_values[ 3], almost_same_values[ 8], 0}, {almost_same_values[ 3], almost_same_values[ 9], 0},
        {almost_same_values[ 3], almost_same_values[10], 0}, {almost_same_values[ 3], almost_same_values[11], 0},
        {almost_same_values[ 3], almost_same_values[12], 0}, {almost_same_values[ 3], almost_same_values[13], 0},
        {almost_same_values[ 4], almost_same_values[ 0], 0}, {almost_same_values[ 4], almost_same_values[ 1], 0},
        {almost_same_values[ 4], almost_same_values[ 2], 0}, {almost_same_values[ 4], almost_same_values[ 3], 0},
        {almost_same_values[ 4], almost_same_values[ 5], 0}, {almost_same_values[ 4], almost_same_values[ 6], 0},
        {almost_same_values[ 4], almost_same_values[ 7], 0}, {almost_same_values[ 4], almost_same_values[ 8], 0},
        {almost_same_values[ 4], almost_same_values[ 9], 0}, {almost_same_values[ 4], almost_same_values[10], 0},
        {almost_same_values[ 4], almost_same_values[11], 0}, {almost_same_values[ 4], almost_same_values[12], 0},
        {almost_same_values[ 4], almost_same_values[13], 0}, {almost_same_values[ 5], almost_same_values[ 0], 0},
        {almost_same_values[ 5], almost_same_values[ 1], 0}, {almost_same_values[ 5], almost_same_values[ 2], 0},
        {almost_same_values[ 5], almost_same_values[ 3], 0}, {almost_same_values[ 5], almost_same_values[ 4], 0},
        {almost_same_values[ 5], almost_same_values[ 6], 0}, {almost_same_values[ 5], almost_same_values[ 7], 0},
        {almost_same_values[ 5], almost_same_values[ 8], 0}, {almost_same_values[ 5], almost_same_values[ 9], 0},
        {almost_same_values[ 5], almost_same_values[10], 0}, {almost_same_values[ 5], almost_same_values[11], 0},
        {almost_same_values[ 5], almost_same_values[12], 0}, {almost_same_values[ 5], almost_same_values[13], 0},
        {almost_same_values[ 6], almost_same_values[ 0], 0}, {almost_same_values[ 6], almost_same_values[ 1], 0},
        {almost_same_values[ 6], almost_same_values[ 2], 0}, {almost_same_values[ 6], almost_same_values[ 3], 0},
        {almost_same_values[ 6], almost_same_values[ 4], 0}, {almost_same_values[ 6], almost_same_values[ 5], 0},
        {almost_same_values[ 6], almost_same_values[ 7], 0}, {almost_same_values[ 6], almost_same_values[ 8], 0},
        {almost_same_values[ 6], almost_same_values[ 9], 0}, {almost_same_values[ 6], almost_same_values[10], 0},
        {almost_same_values[ 6], almost_same_values[11], 0}, {almost_same_values[ 6], almost_same_values[12], 0},
        {almost_same_values[ 6], almost_same_values[13], 0}, {almost_same_values[ 7], almost_same_values[ 0], 0},
        {almost_same_values[ 7], almost_same_values[ 1], 0}, {almost_same_values[ 7], almost_same_values[ 2], 0},
        {almost_same_values[ 7], almost_same_values[ 3], 0}, {almost_same_values[ 7], almost_same_values[ 4], 0},
        {almost_same_values[ 7], almost_same_values[ 5], 0}, {almost_same_values[ 7], almost_same_values[ 6], 0},
        {almost_same_values[ 7], almost_same_values[ 8], 0}, {almost_same_values[ 7], almost_same_values[ 9], 0},
        {almost_same_values[ 7], almost_same_values[10], 0}, {almost_same_values[ 7], almost_same_values[11], 0},
        {almost_same_values[ 7], almost_same_values[12], 0}, {almost_same_values[ 7], almost_same_values[13], 0},
        {almost_same_values[ 8], almost_same_values[ 0], 0}, {almost_same_values[ 8], almost_same_values[ 1], 0},
        {almost_same_values[ 8], almost_same_values[ 2], 0}, {almost_same_values[ 8], almost_same_values[ 3], 0},
        {almost_same_values[ 8], almost_same_values[ 4], 0}, {almost_same_values[ 8], almost_same_values[ 5], 0},
        {almost_same_values[ 8], almost_same_values[ 6], 0}, {almost_same_values[ 8], almost_same_values[ 7], 0},
        {almost_same_values[ 8], almost_same_values[ 9], 0}, {almost_same_values[ 8], almost_same_values[10], 0},
        {almost_same_values[ 8], almost_same_values[11], 0}, {almost_same_values[ 8], almost_same_values[12], 0},
        {almost_same_values[ 8], almost_same_values[13], 0}, {almost_same_values[ 9], almost_same_values[ 0], 0},
        {almost_same_values[ 9], almost_same_values[ 1], 0}, {almost_same_values[ 9], almost_same_values[ 2], 0},
        {almost_same_values[ 9], almost_same_values[ 3], 0}, {almost_same_values[ 9], almost_same_values[ 4], 0},
        {almost_same_values[ 9], almost_same_values[ 5], 0}, {almost_same_values[ 9], almost_same_values[ 6], 0},
        {almost_same_values[ 9], almost_same_values[ 7], 0}, {almost_same_values[ 9], almost_same_values[ 8], 0},
        {almost_same_values[ 9], almost_same_values[10], 0}, {almost_same_values[ 9], almost_same_values[11], 0},
        {almost_same_values[ 9], almost_same_values[12], 0}, {almost_same_values[ 9], almost_same_values[13], 0},
        {almost_same_values[10], almost_same_values[ 0], 0}, {almost_same_values[10], almost_same_values[ 1], 0},
        {almost_same_values[10], almost_same_values[ 2], 0}, {almost_same_values[10], almost_same_values[ 3], 0},
        {almost_same_values[10], almost_same_values[ 4], 0}, {almost_same_values[10], almost_same_values[ 5], 0},
        {almost_same_values[10], almost_same_values[ 6], 0}, {almost_same_values[10], almost_same_values[ 7], 0},
        {almost_same_values[10], almost_same_values[ 8], 0}, {almost_same_values[10], almost_same_values[ 9], 0},
        {almost_same_values[10], almost_same_values[11], 0}, {almost_same_values[10], almost_same_values[12], 0},
        {almost_same_values[10], almost_same_values[13], 0}, {almost_same_values[11], almost_same_values[ 0], 0},
        {almost_same_values[11], almost_same_values[ 1], 0}, {almost_same_values[11], almost_same_values[ 2], 0},
        {almost_same_values[11], almost_same_values[ 3], 0}, {almost_same_values[11], almost_same_values[ 4], 0},
        {almost_same_values[11], almost_same_values[ 5], 0}, {almost_same_values[11], almost_same_values[ 6], 0},
        {almost_same_values[11], almost_same_values[ 7], 0}, {almost_same_values[11], almost_same_values[ 8], 0},
        {almost_same_values[11], almost_same_values[ 9], 0}, {almost_same_values[11], almost_same_values[10], 0},
        {almost_same_values[11], almost_same_values[12], 0}, {almost_same_values[11], almost_same_values[13], 0},
        {almost_same_values[12], almost_same_values[ 0], 0}, {almost_same_values[12], almost_same_values[ 1], 0},
        {almost_same_values[12], almost_same_values[ 2], 0}, {almost_same_values[12], almost_same_values[ 3], 0},
        {almost_same_values[12], almost_same_values[ 4], 0}, {almost_same_values[12], almost_same_values[ 5], 0},
        {almost_same_values[12], almost_same_values[ 6], 0}, {almost_same_values[12], almost_same_values[ 7], 0},
        {almost_same_values[12], almost_same_values[ 8], 0}, {almost_same_values[12], almost_same_values[ 9], 0},
        {almost_same_values[12], almost_same_values[10], 0}, {almost_same_values[12], almost_same_values[11], 0},
        {almost_same_values[12], almost_same_values[13], 0}, {almost_same_values[13], almost_same_values[ 0], 0},
        {almost_same_values[13], almost_same_values[ 1], 0}, {almost_same_values[13], almost_same_values[ 2], 0},
        {almost_same_values[13], almost_same_values[ 3], 0}, {almost_same_values[13], almost_same_values[ 4], 0},
        {almost_same_values[13], almost_same_values[ 5], 0}, {almost_same_values[13], almost_same_values[ 6], 0},
        {almost_same_values[13], almost_same_values[ 7], 0}, {almost_same_values[13], almost_same_values[ 8], 0},
        {almost_same_values[13], almost_same_values[ 9], 0}, {almost_same_values[13], almost_same_values[10], 0},
        {almost_same_values[13], almost_same_values[11], 0}, {almost_same_values[13], almost_same_values[12], 0}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_mp_value_t *a, *b;

    for (t = 0; t < test_vector_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, kstrlen(test_vector[t].a));
        KUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[t].b, kstrlen(test_vector[t].b));
        KUTE_ASSERT(b != NULL);
        KUTE_ASSERT(kryptos_mp_eq(a, b) == test_vector[t].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }

KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_get_gt_tests)
    char *values[] = {
        "00000002",
        "0000000000000001",
        "000000000000000000000000000000000000000000000000000000A",
        "FF"
    };
    kryptos_mp_value_t *a, *b;

    a = kryptos_hex_value_as_mp(values[0], kstrlen(values[0]));
    b = kryptos_hex_value_as_mp(values[1], kstrlen(values[1]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[0], kstrlen(values[0]));
    b = kryptos_hex_value_as_mp(values[2], kstrlen(values[2]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[0], kstrlen(values[0]));
    b = kryptos_hex_value_as_mp(values[3], kstrlen(values[3]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[1], kstrlen(values[1]));
    b = kryptos_hex_value_as_mp(values[0], kstrlen(values[0]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[1], kstrlen(values[1]));
    b = kryptos_hex_value_as_mp(values[2], kstrlen(values[2]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[1], kstrlen(values[1]));
    b = kryptos_hex_value_as_mp(values[3], kstrlen(values[3]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[2], kstrlen(values[2]));
    b = kryptos_hex_value_as_mp(values[1], kstrlen(values[1]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[2], kstrlen(values[2]));
    b = kryptos_hex_value_as_mp(values[0], kstrlen(values[0]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[2], kstrlen(values[2]));
    b = kryptos_hex_value_as_mp(values[3], kstrlen(values[3]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[3], kstrlen(values[3]));
    b = kryptos_hex_value_as_mp(values[1], kstrlen(values[1]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[3], kstrlen(values[3]));
    b = kryptos_hex_value_as_mp(values[2], kstrlen(values[2]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[3], kstrlen(values[3]));
    b = kryptos_hex_value_as_mp(values[0], kstrlen(values[0]));
    KUTE_ASSERT(a != NULL && b != NULL);
    KUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_ne_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct ne_tests_ctx {
        char *a, *b;
        int expected;
    };
    struct ne_tests_ctx test_vector[] = {
        {values[0], values[0], 0},
        {values[0], values[1], 1},
        {values[0], values[2], 1},
        {values[0], values[3], 1},
        {values[1], values[0], 1},
        {values[1], values[1], 0},
        {values[1], values[2], 1},
        {values[1], values[3], 1},
        {values[2], values[0], 1},
        {values[2], values[1], 1},
        {values[2], values[2], 0},
        {values[2], values[3], 1},
        {values[3], values[0], 1},
        {values[3], values[1], 1},
        {values[3], values[2], 1},
        {values[3], values[3], 0}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        KUTE_ASSERT(b != NULL);
        KUTE_ASSERT(kryptos_mp_ne(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_gt_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct gt_tests_ctx {
        char *a, *b;
        int expected;
    };
    struct gt_tests_ctx test_vector[] = {
        {values[0], values[0], 0},
        {values[0], values[1], 0},
        {values[0], values[2], 0},
        {values[0], values[3], 0},
        {values[1], values[0], 1},
        {values[1], values[1], 0},
        {values[1], values[2], 0},
        {values[1], values[3], 0},
        {values[2], values[0], 1},
        {values[2], values[1], 1},
        {values[2], values[2], 0},
        {values[2], values[3], 0},
        {values[3], values[0], 1},
        {values[3], values[1], 1},
        {values[3], values[2], 1},
        {values[3], values[3], 0}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        KUTE_ASSERT(b != NULL);
        KUTE_ASSERT(kryptos_mp_gt(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_lt_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct lt_tests_ctx {
        char *a, *b;
        int expected;
    };
    struct lt_tests_ctx test_vector[] = {
        {values[0], values[0], 0},
        {values[0], values[1], 1},
        {values[0], values[2], 1},
        {values[0], values[3], 1},
        {values[1], values[0], 0},
        {values[1], values[1], 0},
        {values[1], values[2], 1},
        {values[1], values[3], 1},
        {values[2], values[0], 0},
        {values[2], values[1], 0},
        {values[2], values[2], 0},
        {values[2], values[3], 1},
        {values[3], values[0], 0},
        {values[3], values[1], 0},
        {values[3], values[2], 0},
        {values[3], values[3], 0}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        KUTE_ASSERT(b != NULL);
        KUTE_ASSERT(kryptos_mp_lt(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_ge_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct ge_tests_ctx {
        char *a, *b;
        int expected;
    };
    struct ge_tests_ctx test_vector[] = {
        {values[0], values[0], 1},
        {values[0], values[1], 0},
        {values[0], values[2], 0},
        {values[0], values[3], 0},
        {values[1], values[0], 1},
        {values[1], values[1], 1},
        {values[1], values[2], 0},
        {values[1], values[3], 0},
        {values[2], values[0], 1},
        {values[2], values[1], 1},
        {values[2], values[2], 1},
        {values[2], values[3], 0},
        {values[3], values[0], 1},
        {values[3], values[1], 1},
        {values[3], values[2], 1},
        {values[3], values[3], 1}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        KUTE_ASSERT(b != NULL);
        KUTE_ASSERT(kryptos_mp_ge(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_le_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct le_tests_ctx {
        char *a, *b;
        int expected;
    };
    struct le_tests_ctx test_vector[] = {
        {values[0], values[0], 1},
        {values[0], values[1], 1},
        {values[0], values[2], 1},
        {values[0], values[3], 1},
        {values[1], values[0], 0},
        {values[1], values[1], 1},
        {values[1], values[2], 1},
        {values[1], values[3], 1},
        {values[2], values[0], 0},
        {values[2], values[1], 0},
        {values[2], values[2], 1},
        {values[2], values[3], 1},
        {values[3], values[0], 0},
        {values[3], values[1], 0},
        {values[3], values[2], 0},
        {values[3], values[3], 1}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        KUTE_ASSERT(b != NULL);
        KUTE_ASSERT(kryptos_mp_le(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_is_neg_tests)
    struct is_neg_tests_ctx {
        char *v;
        int is_neg;
    };
#ifndef KRYPTOS_MP_U32_DIGIT
    struct is_neg_tests_ctx test_vector[] = {
        {                 "2", 0 },
        {                "-2", 1 },
        {              "0002", 0 },
        {             "-0002", 1 },
        {          "0000000A", 0 },
        {         "-0000000A", 1 },
        {          "21524111", 0 },
        {          "DEADBEEF", 0 },
        {  "2152411021524111", 0 },
        {  "DEADBEEFDEADBEEF", 0 }
    };
#else
    struct is_neg_tests_ctx test_vector[] = {
        {                 "2", 0 },
        {                "-2", 1 },
        {              "0002", 0 },
        {             "-0002", 1 },
        {          "0000000A", 0 },
        {         "-0000000A", 1 },
        {          "21524111", 0 },
        {          "DEADBEEF", 0 },
        {  "2152411021524111", 0 },
        {  "DEADBEEFDEADBEEF", 0 }
    };
#endif
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *v;
    for (tv = 0; tv < tv_nr; tv++) {
        v = kryptos_hex_value_as_mp(test_vector[tv].v, kstrlen(test_vector[tv].v));
        KUTE_ASSERT(v != NULL);
        KUTE_ASSERT(kryptos_mp_is_neg(v) == test_vector[tv].is_neg);
        kryptos_del_mp_value(v);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_add_tests)
    kryptos_mp_value_t *a, *b, *e;
    struct add_tests_ctx {
        char *a, *b, *e;
    };
#ifndef KRYPTOS_MP_U32_DIGIT
    struct add_tests_ctx test_vector[] = {
        {       "01",       "01",        "02" },
        {       "02",       "0A",        "0C" },
        {     "DEAD",     "BEEF",      "9D9C" },
        {     "6671",       "00",      "6671" },
        { "DEADBEEF",     "BEEF",  "DEAE7DDE" },
        { "DEADBEEF", "DEADBEEF", "1BD5B7DDE" },
        { "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFF7300",
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFF7300",
                                                      "1FFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFEE600"   }
    };
#else
    struct add_tests_ctx test_vector[] = {
        {       "01",       "01",        "02" },
        {       "02",       "0A",        "0C" },
        {     "DEAD",     "BEEF",     "19D9C" },
        {     "6671",       "00",      "6671" },
        { "DEADBEEF",     "BEEF",  "DEAE7DDE" },
        { "DEADBEEF", "DEADBEEF", "1BD5B7DDE" },
        { "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFFFFFFFFFF"
          "FFFFFFFFFFFF7300",
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFF7300",
                                                      "1FFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFFFFFFFFF"
                                                      "FFFFFFFFFFFFEE600"   }
    };
#endif
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    // INFO(Rafael): (null) = (null) + 1;
    b = kryptos_hex_value_as_mp("01", 2);
    KUTE_ASSERT(b != NULL);
    a = NULL;
    a = kryptos_mp_add(&a, b);
    KUTE_ASSERT(a != NULL);
    KUTE_ASSERT(kryptos_mp_eq(a, b) == 1);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        b = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, kstrlen(test_vector[tv].e));

        KUTE_ASSERT(a != NULL && b != NULL && e != NULL);

        a = kryptos_mp_add(&a, b);

        KUTE_ASSERT(a != NULL);

        KUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(e);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_sub_tests)
    kryptos_mp_value_t *a, *b, *e;
    struct sub_tests_ctx {
        char *a, *b, *e;
    };
#ifndef KRYPTOS_MP_U32_DIGIT
    struct sub_tests_ctx test_vector[] = {
        {               "01",        "1",                "0" },
        {               "06",       "02",               "04" },
        {             "2001",     "1006",              "FFB" },
        {             "DEAD",     "BEEF",             "1FBE" },
        {             "BEEF",     "DEAD",            "-1FBE" },
        {               "01",       "02",              "-01" },
        {         "DEADBEEF", "BEEFDEAD",         "1FBDE042" },
        {                "5",     "1006",            "-1001" },
        {               "10",     "1006",             "-FF6" },
        { "BABABABABABABABA",       "FD", "BABABABABABAB9BD" },
        { "2B2CC74FC1B75D0F"
          "9C18DC99223085A5"
          "EB12D039DFB91475"
          "E99E4B1A7E4F3BF9"
          "D1741969150D072D"
          "5956A0D5668FB0A8"
          "04A75FE572E9AD34"
          "5F3AA6BBF5F2DE06"
          "3D8556760F474F5C"
          "6B4CB525D1B36383"
          "15ACE084993BCE2B"
          "5D87BA2EF383F8E8"
          "783BC43BD2564E3D"
          "58318D6F2D712361"
          "6EF11F5D696EE176"
          "34BE105678DBDD80"
          "AEF23E5FBBBD04F5"
          "3A50430D72A2A149"
          "BDB4D5DD68B5C2FF"
          "F0EA213BC00BE620"
          "AA0753B68FFACFB1"
          "09110CC071E13FF3"
          "884ECFE7F6", "2ACA8449BD982E18"
                        "C8C4000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000", "624306041F2EF6D3"
                                      "54DC99223085A5EB"
                                      "12D039DFB91475E9"
                                      "9E4B1A7E4F3BF9D1"
                                      "741969150D072D59"
                                      "56A0D5668FB0A804"
                                      "A75FE572E9AD345F"
                                      "3AA6BBF5F2DE063D"
                                      "8556760F474F5C6B"
                                      "4CB525D1B3638315"
                                      "ACE084993BCE2B5D"
                                      "87BA2EF383F8E878"
                                      "3BC43BD2564E3D58"
                                      "318D6F2D7123616E"
                                      "F11F5D696EE17634"
                                      "BE105678DBDD80AE"
                                      "F23E5FBBBD04F53A"
                                      "50430D72A2A149BD"
                                      "B4D5DD68B5C2FFF0"
                                      "EA213BC00BE620AA"
                                      "0753B68FFACFB109"
                                      "110CC071E13FF388"
                                      "4ECFE7F6" },
        { "4083FB324A10B35102CBB276A0348322", "4083FB321A15F35FA412BEF100000000", "2FFABFF15EB8F385A0348322" }
    };
#else
    struct sub_tests_ctx test_vector[] = {
        {               "01",        "1",                "0" },
        {               "06",       "02",               "04" },
        {             "2001",     "1006",              "FFB" },
        {             "DEAD",     "BEEF",             "1FBE" },
        {             "BEEF",     "DEAD",            "-1FBE" },
        {               "01",       "02",              "-01" },
        {         "DEADBEEF", "BEEFDEAD",         "1FBDE042" },
        {                "5",     "1006",            "-1001" },
        {               "10",     "1006",             "-FF6" },
        { "BABABABABABABABA",       "FD", "BABABABABABAB9BD" },
        { "2B2CC74FC1B75D0F"
          "9C18DC99223085A5"
          "EB12D039DFB91475"
          "E99E4B1A7E4F3BF9"
          "D1741969150D072D"
          "5956A0D5668FB0A8"
          "04A75FE572E9AD34"
          "5F3AA6BBF5F2DE06"
          "3D8556760F474F5C"
          "6B4CB525D1B36383"
          "15ACE084993BCE2B"
          "5D87BA2EF383F8E8"
          "783BC43BD2564E3D"
          "58318D6F2D712361"
          "6EF11F5D696EE176"
          "34BE105678DBDD80"
          "AEF23E5FBBBD04F5"
          "3A50430D72A2A149"
          "BDB4D5DD68B5C2FF"
          "F0EA213BC00BE620"
          "AA0753B68FFACFB1"
          "09110CC071E13FF3"
          "884ECFE7F6", "2ACA8449BD982E18"
                        "C8C4000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000000000"
                        "0000000000", "624306041F2EF6D3"
                                      "54DC99223085A5EB"
                                      "12D039DFB91475E9"
                                      "9E4B1A7E4F3BF9D1"
                                      "741969150D072D59"
                                      "56A0D5668FB0A804"
                                      "A75FE572E9AD345F"
                                      "3AA6BBF5F2DE063D"
                                      "8556760F474F5C6B"
                                      "4CB525D1B3638315"
                                      "ACE084993BCE2B5D"
                                      "87BA2EF383F8E878"
                                      "3BC43BD2564E3D58"
                                      "318D6F2D7123616E"
                                      "F11F5D696EE17634"
                                      "BE105678DBDD80AE"
                                      "F23E5FBBBD04F53A"
                                      "50430D72A2A149BD"
                                      "B4D5DD68B5C2FFF0"
                                      "EA213BC00BE620AA"
                                      "0753B68FFACFB109"
                                      "110CC071E13FF388"
                                      "4ECFE7F6" },
        { "4083FB324A10B35102CBB276A0348322", "4083FB321A15F35FA412BEF100000000", "2FFABFF15EB8F385A0348322" },
    };
#endif
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    a = NULL;
    b = kryptos_hex_value_as_mp("101", 3);

    KUTE_ASSERT(b != NULL);

    a = kryptos_mp_sub(&a, b);

    KUTE_ASSERT(a != NULL);

    KUTE_ASSERT(kryptos_mp_eq(a, b) == 1);

    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        b = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, kstrlen(test_vector[tv].e));

        KUTE_ASSERT(a != NULL && b != NULL && e != NULL);

        a = kryptos_mp_sub(&a, b);

        KUTE_ASSERT(a != NULL);

        KUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(e);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_mul_tests)
    kryptos_mp_value_t *a, *b, *e;
    struct mul_tests_ctx {
        char *a, *b, *e;
    };
    struct mul_tests_ctx test_vector[] = {
        {                "2",        "4",                        "8" },
        {                "2",       "44",                       "88" },
        {               "22",       "44",                      "908" },
        {              "101",     "1001",                   "101101" },
        {             "DEAD",     "BEEF",                 "A6144983" },
        {             "BEEF",     "DEAD",                 "A6144983" },
        {               "FF",       "FF",                     "FE01" },
        {             "FFFF",     "FFFF",                 "FFFE0001" },
        {         "FFFFFFFF", "FFFFFFFF",         "FFFFFFFE00000001" },
        {         "DEADBEEF",     "DEAD",             "C1B126FD4983" },
        { "DEADBEEFDEADBEEF", "DEADBEEF", "C1B1CD12E31F7033216DA321" },
        {           "FD02FF",       "FF",                 "FC05FC01" }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    a = NULL;
    b = kryptos_hex_value_as_mp("2", 1);
    KUTE_ASSERT(b != NULL);
    a = kryptos_mp_mul(&a, b);
    KUTE_ASSERT(a != NULL);
    KUTE_ASSERT(kryptos_mp_eq(a, b) == 1);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        b = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, kstrlen(test_vector[tv].e));

        KUTE_ASSERT(a != NULL && b != NULL && e != NULL);

        a = kryptos_mp_mul(&a, b);

        KUTE_ASSERT(a != NULL);

        KUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(e);
    }

KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_mul_digit_tests)
    struct mul_digit_tests_ctx {
        char *n;
        kryptos_u8_t d;
        char *e;
    };
    struct mul_digit_tests_ctx test_vector[] = {
        { "0000000022", 0x02, "000000000044" },
        { "00000000FF", 0x50, "000000004FB0" },
        { "FFFFFFFFFF", 0x99, "98FFFFFFFF67" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *n, *e;
    for (tv = 0; tv < tv_nr; tv++) {
        n = kryptos_hex_value_as_mp(test_vector[tv].n, kstrlen(test_vector[tv].n));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, kstrlen(test_vector[tv].e));
        KUTE_ASSERT(n != NULL && e != NULL);
        n = kryptos_mp_mul_digit(&n, test_vector[tv].d);
        KUTE_ASSERT(n != NULL);
        KUTE_ASSERT(kryptos_mp_eq(n, e) == 1);
        kryptos_del_mp_value(n);
        kryptos_del_mp_value(e);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_not_tests)
    struct not_tests_ctx {
        char *n, *en;
    };
#ifndef KRYPTOS_MP_U32_DIGIT
    struct not_tests_ctx test_vector[] = {
        {               "FE",                "1" },
        {                "1",               "FE" },
        {             "FFFE",                "1" },
        {             "0001",             "FFFE" },
        {         "FFFFFFFE",         "00000001" },
        {         "00000001",         "FFFFFFFE" },
        { "FFFFFFFFFFFFFFFE", "0000000000000001" },
        { "0000000000000001", "FFFFFFFFFFFFFFFE" }
    };
#else
    struct not_tests_ctx test_vector[] = {
# if !defined(KRYPTOS_MP_EXTENDED_RADIX)
        {               "FE",         "FFFFFF01" },
        {                "1",         "FFFFFFFE" },
        {             "FFFE",         "FFFF0001" },
        {             "0001",         "FFFFFFFE" },
        {         "FFFFFFFE",         "00000001" },
        {         "00000001",         "FFFFFFFE" },
        { "FFFFFFFFFFFFFFFE", "0000000000000001" },
        { "0000000000000001", "FFFFFFFFFFFFFFFE" }
# else
        {               "FE", "FFFFFFFFFFFFFF01" },
        {                "1", "FFFFFFFFFFFFFFFE" },
        {             "FFFE", "FFFFFFFFFFFF0001" },
        {             "0001", "FFFFFFFFFFFFFFFE" },
        { "FFFFFFFFFFFFFFFE", "0000000000000001" },
        {         "00000001", "FFFFFFFFFFFFFFFE" },
        { "FFFFFFFFFFFFFFFE", "0000000000000001" },
        { "0000000000000001", "FFFFFFFFFFFFFFFE" }
# endif
    };
#endif
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *n, *en;
    for (tv = 0; tv < tv_nr; tv++) {
        n = kryptos_hex_value_as_mp(test_vector[tv].n, kstrlen(test_vector[tv].n));
        KUTE_ASSERT(n != NULL);
        en = kryptos_hex_value_as_mp(test_vector[tv].en, kstrlen(test_vector[tv].en));
        KUTE_ASSERT(en != NULL);
        n = kryptos_mp_not(n);
        KUTE_ASSERT(kryptos_mp_eq(n, en) == 1);
        kryptos_del_mp_value(n);
        kryptos_del_mp_value(en);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_div_tests)
    kryptos_mp_value_t *x, *y, *q, *r, *eq, *er;
    struct div_tests_ctx {
        char *x, *y, *eq, *er;
    };
    struct div_tests_ctx test_vector[] = {
        {                             "0002",                "1",                "2",                "0" },
        {                             "0002",                "2",                "1",                "0" },
        {                             "0003",                "2",                "1",                "1" },
        {                             "0004",                "2",                "2",                "0" },
        {                             "0007",                "2",                "3",                "1" },
        {                             "0008",                "2",                "4",                "0" },
        {                                "2",                "2",                "1",                "0" },
        {                                "3",                "2",                "1",                "1" },
        {                                "4",                "2",                "2",                "0" },
        {                                "7",                "2",                "3",                "1" },
        {                                "8",                "2",                "4",                "0" },
        {                              "ABC",              "BAD",                "0",              "ABC" },
        {                              "BAD",              "ABC",                "1",               "F1" },
        {                             "DEAD",             "BEEF",                "1",             "1FBE" },
        {                              "100",               "50",                "3",               "10" },
        {                         "DEADBEEF",            "DEADB",             "1000",              "EEF" },
        {                     "DEADBEEFDEAD",         "DEADBEEF",            "10000",             "DEAD" },
        {                            "10001",              "100",              "100",                "1" },
        {                     "BABACABABACA",     "252525252525",                "5",      "10111010111" },
        {                      "ABCDEF01023",      "32010FEDCBA",                "3",      "15CABF379F5" },
        {                          "9876546",             "6671",             "17D0",              "276" },
        {                          "9876546",                "2",          "4C3B2A3",                "0" },
        {                       "41C21CB8E1",               "0D",        "50EEE8460",                "1" },
        {                             "06E4",               "35",               "21",                "F" },
        {                         "0307ED59",             "6EB1",              "702",             "38F7" },
        { "4083FB324A10B35102CBB276A0348322", "C61E99756B0CC3D9", "535D1CD93DFF2556", "8DCBC13907755B3C" },
        {                           "072608",             "0647",              "123",              "353" },
        {                             "3AA4",               "02",             "1D52",                "0" },
        { "0FE95C5A853FEF9DC716090255DA76AB"
          "657A20DF154A3AA3414F0306C0260D0D"
          "E51086E63D51C1093F87735C2F4A665D"
          "E88A13C148C01F3E9401A123DAB73DB7"
          "F225C69EEB361C72F72BB1C8E90AB039"
          "D82D4FB15D260554BA90B88E02E03A53"
          "37AAA2BCE6CF0D86B7B9A8F5AA9E5696"
          "885B88BB43B1A0DE7C143B4D5EF38C1E"
          "7B4A1C262AFA778F92CA15B1CEC74E5D"
          "6F723DEE631E050F701A7923811C7A9A"
          "D3C759205217E6790CEC2749F64D0EFB"
          "7579A5D1775880247C85A8454CEC282A",             "E744", "119D040A78353383"
                                                                  "FB99295D79EE5A29"
                                                                  "7FF2DBD46FC6F801"
                                                                  "8718858E28537E33"
                                                                  "6432E16541DA9C39"
                                                                  "5A17D93D7C13547B"
                                                                  "8802293476600F36"
                                                                  "E5DF626A1254A32B"
                                                                  "E3BA7F89775A37F2"
                                                                  "D11771A823E2406B"
                                                                  "33C174B3EFC4863D"
                                                                  "08264BC8750FA9BD"
                                                                  "A68E4A2FDEDB4505"
                                                                  "F74A38CA57684E8D"
                                                                  "7BDF73AC5F347681"
                                                                  "AB5EFCC116E5EAFE"
                                                                  "F58B82DF33BE4EB2"
                                                                  "0EF3EF43E1CC470A"
                                                                  "99A247D7553E7A6B"
                                                                  "68CED4FFEB174F24"
                                                                  "5B0268B64F6C6363"
                                                                  "5A5B0B32F6DF49E3"
                                                                  "003287A4802A9E47"
                                                                  "6B0042B77FA5",                 "5D56" },
        { "9048E998B14FC9A31D8A96E11CE4A9"
          "4BEA7535A618DC99223085A5EB12D0"
          "39DFB91475E99E4B1A7E4F3BF9D174"
          "1969150D072D5956A0D5668FB0A804"
          "A75FE572E9AD345F3AA6BBF5F2DE06"
          "3D8556760F474F5C6B4CB525D1B363"
          "8315ACE084993BCE2B5D87BA2EF383"
          "F8E8783BC43BD2564E3D58318D6F2D"
          "7123616EF11F5D696EE17634BE1056"
          "78DBDD80AEF23E5FBBBD04F53A5043"
          "0D72A2A149BDB4D5DD68B5C2FFF0EA"
          "213BC00BE620AA0753B68FFACFB109"
          "110CC071E13FF3884ECFE7F6",  "675830FF5F9FD4C31A", "01656A56156E4BCD158C0"
                                                             "D596AF368CF4913931F01"
                                                             "0F95FF7711AB7F4E4DC6B"
                                                             "7CC1451A465AF09F6CFC2"
                                                             "238C18BA9D2FE3B9D7DE5"
                                                             "792CB99B620B47C777DDB"
                                                             "A31359298E5CC7EAC8429"
                                                             "F6713381981C82DCB6327"
                                                             "7B52096E8BCA0EEEBFD1D"
                                                             "9CF487D5D7F2CE465D5E0"
                                                             "D8D0BD71FB63CF283EAFC"
                                                             "93C64E38C39D6D79CBE84"
                                                             "09935F428E6A89A7449C0"
                                                             "56E461AD4C592B1C21CB7"
                                                             "3935D8F25EAFBD785B0B9"
                                                             "117A59A741E21D2157EC9"
                                                             "44A6AC320FB825A1EF88A"
                                                             "2DF372CDA3B", "459B1B14412C2ACCF8" },
        { "04000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "00000000000000000000000000000000"
          "0000000000000000", "FFFFFFFFFFFFFFFFC90FDAA22168C234"
                              "C4C6628B80DC1CD129024E088A67CC74"
                              "020BBEA63B139B22514A08798E3404DD"
                              "EF9519B3CD3A431B302B0A6DF25F1437"
                              "4FE1356D6D51C245E485B576625E7EC6"
                              "F44C42E9A637ED6B0BFF5CB6F406B7ED"
                              "EE386BFB5A899FA5AE9F24117C4B1FE6"
                              "49286651ECE45B3DC2007CB8A163BF05"
                              "98DA48361C55D39A69163FA8FD24CF5F"
                              "83655D23DCA3AD961C62F356208552BB"
                              "9ED529077096966D670C354E4ABC9804"
                              "F1746C08CA237327FFFFFFFFFFFFFFFF", "40000000000000000DBC095777A"
                                                                  "5CF72D1C0F39F8BA05465E9B6C3"
                                                                  "D621122D845933F2B17C61CB946"
                                                                  "C7E7EED6FC5BEF9E5A27F0240EA"
                                                                  "0078F5200BEE34CA5543723274F"
                                                                  "648BBB3A6951D76CCF6DEE0EED7"
                                                                  "0384F45A0126EF21B1605D91EC2"
                                                                  "2345EA9731038080D5623B6CB78"
                                                                  "6264D04DC67F09635E6F085", "EB12E1CE72FA80E2782FB48F9331D"
                                                                                             "C9134FACC5F468C73B210A4F16F4D"
                                                                                             "0EDAA5D62AD1024814A78819886C0"
                                                                                             "A90C5ECD02879583E60CAFE0072F1"
                                                                                             "3CE4C6019A83CA385DF98461F765F"
                                                                                             "B99AD6D4201DDBCF21417258F764A"
                                                                                             "CBF02B464A7A43CAC6CE2B738F1E1"
                                                                                             "49443224C2DB20D9CC56D941C5CD9"
                                                                                             "630B78D745821B16FF8272D652474"
                                                                                             "3B11ABB1EC2D4406426E195028241"
                                                                                             "A2E7669FB68BA5B37B38E83C09D98"
                                                                                             "F89AA3DC4D74E9B9972B5508647B2"
                                                                                             "B06E87E5228487D5F93CDC67F0963"
                                                                                             "5E6F085" },
        { "0800000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000", "FFFFFFFFFFFFFFFFC90FDAA22168C2"
                                                            "34C4C6628B80DC1CD129024E088A67"
                                                            "CC74020BBEA63B139B22514A08798E"
                                                            "3404DDEF9519B3CD3A431B302B0A6D"
                                                            "F25F14374FE1356D6D51C245E485B5"
                                                            "76625E7EC6F44C42E9A637ED6B0BFF"
                                                            "5CB6F406B7EDEE386BFB5A899FA5AE"
                                                            "9F24117C4B1FE649286651ECE45B3D"
                                                            "C2007CB8A163BF0598DA48361C55D3"
                                                            "9A69163FA8FD24CF5F83655D23DCA3"
                                                            "AD961C62F356208552BB9ED5290770"
                                                            "96966D670C354E4ABC9804F1746C08"
                                                            "CA237327FFFFFFFFFFFFFFFF",
          "080000000000000001B7812AEE", "F4B9EE5A381E73F13F85C26E1EA4FF6F4"
                                        "DE1B734D38C51A5AECB765ECBAD742999"
                                        "1AF0EB59F86C4D25DA3840B7D053B7F1A"
                                        "8A601B57C66D3F1B00441E44202AB244D"
                                        "1FC491A262ABF6D4D76F9C2EB8105A230"
                                        "BC1A4C662FCAA6C4FE6E0330B90F190C0"
                                        "2665A94DB6FC0A49DD1469855044057F4"
                                        "2A41B30F1369BC536744B289CFE360CF2"
                                        "0D4EECB4E37FFB827135E627C3E213722"
                                        "B5EB8688B35ED1E3E2E104B9861EA9DAA"
                                        "D7F68BC22EEDFA7F2D8ADCE8F9785BA2F"
                                        "E60D000000001B7812AEE" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    x = NULL;
    y = NULL;
    r = NULL;

    KUTE_ASSERT(kryptos_mp_div(x, y, &r) == NULL);

    // INFO(Rafael): Division by zero.

    x = kryptos_hex_value_as_mp("2", 1);
    y = kryptos_hex_value_as_mp("0", 1);
    KUTE_ASSERT(x != NULL && y != NULL);
    KUTE_ASSERT(kryptos_mp_div(x, y, &r) == NULL);
    KUTE_ASSERT(r == NULL);
    kryptos_del_mp_value(x);
    kryptos_del_mp_value(y);


    // INFO(Rafael): 0 / y.

    x = kryptos_hex_value_as_mp("0", 1);
    y = kryptos_hex_value_as_mp("2", 1);
    KUTE_ASSERT(x != NULL && y != NULL);
    eq = kryptos_hex_value_as_mp("0", 1);
    er = kryptos_hex_value_as_mp("0", 1);
    KUTE_ASSERT(eq != NULL && er != NULL);
    q = kryptos_mp_div(x, y, &r);
    KUTE_ASSERT(q != NULL);
    KUTE_ASSERT(r != NULL);
    KUTE_ASSERT(kryptos_mp_eq(q, eq) == 1);
    KUTE_ASSERT(kryptos_mp_eq(r, er) == 1);
    kryptos_del_mp_value(x);
    kryptos_del_mp_value(y);
    kryptos_del_mp_value(r);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(eq);
    kryptos_del_mp_value(er);

    for (tv = 0; tv < tv_nr; tv++) {
        x = kryptos_hex_value_as_mp(test_vector[tv].x, kstrlen(test_vector[tv].x));
        y = kryptos_hex_value_as_mp(test_vector[tv].y, kstrlen(test_vector[tv].y));
        eq = kryptos_hex_value_as_mp(test_vector[tv].eq, kstrlen(test_vector[tv].eq));
        er = kryptos_hex_value_as_mp(test_vector[tv].er, kstrlen(test_vector[tv].er));

        KUTE_ASSERT(x != NULL && y != NULL && eq != NULL && er != NULL);

        q = kryptos_mp_div(x, y, &r);

        KUTE_ASSERT(q != NULL);
        KUTE_ASSERT(r != NULL);

        KUTE_ASSERT(kryptos_mp_eq(q, eq) == 1);
        KUTE_ASSERT(kryptos_mp_eq(r, er) == 1);

        kryptos_del_mp_value(r);
        kryptos_del_mp_value(q);
        kryptos_del_mp_value(er);
        kryptos_del_mp_value(eq);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(x);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_div_2p_tests)
    struct div_2p_tests_ctx {
        char *x;
        int p;
        char *q, *r;
    };
    struct div_2p_tests_ctx test_vector[] = {
        { "1667", 1,  "B33", "1" },
        { "DECEB", 5, "6F67", "B" },
        { "22CD01A3F7EFEC21C982BE4ECB3450"
          "21E9BC8A9C64F0679E83E993CB05C8"
          "F3EB5F4FD03EE631BAF5F596DDC263"
          "8A5DA62CAB41FB364BBC84D3E44624"
          "CA07576BB4900A9041DABC95BFC20C"
          "7167D7AD07E40A2FF3D23149C3569F"
          "D1B307AC86C008C625D29745B2A5F2"
          "0F20742CA317C52DD31AA3BABC6689"
          "996BC624BA3763BD56B850A5F776C5"
          "7B84B1FB8B53A0B67835FCD42ED3E7"
          "246CF5B70740573FB9B1F646FECB5A"
          "39DC038CB000BC8D9501ECB0FAD166"
          "9341D28A4633F9DF0E67594985508B"
          "590694B03801B2E02597FE59046125"
          "2026716864A62F413B51DD9A8E0",  1, "116680D1FBF7F610E4C15F27659A2810"
                                             "F4DE454E327833CF41F4C9E582E479F5"
                                             "AFA7E81F7318DD7AFACB6EE131C52ED3"
                                             "1655A0FD9B25DE4269F223126503ABB5"
                                             "DA48054820ED5E4ADFE10638B3EBD683"
                                             "F20517F9E918A4E1AB4FE8D983D64360"
                                             "046312E94BA2D952F907903A16518BE2"
                                             "96E98D51DD5E3344CCB5E3125D1BB1DE"
                                             "AB5C2852FBBB62BDC258FDC5A9D05B3C"
                                             "1AFE6A1769F392367ADB83A02B9FDCD8"
                                             "FB237F65AD1CEE01C658005E46CA80F6"
                                             "587D68B349A0E9452319FCEF8733ACA4"
                                             "C2A845AC834A581C00D97012CBFF2C82"
                                             "3092901338B4325317A09DA8EECD470", "0" },
        { "14BE2E7ED21BB6C06182985BA9F985D5"
          "3EB7DBA458E014DB09033C91EE4A3777"
          "2676EC1145A7DB3E736A74DCC9E1AC72"
          "B8B6F1DB726C637531E61B5914952138"
          "D8072CF3DCE89710C7E472F7A6539B07"
          "E8899C75F5A455C5D8C55177144E72EF"
          "3D1ACEF2461F508C0E47C9298ECD13FE"
          "8CA0C86C602124A3FAFCAF81CB285CC8"
          "8E4CEB3DF48080946FE72FFD1B101652"
          "A5B9DB1E8B58D1039BF32067F7212138"
          "55597005881EE5A5F39EB5E862E9B53E"
          "2ABAF7C9023CA7345FF921EAD62F54C5"
          "A4E0B296C7BEA70AD9EF34BF1858DFE1"
          "EEC1276A39EFA7A1D7C18311FB348BB6"
          "0467F", 6, "52F8B9FB486EDB01860A616EA7E61754"
                      "FADF6E916380536C240CF247B928DDDC"
                      "99DBB045169F6CF9CDA9D3732786B1CA"
                      "E2DBC76DC9B18DD4C7986D64525484E3"
                      "601CB3CF73A25C431F91CBDE994E6C1F"
                      "A22671D7D6915717631545DC5139CBBC"
                      "F46B3BC9187D4230391F24A63B344FFA"
                      "328321B18084928FEBF2BE072CA17322"
                      "3933ACF7D2020251BF9CBFF46C40594A"
                      "96E76C7A2D63440E6FCC819FDC8484E1"
                      "5565C016207B9697CE7AD7A18BA6D4F8"
                      "AAEBDF2408F29CD17FE487AB58BD5316"
                      "9382CA5B1EFA9C2B67BCD2FC61637F87"
                      "BB049DA8E7BE9E875F060C47ECD22ED8"
                      "119", "3F" }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *x, *q, *r, *eq, *er;

    KUTE_ASSERT(kryptos_mp_div_2p(NULL, 0, NULL) == NULL);

    for (tv = 0; tv < test_vector_nr; tv++) {
        x = kryptos_hex_value_as_mp(test_vector[tv].x, kstrlen(test_vector[tv].x));
        KUTE_ASSERT(x != NULL);
        eq = kryptos_hex_value_as_mp(test_vector[tv].q, kstrlen(test_vector[tv].q));
        KUTE_ASSERT(eq != NULL);
        er = kryptos_hex_value_as_mp(test_vector[tv].r, kstrlen(test_vector[tv].r));
        KUTE_ASSERT(er != NULL);
        q = kryptos_mp_div_2p(x, test_vector[tv].p, &r);
        KUTE_ASSERT(q != NULL);
        KUTE_ASSERT(r != NULL);
        KUTE_ASSERT(kryptos_mp_eq(q, eq) == 1);
        KUTE_ASSERT(kryptos_mp_eq(r, er) == 1);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(eq);
        kryptos_del_mp_value(er);
        kryptos_del_mp_value(q);
        kryptos_del_mp_value(r);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_pow_tests)
    kryptos_mp_value_t *b, *e, *pe, *p;
    struct pow_tests_ctx {
        char *b, *e, *pe;
    };
    struct pow_tests_ctx test_vector[] = {
        {  "2",  "0",                    "1" },
        {  "2",  "8",                  "100" },
        {  "2",  "2",                    "4" },
        {  "2",  "0",                    "1" },
        {  "2",  "1",                    "2" },
        { "FF",  "3",               "FD02FF" },
        { "FF",  "5",           "FB09F604FF" },
        { "FF", "0A", "F62C88D104D1882CF601" }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    for (tv = 0; tv < test_vector_nr; tv++) {
        b  = kryptos_hex_value_as_mp(test_vector[tv].b, kstrlen(test_vector[tv].b));
        e  = kryptos_hex_value_as_mp(test_vector[tv].e, kstrlen(test_vector[tv].e));
        pe = kryptos_hex_value_as_mp(test_vector[tv].pe, kstrlen(test_vector[tv].pe));

        KUTE_ASSERT(b != NULL && e != NULL && pe != NULL);

        p = kryptos_mp_pow(b, e);

        KUTE_ASSERT(kryptos_mp_eq(p, pe) == 1);

        kryptos_del_mp_value(b);
        kryptos_del_mp_value(e);
        kryptos_del_mp_value(pe);
        kryptos_del_mp_value(p);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_is_odd_tests)
    kryptos_mp_value_t *a;
    struct odd_tests_ctx {
        char *a;
        kryptos_u8_t e;
    };
    struct odd_tests_ctx test_vector[] = {
        { "0", 0 },
        { "1", 1 },
        { "2", 0 },
        { "3", 1 },
        { "4", 0 },
        { "5", 1 },
        { "6", 0 },
        { "7", 1 },
        { "8", 0 },
        { "9", 1 },
        { "A", 0 },
        { "B", 1 },
        { "C", 0 },
        { "D", 1 },
        { "E", 0 },
        { "F", 1 }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    for (tv = 0; tv < tv_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        KUTE_ASSERT(kryptos_mp_is_odd(a) == test_vector[tv].e);
        kryptos_del_mp_value(a);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_is_even_tests)
    kryptos_mp_value_t *a;
    struct odd_tests_ctx {
        char *a;
        int e;
    };
    struct odd_tests_ctx test_vector[] = {
        { "0", 1 },
        { "1", 0 },
        { "2", 1 },
        { "3", 0 },
        { "4", 1 },
        { "5", 0 },
        { "6", 1 },
        { "7", 0 },
        { "8", 1 },
        { "9", 0 },
        { "A", 1 },
        { "B", 0 },
        { "C", 1 },
        { "D", 0 },
        { "E", 1 },
        { "F", 0 }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    for (tv = 0; tv < tv_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        KUTE_ASSERT(kryptos_mp_is_even(a) == test_vector[tv].e);
        kryptos_del_mp_value(a);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_me_mod_n_tests)
    struct mp_me_mod_n_tests_ctx {
        char *m, *e, *n, *exp;
    };
    struct mp_me_mod_n_tests_ctx test_vector[] = {
        {  "5", "2",   "D",   "C" },
        {  "9", "2",   "5",   "1" },
        {  "3", "4",  "15",  "12" },
        {  "4", "8",  "3B",  "2E" },
        {  "5", "3",   "2",   "1" },
        { "28", "2", "190",   "0" },
        { "28", "2", "193", "187" },
        {  "2", "3",  "B",    "8" },
        {  "4", "4",  "B",    "3" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *m, *e, *n, *exp, *me_mod_n;

    for (tv = 0; tv < tv_nr; tv++) {
        m = kryptos_hex_value_as_mp(test_vector[tv].m, kstrlen(test_vector[tv].m));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, kstrlen(test_vector[tv].e));
        n = kryptos_hex_value_as_mp(test_vector[tv].n, kstrlen(test_vector[tv].n));
        exp = kryptos_hex_value_as_mp(test_vector[tv].exp, kstrlen(test_vector[tv].exp));

        KUTE_ASSERT(m != NULL && e != NULL && n != NULL && exp != NULL);

        me_mod_n = kryptos_mp_me_mod_n(m, e, n);

        KUTE_ASSERT(me_mod_n != NULL);

        KUTE_ASSERT(kryptos_mp_eq(me_mod_n, exp) == 1);

        kryptos_del_mp_value(m);
        kryptos_del_mp_value(e);
        kryptos_del_mp_value(n);
        kryptos_del_mp_value(exp);
        kryptos_del_mp_value(me_mod_n);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_fermat_test_tests)
    struct fermat_test_ctx {
        char *n;
        int is_prime;
    };
    struct fermat_test_ctx test_vector[] = {
        { "3", 1 }, { "4", 0 }, { "5", 1 }, { "6", 0 }, { "7", 1 }, { "8", 0 }, { "9", 0 },
        { "A", 0 }, { "B", 1 }, { "C", 0 }, { "D", 1 }, { "E", 0 }, { "F", 0 }
    };
    size_t test_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_mp_value_t *n;

    for (t = 0; t < test_nr; t++) {
        n = kryptos_hex_value_as_mp(test_vector[t].n, kstrlen(test_vector[t].n));
        KUTE_ASSERT(n != NULL);
        KUTE_ASSERT(kryptos_mp_fermat_test(n, 10) == test_vector[t].is_prime);
        kryptos_del_mp_value(n);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_lsh_tests)
    struct lsh_tests_ctx {
        char *a;
        int l;
        char *e;
    };
    struct lsh_tests_ctx test_vector[] = {
        {       "50",  7,          "2800" },
        {        "2",  1,             "4" },
        {       "10",  4,           "100" },
        {       "10", 16,        "100000" },
        {     "DEAD", 10,       "37AB400" },
        {     "BEEF", 34, "2FBBC00000000" },
        { "DEADBEEF",  8,    "DEADBEEF00" }
    };
    size_t test_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_mp_value_t *a, *e;

    for (t = 0; t < test_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, kstrlen(test_vector[t].a));
        e = kryptos_hex_value_as_mp(test_vector[t].e, kstrlen(test_vector[t].e));

        KUTE_ASSERT(a != NULL && e != NULL);

        a = kryptos_mp_lsh(&a, test_vector[t].l);

        KUTE_ASSERT(a != NULL);

        KUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(e);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_rsh_tests)
    struct rsh_tests_ctx {
        char *a;
        int l;
        char *e;
    };
    struct rsh_tests_ctx test_vector[] = {
        {        "2",  1,             "1" },
        {       "10",  4,             "1" },
        {       "10", 16,             "0" },
        {     "DEAD", 10,            "37" },
        {     "BEEF", 34,             "0" },
        {     "BEEF",  4,           "BEE" },
        {     "BEEF",  8,            "BE" },
        {     "BEEF", 12,             "B" },
        {     "BEEF", 15,             "1" },
        {     "BEEF", 16,             "0" },
        { "DEADBEEF",  8,        "DEADBE" }
    };
    size_t test_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_mp_value_t *a, *e;

    for (t = 0; t < test_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, kstrlen(test_vector[t].a));
        e = kryptos_hex_value_as_mp(test_vector[t].e, kstrlen(test_vector[t].e));

        KUTE_ASSERT(a != NULL && e != NULL);

        a = kryptos_mp_rsh(&a, test_vector[t].l);

        KUTE_ASSERT(a != NULL);

        KUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(e);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_miller_rabin_test_tests)
    struct miller_rabin_test_ctx {
        char *n;
        int is_prime;
    };
    struct miller_rabin_test_ctx test_vector[] = {
        {  "3", 1 }, {  "4", 0 }, {  "5", 1 }, {  "6", 0 }, {  "7", 1 }, {  "8", 0 }, {  "9", 0 },
        {  "A", 0 }, {  "B", 1 }, {  "C", 0 }, {  "D", 1 }, {  "E", 0 }, {  "F", 0 }, { "35", 1 }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *n = NULL;

    for (tv = 0; tv < tv_nr; tv++) {
        n = kryptos_hex_value_as_mp(test_vector[tv].n, kstrlen(test_vector[tv].n));
        KUTE_ASSERT(n != NULL);
        KUTE_ASSERT(kryptos_mp_miller_rabin_test(n, 10) == test_vector[tv].is_prime);
        kryptos_del_mp_value(n);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_is_prime_tests)
    struct is_prime_test_ctx {
        char *n;
        int is_prime;
    };
    struct is_prime_test_ctx test_vector[] = {
        {  "3", 1 }, {  "4", 0 }, {  "5", 1 }, {  "6", 0 }, {  "7", 1 }, {  "8", 0 }, {  "9", 0 },
        {  "A", 0 }, {  "B", 1 }, {  "C", 0 }, {  "D", 1 }, {  "E", 0 }, {  "F", 0 }, { "35", 1 }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *n = NULL;

    for (tv = 0; tv < tv_nr; tv++) {
        n = kryptos_hex_value_as_mp(test_vector[tv].n, kstrlen(test_vector[tv].n));
        KUTE_ASSERT(n != NULL);
        KUTE_ASSERT(kryptos_mp_is_prime(n) == test_vector[tv].is_prime);
        kryptos_del_mp_value(n);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_gen_prime_tests)
    kryptos_mp_value_t *p = kryptos_mp_gen_prime(16);
    size_t expected_bitsize;
    KUTE_ASSERT(p != NULL);
    // WARN(Rafael): Important check the bitsize by using the bit2byte macro because it depends on the current radix base.
    expected_bitsize = kryptos_mp_bit2byte(16);
    if (expected_bitsize == 0) {
        expected_bitsize = 1;
    }
    KUTE_ASSERT(p->data_size == expected_bitsize);
#if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf(" *** Your luck number is: "); kryptos_print_mp(p);
    uprintf(" *** Search for it in everywhere...\n");
#elif defined(__linux__)
//    printk(KERN_ERR " *** Your luck number is: "); kryptos_print_mp(p);
//    printk(KERN_ERR " *** Search for it in everywhere...\n");
#endif
    kryptos_del_mp_value(p);
    // INFO(Rafael): Well, all we need to do is to believe in this function... To test the return to make sure if the
    //               value is really prime means to use the same tests (Fermat, Miller-Rabin) used by the generating function.
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_gcd_tests)
    struct gcd_tests_ctx {
        char *x, *y, *gcd;
    };
    struct gcd_tests_ctx test_vector[] = {
        {                              "6E4",                             "364",   "1C" },
        {                                "D",                               "D",    "D" },
        {                               "25",                             "258",    "1" },
        {                               "14",                              "64",   "14" },
        {                            "98601",                          "1F74CD", "49E1" },
        { "29EC3865B1400AC43088F02295967869"
          "D9366A9C1CCD15349E1FD4FE419F9433"
          "36ED7A6BD33FCFC9831D3809FDFE6631"
          "D8C4984BFA7A86D367D5D54EB7D9DAC4"
          "94AE7576332F8863BF6C657A3BF6C657"
          "A3BF6C657A3BF6C657A3BF",          "999E0D9FCCD8F2508E2B1EEACF8462A8"
                                             "47F8F57A7B4FEBB480442C646D08E4C5"
                                             "E28D20DE9D804032DB83D29A5EA0A6E8"
                                             "47AAEEB7208AC801120D9034E9C6E7D8"
                                             "E43B497E067005EB2FA17B8BA3FB27FE"
                                             "9EB96EC25D101DD64AE7A363328",         "3" },
        { "00000038000000B7", "8640EF6BCEBAECE8", "B" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *x, *y, *g, *eg;
    for (tv = 0; tv < tv_nr; tv++) {
        x = kryptos_hex_value_as_mp(test_vector[tv].x, kstrlen(test_vector[tv].x));
        KUTE_ASSERT(x != NULL);
        y = kryptos_hex_value_as_mp(test_vector[tv].y, kstrlen(test_vector[tv].y));
        KUTE_ASSERT(y != NULL);
        eg = kryptos_hex_value_as_mp(test_vector[tv].gcd, kstrlen(test_vector[tv].gcd));
        KUTE_ASSERT(eg != NULL);
        g = kryptos_mp_gcd(x, y);
        KUTE_ASSERT(g != NULL);
        KUTE_ASSERT(kryptos_mp_eq(g, eg) == 1);
        kryptos_del_mp_value(g);
        g = kryptos_mp_gcd(y, x);
        KUTE_ASSERT(g != NULL);
        KUTE_ASSERT(kryptos_mp_eq(g, eg) == 1);
        kryptos_del_mp_value(g);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(eg);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_modinv_tests)
    struct egcd_tests_ctx {
        char *a, *m, *v;
    };
    struct egcd_tests_ctx test_vector[] = {
        {     "10F",       "17F",        "6A" },
        {       "3",        "14",         "7" },
        { "1819E5B", "8F5B23580", "6BE56E4D3" },
        {       "3",         "7",         "5" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *m, *ev, *v;

    for (tv = 0; tv < tv_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, kstrlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        m = kryptos_hex_value_as_mp(test_vector[tv].m, kstrlen(test_vector[tv].m));
        KUTE_ASSERT(m != NULL);
        ev = kryptos_hex_value_as_mp(test_vector[tv].v, kstrlen(test_vector[tv].v));
        KUTE_ASSERT(ev != NULL);
        v = kryptos_mp_modinv(a, m);
        KUTE_ASSERT(v != NULL);
        KUTE_ASSERT(kryptos_mp_eq(v, ev) == 1);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(m);
        kryptos_del_mp_value(ev);
        kryptos_del_mp_value(v);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_modinv_rs_tests)
    struct egcd_tests_ctx {
        char *a, *m, *v;
    };
    struct egcd_tests_ctx test_vector[] = {
        {     "10F",       "17F",        "6A" },
        {       "3",         "7",         "5" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *m, *ev, *v;

    for (tv = 0; tv < tv_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        KUTE_ASSERT(a != NULL);
        m = kryptos_hex_value_as_mp(test_vector[tv].m, strlen(test_vector[tv].m));
        KUTE_ASSERT(m != NULL);
        ev = kryptos_hex_value_as_mp(test_vector[tv].v, strlen(test_vector[tv].v));
        KUTE_ASSERT(ev != NULL);
        v = kryptos_mp_modinv_rs(a, m);
        KUTE_ASSERT(v != NULL);
        KUTE_ASSERT(kryptos_mp_eq(v, ev) == 1);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(m);
        kryptos_del_mp_value(ev);
        kryptos_del_mp_value(v);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_montgomery_reduction_tests)
    kryptos_mp_value_t *m;
    kryptos_mp_value_t *x;
    kryptos_mp_value_t *y;
    kryptos_mp_value_t *e;
    struct montgomery_reduction_test_ctx {
        char *x, *y, *e;
    };
    struct montgomery_reduction_test_ctx test_vector[] = {
        {    "37",   "7",   "6" },
        {   "109",   "3",   "1" },
        {   "101",   "D",   "A" },
        { "74EF9", "599", "15B" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    for (tv = 0; tv < tv_nr; tv++) {
        x = kryptos_hex_value_as_mp(test_vector[tv].x, kstrlen(test_vector[tv].x));
        KUTE_ASSERT(x != NULL);
        y = kryptos_hex_value_as_mp(test_vector[tv].y, kstrlen(test_vector[tv].y));
        KUTE_ASSERT(y != NULL);
        e = kryptos_hex_value_as_mp(test_vector[tv].e, kstrlen(test_vector[tv].e));
        KUTE_ASSERT(e != NULL);
        m = kryptos_mp_montgomery_reduction(x, y);
        KUTE_ASSERT(m != NULL);
        KUTE_ASSERT(kryptos_mp_eq(m, e) == 1);
        kryptos_del_mp_value(m);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(e);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_raw_buffer_as_mp_tests)
    kryptos_mp_value_t *mp = NULL;
    kryptos_mp_value_t *emp = NULL;

    KUTE_ASSERT(kryptos_raw_buffer_as_mp(NULL, 0) == NULL);

    KUTE_ASSERT(kryptos_raw_buffer_as_mp((kryptos_u8_t *) 0x1, 0) == NULL);

    emp = kryptos_hex_value_as_mp("00112233445566778899AABBCCDDEEFF", 32);

    KUTE_ASSERT(emp != NULL);

    mp = kryptos_raw_buffer_as_mp((kryptos_u8_t *)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16);

    KUTE_ASSERT(mp != NULL);

    KUTE_ASSERT(kryptos_mp_eq(mp, emp) == 1);

    kryptos_del_mp_value(mp);
    kryptos_del_mp_value(emp);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_as_task_out_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_mp_value_t *mp = NULL;
    kryptos_u8_t *o = NULL;
    ssize_t o_size = 0, d = 0;
    kryptos_u8_t *expected_buffer = (kryptos_u8_t *)"\xDE\xAD\xBE\xEF\xBE\xEF\xDE\xAD";
    size_t expected_buffer_size = 8;

    mp = kryptos_raw_buffer_as_mp(expected_buffer, expected_buffer_size);
    KUTE_ASSERT(mp != NULL);

    kryptos_task_init_as_null(ktask);

    kryptos_mp_as_task_out(&ktask, mp, o, o_size, d, kryptos_mp_as_raw_buffer_tests_epilogue);

    KUTE_ASSERT(ktask->out_size == expected_buffer_size);
    KUTE_ASSERT(ktask->out != NULL);

    KUTE_ASSERT(memcmp(ktask->out, expected_buffer, ktask->out_size) == 0);

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    kryptos_del_mp_value(mp);

    goto kryptos_mp_as_raw_buffer_tests_end;

kryptos_mp_as_raw_buffer_tests_epilogue:
    return 1;
kryptos_mp_as_raw_buffer_tests_end:
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_mod_tests)
    struct test_ctx {
        char *a;
        size_t a_size;
        char *b;
        size_t b_size;
        char *e;
        size_t e_size;
    };
    struct test_ctx test_vector[] = {
        {       "-E", 2,  "11", 2,  "03", 2 },
        {       "0E", 2,  "11", 2,  "0E", 2 },
        {     "9C40", 4,  "11", 2,  "10", 2 },
        {      "-12", 3,  "11", 2,  "10", 2 },
        {      "-1B", 3,  "0D", 2,  "0C", 2 },
        {      "-12", 3, "3E8", 3, "3D6", 3 },
        {       "-2", 2,  "02", 2,  "00", 2 },
        {       "12", 2,  "11", 2,  "01", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_mp_value_t *a_value, *b_value, *e_value;

    for (t = 0; t < tv_nr; t++) {
        a_value = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        KUTE_ASSERT(a_value != NULL);
        b_value = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        KUTE_ASSERT(b_value != NULL);
        e_value = kryptos_hex_value_as_mp(test_vector[t].e, test_vector[t].e_size);
        KUTE_ASSERT(e_value != NULL);
        KUTE_ASSERT(kryptos_mp_mod(&a_value, b_value) == 1);
        KUTE_ASSERT(a_value != NULL);
        KUTE_ASSERT(kryptos_mp_eq(a_value, e_value) == 1);
        kryptos_del_mp_value(a_value);
        kryptos_del_mp_value(b_value);
        kryptos_del_mp_value(e_value);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_barrett_reduction_tests)
    struct test_ctx {
        char *x;
        size_t x_size;
        char *m;
        size_t m_size;
        char *e;
        size_t e_size;
    };
    struct test_ctx test_vector[] = {
        {       "0E", 2,  "11", 2,  "0E", 2 },
        {       "-E", 2,  "11", 2,  "03", 2 },
        // INFO(Rafael): Barrett's reduction only works for x >= 0 && x <= mod^2.
        //               Anyway, for convenience issues, the function will use standard long division
        //               when a negative x or x >= mod^2 is passed.
        {     "9C40", 4,  "11", 2,  "10", 2 },
        {       "12", 2,  "11", 2,  "01", 2 },
        {       "FA", 2,  "11", 2,  "0C", 2 },
        {      "-12", 3,  "11", 2,  "10", 2 },
        {      "-1B", 3,  "0D", 2,  "0C", 2 },
        {      "-12", 3, "3E8", 3, "3D6", 3 },
        {       "-2", 2,  "02", 2,  "00", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_mp_value_t *x, *factor = NULL, *mod = NULL, *e, *r;
    size_t sh;

    KUTE_ASSERT(kryptos_mp_barrett_reduction(NULL, &factor, &sh, mod) == NULL);

    x = kryptos_hex_value_as_mp("9C40", 4);
    KUTE_ASSERT(x != NULL);

    KUTE_ASSERT(kryptos_mp_barrett_reduction(x, NULL, &sh, mod) == NULL);
    KUTE_ASSERT(kryptos_mp_barrett_reduction(x, &factor, NULL, mod) == NULL);
    KUTE_ASSERT(kryptos_mp_barrett_reduction(x, &factor, &sh, NULL) == NULL);

    mod = kryptos_hex_value_as_mp("11", 2);
    KUTE_ASSERT(mod != NULL);

    r = kryptos_mp_barrett_reduction(x, &factor, &sh, mod);
    KUTE_ASSERT(r != NULL);

    kryptos_del_mp_value(x);
    kryptos_del_mp_value(r);
    kryptos_del_mp_value(factor);
    factor = NULL;
    kryptos_del_mp_value(mod);

    for (t = 0; t < tv_nr; t++) {
        x = kryptos_hex_value_as_mp(test_vector[t].x, test_vector[t].x_size);
        KUTE_ASSERT(x != NULL);
        mod = kryptos_hex_value_as_mp(test_vector[t].m, test_vector[t].m_size);
        KUTE_ASSERT(mod != NULL);
        e = kryptos_hex_value_as_mp(test_vector[t].e, test_vector[t].e_size);
        KUTE_ASSERT(e != NULL);
        r = kryptos_mp_barrett_reduction(x, &factor, &sh, mod);
        KUTE_ASSERT(factor != NULL);
        KUTE_ASSERT(r != NULL);
        KUTE_ASSERT(kryptos_mp_eq(r, e) == 1);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(mod);
        kryptos_del_mp_value(e);
        kryptos_del_mp_value(factor);
        factor = NULL;
        kryptos_del_mp_value(r);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_add_s_tests)
    struct test_ctx {
        char *a;
        size_t a_size;
        char *b;
        size_t b_size;
        char *e;
        size_t e_size;
    };
    struct test_ctx test_vector[] = {
        {      "-0E", 3,       "11", 2,       "03", 2 },
        {       "0E", 2,       "11", 2,       "1F", 2 },
        {     "9C40", 4,       "11", 2,     "9C51", 4 },
        {      "-0E", 3,      "-11", 3,      "-1F", 3 },
        {      "-11", 3,       "0E", 2,      "-03", 3 },
        {      "-11", 3,      "-0E", 3,      "-1F", 3 },
        {       "0E", 2,      "-11", 3,      "-03", 3 },
        {      "-11", 3,       "11", 2,       "00", 2 },
        {       "00", 2,       "00", 2,       "00", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_mp_value_t *a_value, *b_value, *e_value;

    for (t = 0; t < tv_nr; t++) {
        a_value = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        KUTE_ASSERT(a_value != NULL);
        b_value = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        KUTE_ASSERT(b_value != NULL);
        e_value = kryptos_hex_value_as_mp(test_vector[t].e, test_vector[t].e_size);
        KUTE_ASSERT(e_value != NULL);
        //printf("A = "); kryptos_print_mp(a_value); printf("\n");
        KUTE_ASSERT(kryptos_mp_add_s(&a_value, b_value) != NULL);
        //printf("B = "); kryptos_print_mp(b_value); printf("\n");
        //printf("R = "); kryptos_print_mp(a_value); printf("\n");
        //printf("E = "); kryptos_print_mp(e_value); printf("\n");
        KUTE_ASSERT(a_value != NULL);
        KUTE_ASSERT(kryptos_mp_eq(a_value, e_value) == 1);
        kryptos_del_mp_value(a_value);
        kryptos_del_mp_value(b_value);
        kryptos_del_mp_value(e_value);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_sub_s_tests)
    struct test_ctx {
        char *a;
        size_t a_size;
        char *b;
        size_t b_size;
        char *e;
        size_t e_size;
    };
    struct test_ctx test_vector[] = {
        {      "-0E", 3,       "11", 2,      "-1F", 3 },
        {       "0E", 2,       "11", 2,      "-03", 3 },
        {     "9C40", 4,       "11", 2,     "9C2F", 4 },
        {      "-0E", 3,      "-11", 3,       "03", 2 },
        {      "-11", 3,       "0E", 2,      "-1F", 3 },
        {      "-11", 3,      "-0E", 3,      "-03", 3 },
        {       "0E", 2,      "-11", 3,       "1F", 2 },
        {      "-11", 3,       "11", 2,      "-22", 3 },
        {      "-11", 3,      "-11", 3,       "00", 2 },
        {      "-11", 3,       "00", 2,      "-11", 3 },
        {       "00", 2,      "-11", 3,       "11", 2 },
        {       "00", 2,       "11", 2,      "-11", 3 },
        {       "00", 2,       "00", 2,       "00", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_mp_value_t *a_value, *b_value, *e_value;

    for (t = 0; t < tv_nr; t++) {
        a_value = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        KUTE_ASSERT(a_value != NULL);
        b_value = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        KUTE_ASSERT(b_value != NULL);
        e_value = kryptos_hex_value_as_mp(test_vector[t].e, test_vector[t].e_size);
        KUTE_ASSERT(e_value != NULL);
        //printf("A = "); kryptos_print_mp(a_value); printf("\n");
        KUTE_ASSERT(kryptos_mp_sub_s(&a_value, b_value) != NULL);
        //printf("B = "); kryptos_print_mp(b_value); printf("\n");
        //printf("R = "); kryptos_print_mp(a_value); printf("\n");
        //printf("E = "); kryptos_print_mp(e_value); printf("\n");
        KUTE_ASSERT(a_value != NULL);
        KUTE_ASSERT(kryptos_mp_eq(a_value, e_value) == 1);
        kryptos_del_mp_value(a_value);
        kryptos_del_mp_value(b_value);
        kryptos_del_mp_value(e_value);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_mul_s_tests)
    struct test_ctx {
        char *a;
        size_t a_size;
        char *b;
        size_t b_size;
        char *e;
        size_t e_size;
    };
    struct test_ctx test_vector[] = {
        {       "-E", 2,       "11", 2,      "-EE", 3 },
        {       "0E", 2,       "11", 2,       "EE", 2 },
        {     "9C40", 4,       "11", 2,    "A6040", 5 },
        {      "-0E", 3,      "-11", 3,       "EE", 2 },
        {      "-11", 3,       "0E", 2,      "-EE", 3 },
        {      "-11", 3,      "-0E", 3,       "EE", 2 },
        {       "0E", 2,      "-11", 3,      "-EE", 3 },
        {      "-11", 3,       "11", 2,     "-121", 4 },
        {      "-11", 3,      "-11", 3,      "121", 3 },
        {      "-11", 3,       "00", 2,       "00", 2 },
        {       "00", 2,      "-11", 3,       "00", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_mp_value_t *a_value, *b_value, *e_value;

    for (t = 0; t < tv_nr; t++) {
        a_value = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        KUTE_ASSERT(a_value != NULL);
        b_value = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        KUTE_ASSERT(b_value != NULL);
        e_value = kryptos_hex_value_as_mp(test_vector[t].e, test_vector[t].e_size);
        KUTE_ASSERT(e_value != NULL);
        //printf("A = "); kryptos_print_mp(a_value); printf("\n");
        KUTE_ASSERT(kryptos_mp_mul_s(&a_value, b_value) != NULL);
        //printf("B = "); kryptos_print_mp(b_value); printf("\n");
        //printf("R = "); kryptos_print_mp(a_value); printf("\n");
        //printf("E = "); kryptos_print_mp(e_value); printf("\n");
        KUTE_ASSERT(a_value != NULL);
        KUTE_ASSERT(kryptos_mp_eq(a_value, e_value) == 1);
        kryptos_del_mp_value(a_value);
        kryptos_del_mp_value(b_value);
        kryptos_del_mp_value(e_value);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_get_bitmap_tests)
    struct test_ctx {
        char *value;
        kryptos_u8_t *expected;
        size_t expected_size;
    };
    struct test_ctx test_vector[] = {
#if !defined(KRYPTOS_MP_EXTENDED_RADIX)
        { "DEADBEEF",         (kryptos_u8_t *)"\x1\x1\x0\x1\x1\x1\x1\x0\x1\x0\x1\x0\x1\x1\x0\x1"
                              "\x1\x0\x1\x1\x1\x1\x1\x0\x1\x1\x1\x0\x1\x1\x1\x1", 32 },
        { "DEADBEEFDEADBEEF", (kryptos_u8_t *)"\x1\x1\x0\x1\x1\x1\x1\x0\x1\x0\x1\x0\x1\x1\x0\x1"
                              "\x1\x0\x1\x1\x1\x1\x1\x0\x1\x1\x1\x0\x1\x1\x1\x1"
                              "\x1\x1\x0\x1\x1\x1\x1\x0\x1\x0\x1\x0\x1\x1\x0\x1"
                              "\x1\x0\x1\x1\x1\x1\x1\x0\x1\x1\x1\x0\x1\x1\x1\x1", 64 }
#elif defined(KRYPTOS_MP_EXTENDED_RADIX)
        { "DEADBEEF",         (kryptos_u8_t *)"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0"
                              "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0"
                              "\x1\x1\x0\x1\x1\x1\x1\x0\x1\x0\x1\x0\x1\x1\x0\x1"
                              "\x1\x0\x1\x1\x1\x1\x1\x0\x1\x1\x1\x0\x1\x1\x1\x1", 64 },
        { "DEADBEEFDEADBEEF", (kryptos_u8_t *)"\x1\x1\x0\x1\x1\x1\x1\x0\x1\x0\x1\x0\x1\x1\x0\x1"
                              "\x1\x0\x1\x1\x1\x1\x1\x0\x1\x1\x1\x0\x1\x1\x1\x1"
                              "\x1\x1\x0\x1\x1\x1\x1\x0\x1\x0\x1\x0\x1\x1\x0\x1"
                              "\x1\x0\x1\x1\x1\x1\x1\x0\x1\x1\x1\x0\x1\x1\x1\x1", 64 }
#else
# error Some code wanted.
#endif
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *value = NULL;
    kryptos_u8_t *bitmap = NULL;
    size_t bitmap_size;
    for (tv = 0; tv < tv_nr; tv++) {
        value = kryptos_hex_value_as_mp(test_vector[tv].value, kstrlen(test_vector[tv].value));
        KUTE_ASSERT(value != NULL);
        bitmap = kryptos_mp_get_bitmap(value, &bitmap_size);
        KUTE_ASSERT(bitmap_size == test_vector[tv].expected_size);
        KUTE_ASSERT(memcmp(bitmap, test_vector[tv].expected, bitmap_size) == 0);
        kryptos_freeseg(bitmap, bitmap_size);
        kryptos_del_mp_value(value);
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mp_inv_tests)
    struct inv_signal_tests_ctx {
        char *n, *en;
    };

    // INFO(Rafael): This is equivalent to the "signed char" range (-128 to 128).
    //               We could continue testing beyond the infinity but I am in a rush.
#ifndef KRYPTOS_MP_U32_DIGIT
    struct inv_signal_tests_ctx test_vector[] = {
        { "FF", "-FF" }, { "FE", "-FE" }, { "FD", "-FD" }, { "FC", "-FC" }, { "FB", "-FB" }, { "FA", "-FA" }, { "F9", "-F9" },
        { "F8", "-F8" }, { "F7", "-F7" }, { "F6", "-F6" }, { "F5", "-F5" }, { "F4", "-F4" }, { "F3", "-F3" }, { "F2", "-F2" },
        { "F1", "-F1" }, { "F0", "-F0" }, { "EF", "-EF" }, { "EE", "-EE" }, { "ED", "-ED" }, { "EC", "-EC" }, { "EB", "-EB" },
        { "EA", "-EA" }, { "E9", "-E9" }, { "E8", "-E8" }, { "E7", "-E7" }, { "E6", "-E6" }, { "E5", "-E5" }, { "E4", "-E4" },
        { "E3", "-E3" }, { "E2", "-E2" }, { "E1", "-E1" }, { "E0", "-E0" }, { "DF", "-DF" }, { "DE", "-DE" }, { "DD", "-DD" },
        { "DC", "-DC" }, { "DB", "-DB" }, { "DA", "-DA" }, { "D9", "-D9" }, { "D8", "-D8" }, { "D7", "-D7" }, { "D6", "-D6" },
        { "D5", "-D5" }, { "D4", "-D4" }, { "D3", "-D3" }, { "D2", "-D2" }, { "D1", "-D1" }, { "D0", "-D0" }, { "CF", "-CF" },
        { "CE", "-CE" }, { "CD", "-CD" }, { "CC", "-CC" }, { "CB", "-CB" }, { "CA", "-CA" }, { "C9", "-C9" }, { "C8", "-C8" },
        { "C7", "-C7" }, { "C6", "-C6" }, { "C5", "-C5" }, { "C4", "-C4" }, { "C3", "-C3" }, { "C2", "-C2" }, { "C1", "-C1" },
        { "C0", "-C0" }, { "BF", "-BF" }, { "BE", "-BE" }, { "BD", "-BD" }, { "BC", "-BC" }, { "BB", "-BB" }, { "BA", "-BA" },
        { "B9", "-B9" }, { "B8", "-B8" }, { "B7", "-B7" }, { "B6", "-B6" }, { "B5", "-B5" }, { "B4", "-B4" }, { "B3", "-B3" },
        { "B2", "-B2" }, { "B1", "-B1" }, { "B0", "-B0" }, { "AF", "-AF" }, { "AE", "-AE" }, { "AD", "-AD" }, { "AC", "-AC" },
        { "AB", "-AB" }, { "AA", "-AA" }, { "A9", "-A9" }, { "A8", "-A8" }, { "A7", "-A7" }, { "A6", "-A6" }, { "A5", "-A5" },
        { "A4", "-A4" }, { "A3", "-A3" }, { "A2", "-A2" }, { "A1", "-A1" }, { "A0", "-A0" }, { "9F", "-9F" }, { "9E", "-9E" },
        { "9D", "-9D" }, { "9C", "-9C" }, { "9B", "-9B" }, { "9A", "-9A" }, { "99", "-99" }, { "98", "-98" }, { "97", "-97" },
        { "96", "-96" }, { "95", "-95" }, { "94", "-94" }, { "93", "-93" }, { "92", "-92" }, { "91", "-91" }, { "90", "-90" },
        { "8F", "-8F" }, { "8E", "-8E" }, { "8D", "-8D" }, { "8C", "-8C" }, { "8B", "-8B" }, { "8A", "-8A" }, { "89", "-89" },
        { "88", "-88" }, { "87", "-87" }, { "86", "-86" }, { "85", "-85" }, { "84", "-84" }, { "83", "-83" }, { "82", "-82" },
        { "81", "-81" }, { "80", "-80" }
    };
#else
    struct inv_signal_tests_ctx test_vector[] = {
        { "FF", "-FF" }, { "FE", "-FE" }, { "FD", "-FD" }, { "FC", "-FC" }, { "FB", "-FB" }, { "FA", "-FA" }, { "F9", "-F9" },
        { "F8", "-F8" }, { "F7", "-F7" }, { "F6", "-F6" }, { "F5", "-F5" }, { "F4", "-F4" }, { "F3", "-F3" }, { "F2", "-F2" },
        { "F1", "-F1" }, { "F0", "-F0" }, { "EF", "-EF" }, { "EE", "-EE" }, { "ED", "-ED" }, { "EC", "-EC" }, { "EB", "-EB" },
        { "EA", "-EA" }, { "E9", "-E9" }, { "E8", "-E8" }, { "E7", "-E7" }, { "E6", "-E6" }, { "E5", "-E5" }, { "E4", "-E4" },
        { "E3", "-E3" }, { "E2", "-E2" }, { "E1", "-E1" }, { "E0", "-E0" }, { "DF", "-DF" }, { "DE", "-DE" }, { "DD", "-DD" },
        { "DC", "-DC" }, { "DB", "-DB" }, { "DA", "-DA" }, { "D9", "-D9" }, { "D8", "-D8" }, { "D7", "-D7" }, { "D6", "-D6" },
        { "D5", "-D5" }, { "D4", "-D4" }, { "D3", "-D3" }, { "D2", "-D2" }, { "D1", "-D1" }, { "D0", "-D0" }, { "CF", "-CF" },
        { "CE", "-CE" }, { "CD", "-CD" }, { "CC", "-CC" }, { "CB", "-CB" }, { "CA", "-CA" }, { "C9", "-C9" }, { "C8", "-C8" },
        { "C7", "-C7" }, { "C6", "-C6" }, { "C5", "-C5" }, { "C4", "-C4" }, { "C3", "-C3" }, { "C2", "-C2" }, { "C1", "-C1" },
        { "C0", "-C0" }, { "BF", "-BF" }, { "BE", "-BE" }, { "BD", "-BD" }, { "BC", "-BC" }, { "BB", "-BB" }, { "BA", "-BA" },
        { "B9", "-B9" }, { "B8", "-B8" }, { "B7", "-B7" }, { "B6", "-B6" }, { "B5", "-B5" }, { "B4", "-B4" }, { "B3", "-B3" },
        { "B2", "-B2" }, { "B1", "-B1" }, { "B0", "-B0" }, { "AF", "-AF" }, { "AE", "-AE" }, { "AD", "-AD" }, { "AC", "-AC" },
        { "AB", "-AB" }, { "AA", "-AA" }, { "A9", "-A9" }, { "A8", "-A8" }, { "A7", "-A7" }, { "A6", "-A6" }, { "A5", "-A5" },
        { "A4", "-A4" }, { "A3", "-A3" }, { "A2", "-A2" }, { "A1", "-A1" }, { "A0", "-A0" }, { "9F", "-9F" }, { "9E", "-9E" },
        { "9D", "-9D" }, { "9C", "-9C" }, { "9B", "-9B" }, { "9A", "-9A" }, { "99", "-99" }, { "98", "-98" }, { "97", "-97" },
        { "96", "-96" }, { "95", "-95" }, { "94", "-94" }, { "93", "-93" }, { "92", "-92" }, { "91", "-91" }, { "90", "-90" },
        { "8F", "-8F" }, { "8E", "-8E" }, { "8D", "-8D" }, { "8C", "-8C" }, { "8B", "-8B" }, { "8A", "-8A" }, { "89", "-89" },
        { "88", "-88" }, { "87", "-87" }, { "86", "-86" }, { "85", "-85" }, { "84", "-84" }, { "83", "-83" }, { "82", "-82" },
        { "81", "-81" }, { "80", "-80" }
    };
#endif
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *n, *en;
    for (tv = 0; tv < tv_nr; tv++) {
        n = kryptos_hex_value_as_mp(test_vector[tv].n, strlen(test_vector[tv].n));
        KUTE_ASSERT(n != NULL);
        en = kryptos_hex_value_as_mp(test_vector[tv].en, strlen(test_vector[tv].en));
        KUTE_ASSERT(en != NULL);
        kryptos_mp_inv(&n);
        KUTE_ASSERT(kryptos_mp_eq(n, en) == 1);
        kryptos_del_mp_value(n);
        kryptos_del_mp_value(en);
    }
KUTE_TEST_CASE_END
