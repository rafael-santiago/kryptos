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
#include <kstring.h>

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
    KUTE_ASSERT(mp->data[0] == 0x66778899);
    KUTE_ASSERT(mp->data[1] == 0x22334455);
    KUTE_ASSERT(mp->data[2] == 0xBBAA0011);
    KUTE_ASSERT(mp->data[3] == 0xFFEEDDCC);
#endif
    kryptos_del_mp_value(mp);
KUTE_TEST_CASE_END
