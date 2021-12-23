/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "poly1305_mp_tests.h"
#include <kryptos_poly1305_mp.h>
#include <kryptos.h>

CUTE_TEST_CASE(kryptos_poly1305_le_bytes_to_num_tests)
    struct test_ctx {
        kryptos_u8_t *bytes;
        size_t bytes_total;
        kryptos_poly1305_number_t expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
          (kryptos_u8_t *)"\x00\x11\x22\x33\x44\x55\x66\x77"
                          "\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16,
          { 0x0011223344556677,
            0x8899AABBCCDDEEFF,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
        {
          (kryptos_u8_t *)"\x01\x12\x23\x34\x45\x56\x67\x78"
                          "\x89\x9A\xAB\xBC\xCD\xDE\xEF\xF0", 16,
          { 0x0112233445566778,
            0x899AABBCCDDEEFF0,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
        {
          (kryptos_u8_t *)"\x0F\x1F\x2F\x3F\x4F\x5F\x6F\x7F"
                          "\x8F\x9F\xAF\xBF\xCF\xDF\xEF\xFF", 16,
          { 0x0F1F2F3F4F5F6F7F,
            0x8F9FAFBFCFDFEFFF,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
        {
          (kryptos_u8_t *)"\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8"
                          "\xF9\xFA\xFB\xFC\xFD\xFE\xFF\xF0", 16,
          { 0xF1F2F3F4F5F6F7F8,
            0xF9FAFBFCFDFEFFF0,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
#else
        {
          (kryptos_u8_t *)"\x00\x11\x22\x33\x44\x55\x66\x77"
                          "\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16,
          { 0x00112233,
            0x44556677,
            0x8899AABB,
            0xCCDDEEFF,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
        {
          (kryptos_u8_t *)"\x01\x12\x23\x34\x45\x56\x67\x78"
                          "\x89\x9A\xAB\xBC\xCD\xDE\xEF\xF0", 16,
          { 0x01122334,
            0x45566778,
            0x899AABBC,
            0xCDDEEFF0,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
        {
          (kryptos_u8_t *)"\x0F\x1F\x2F\x3F\x4F\x5F\x6F\x7F"
                          "\x8F\x9F\xAF\xBF\xCF\xDF\xEF\xFF", 16,
          { 0x0F1F2F3F,
            0x4F5F6F7F,
            0x8F9FAFBF,
            0xCFDFEFFF,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
        {
          (kryptos_u8_t *)"\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8"
                          "\xF9\xFA\xFB\xFC\xFD\xFE\xFF\xF0", 16,
          { 0xF1F2F3F4,
            0xF5F6F7F8,
            0xF9FAFBFC,
            0xFDFEFFF0,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_poly1305_number_t v;

    while (test != test_end) {
        kryptos_poly1305_le_bytes_to_num(v, test->bytes, test->bytes_total);
        CUTE_ASSERT(memcmp(v, test->expected, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_le_num_tests)
    struct test_ctx {
        kryptos_u8_t *bytes;
        size_t bytes_total;
        kryptos_poly1305_number_t expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
          (kryptos_u8_t *)"\x00\x11\x22\x33\x44\x55\x66\x77"
                          "\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16,
          { 0x7766554433221100,
            0xFFEEDDCCBBAA9988,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
        {
          (kryptos_u8_t *)"\x01\x12\x23\x34\x45\x56\x67\x78"
                          "\x89\x9A\xAB\xBC\xCD\xDE\xEF\xF0", 16,
          { 0x7867564534231201,
            0xF0EFDECDBCAB9A89,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
        {
          (kryptos_u8_t *)"\x0F\x1F\x2F\x3F\x4F\x5F\x6F\x7F"
                          "\x8F\x9F\xAF\xBF\xCF\xDF\xEF\xFF", 16,
          { 0x7F6F5F4F3F2F1F0F,
            0xFFEFDFCFBFAF9F8F,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
        {
          (kryptos_u8_t *)"\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8"
                          "\xF9\xFA\xFB\xFC\xFD\xFE\xFF\xF0", 16,
          { 0xF8F7F6F5F4F3F2F1,
            0xF0FFFEFDFCFBFAF9,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
#else
        {
          (kryptos_u8_t *)"\x00\x11\x22\x33\x44\x55\x66\x77"
                          "\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16,
          { 0x77665544,
            0x33221100,
            0xFFEEDDCC,
            0xBBAA9988,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
        {
          (kryptos_u8_t *)"\x01\x12\x23\x34\x45\x56\x67\x78"
                          "\x89\x9A\xAB\xBC\xCD\xDE\xEF\xF0", 16,
          { 0x78675645
            0x34231201,
            0xF0EFDECD,
            0xBCAB9A89,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
        {
          (kryptos_u8_t *)"\x0F\x1F\x2F\x3F\x4F\x5F\x6F\x7F"
                          "\x8F\x9F\xAF\xBF\xCF\xDF\xEF\xFF", 16,
          { 0x7F6F5F4F
            0x3F2F1F0F,
            0xFFEFDFCF,
            0xBFAF9F8F,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
        {
          (kryptos_u8_t *)"\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8"
                          "\xF9\xFA\xFB\xFC\xFD\xFE\xFF\xF0", 16,
          { 0xF8F7F6F5
            0xF4F3F2F1,
            0xF0FFFEFD,
            0xFCFBFAF9,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_poly1305_number_t v;

    while (test != test_end) {
        kryptos_poly1305_le_num(v, test->bytes, test->bytes_total);
        CUTE_ASSERT(memcmp(v, test->expected, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_ld_raw_bytes_tests)
    struct test_ctx {
        kryptos_u8_t *bytes;
        size_t bytes_total;
        kryptos_poly1305_number_t expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
          (kryptos_u8_t *)"\xFF\xEE\xDD\xCC\xBB\xAA\x00\x11"
                          "\x22\x33\x44\x55\x66\x77\x88\x99", 16,
          { 0x2233445566778899,
            0xFFEEDDCCBBAA0011,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000 },
        },
#else
        {
          (kryptos_u8_t *)"\xFF\xEE\xDD\xCC\xBB\xAA\x00\x11"
                          "\x22\x33\x44\x55\x66\x77\x88\x99", 16,
          { 0x22334455,
            0x66778899,
            0xFFEEDDCC,
            0xBBAA0011,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000 },
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_poly1305_number_t v;

    while (test != test_end) {
        kryptos_poly1305_ld_raw_bytes(v, test->bytes, test->bytes_total);
        CUTE_ASSERT(memcmp(v, test->expected, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_eq_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y;
        int expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            { 0x2232445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            0
        },
        {
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            1
        },
        {
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0010,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0010,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            1
        },
        {
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            { 0xFFEEDDCCBBAA0011,
              0x2233445566778899,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            0
        },
#else
        {
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            { 0x22324455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            0
        },
        {
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            1
        },
        {
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0010,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0010,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            1
        },
        {
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            { 0xFFEEDDCC,
              0xBBAA0011,
              0x22334455,
              0x66778899,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            0
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        CUTE_ASSERT(kryptos_poly1305_eq(test->x, test->y) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_get_gt_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y;
        kryptos_poly1305_numfrac_t *expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            &test_vector[0].x[0]
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0xF000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            &test_vector[1].y[0]
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            NULL
        },
#else
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            &test_vector[0].x[0]
        },
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0xF0000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            &test_vector[1].y[0]
        },
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            NULL
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    const kryptos_poly1305_numfrac_t *gt;

    while (test != test_end) {
        gt = kryptos_poly1305_get_gt(test->x, test->y);
        CUTE_ASSERT(gt == test->expected);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_ne_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y;
        int expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            { 0x2232445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            1
        },
        {
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            0
        },
        {
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0010,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0010,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            0
        },
        {
            { 0x2233445566778899,
              0xFFEEDDCCBBAA0011,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            { 0xFFEEDDCCBBAA0011,
              0x2233445566778899,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000,
              0x0000000000000000 },
            1
        },
#else
        {
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            { 0x22324455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            1
        },
        {
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            0
        },
        {
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0010,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0010,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            0
        },
        {
            { 0x22334455,
              0x66778899,
              0xFFEEDDCC,
              0xBBAA0011,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            { 0xFFEEDDCC,
              0xBBAA0011,
              0x22334455,
              0x66778899,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000,
              0x00000000 },
            1
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        CUTE_ASSERT(kryptos_poly1305_ne(test->x, test->y) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_gt_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y;
        int expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            1
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0xF000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0
        },
#else
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            1
        },
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0xF0000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            0
        },
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            0
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        CUTE_ASSERT(kryptos_poly1305_gt(test->x, test->y) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_lt_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y;
        int expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0xF000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            1
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0
        },
#else
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            0
        },
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0xF0000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            1
        },
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            0
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        CUTE_ASSERT(kryptos_poly1305_lt(test->x, test->y) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_ge_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y;
        int expected;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            1
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0xF000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            1
        },
#else
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            1
        },
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0xF0000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            0
        },
        {
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0x00000000,
                0x00000001,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            1
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        CUTE_ASSERT(kryptos_poly1305_ge(test->x, test->y) == test->expected);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_not_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x;
        kryptos_poly1305_number_t e;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF
            }
        },
        {
            {
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0
            },
            {
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F
            }
        },
        {
            {
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F,
                0x0F0F0F0F0F0F0F0F
            },
            {
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0,
                0xF0F0F0F0F0F0F0F0
            }
        },
#else
        {
            {
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            {
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF,
                0xFFFFFFFF
            }
        },
        {
            {
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0
            },
            {
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F
            }
        },
        {
            {
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F,
                0x0F0F0F0F
            },
            {
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0,
                0xF0F0F0F0
            }
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        kryptos_poly1305_not(test->x);
        CUTE_ASSERT(memcmp(test->x, test->e, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_lsh_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x;
        size_t level;
        kryptos_poly1305_number_t e;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            8,
            {
                0xADBEEFDEADBEEFAA,
                0xBBCCDDEEFF001100,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            16,
            {
                0xBEEFDEADBEEFAABB,
                0xCCDDEEFF00110000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            4,
            {
                0xEADBEEFDEADBEEFA,
                0xABBCCDDEEFF00110,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000

            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            24,
            {
                0xEFDEADBEEFAABBCC,
                0xDDEEFF0011000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000

            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            32,
            {
                0xDEADBEEFAABBCCDD,
                0xEEFF001100000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            64,
            {
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
#else
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            8,
            {
                0xADBEEFDE,
                0xADBEEFAA,
                0xBBCCDDEE,
                0xFF001100,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            16,
            {
                0xBEEFDEAD,
                0xBEEFAABB,
                0xCCDDEEFF,
                0x00110000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            4,
            {
                0xEADBEEFD,
                0xEADBEEFA,
                0xABBCCDDE,
                0xEFF00110,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            24,
            {
                0xEFDEADBE,
                0xEFAABBCC,
                0xDDEEFF00,
                0x11000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            32,
            {
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            64,
            {
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },

#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        kryptos_poly1305_lsh(test->x, test->level);
        CUTE_ASSERT(memcmp(test->x, test->e, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_rsh_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x;
        size_t level;
        kryptos_poly1305_number_t e;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            8,
            {
                0x00DEADBEEFDEADBE,
                0xEFAABBCCDDEEFF00,
                0x1100000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            16,
            {
                0x0000DEADBEEFDEAD,
                0xBEEFAABBCCDDEEFF,
                0x0011000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            4,
            {
                0x0DEADBEEFDEADBEE,
                0xFAABBCCDDEEFF001,
                0x1000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            24,
            {
                0x000000DEADBEEFDE,
                0xADBEEFAABBCCDDEE,
                0xFF00110000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            32,
            {
                0x00000000DEADBEEF,
                0xDEADBEEFAABBCCDD,
                0xEEFF001100000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            64,
            {
                0x0000000000000000,
                0xDEADBEEFDEADBEEF,
                0xAABBCCDDEEFF0011,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
#else
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            8,
            {
                0x00DEADBE,
                0xEFDEADBE,
                0xEFAABBCC,
                0xDDEEFF00,
                0x11000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            16,
            {
                0x0000DEAD,
                0xBEEFDEAD,
                0xBEEFAABB,
                0xCCDDEEFF,
                0x00110000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            4,
            {
                0x0DEADBEE,
                0xFDEADBEE,
                0xFAABBCCD,
                0xDEEFF001,
                0x10000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            24,
            {
                0x000000DE,
                0xADBEEFDE,
                0xADBEEFAA,
                0xBBCCDDEE,
                0xFF001100,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            32,
            {
                0x00000000,
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
        {
            {
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            },
            64,
            {
                0x00000000,
                0x00000000,
                0xDEADBEEF,
                0xDEADBEEF,
                0xAABBCCDD,
                0xEEFF0011,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000,
                0x00000000
            }
        },
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        kryptos_poly1305_rsh(test->x, test->level);
        CUTE_ASSERT(memcmp(test->x, test->e, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_sub_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y, e;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000006,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000002,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000004,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000002001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000001006,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000FFB,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x000000000000DEAD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000BEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000001FBE,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x000000000000BEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000DEAD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000001FBE,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000002,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x00000000DEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000BEEFDEAD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000001FBDE042,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000005,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000001006,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000001001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000010,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000001006,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000FF6,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0xBABABABABABABABA,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000000000FD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xBABABABABABAB9BD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x02CBB276A0348322,
                0x4083FB324A10B351,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xA412BEF100000000,
                0x4083FB321A15F35F,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x5EB8F385A0348322,
                0x000000002FFABFF1,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x02CBB276A0348322,
                0x4083FB324A10B351,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x02CBB276A0348322,
                0x4083FB324A10B351,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
#else
    // TODO(Rafael): Make test vector based on radix 2^32.
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        kryptos_poly1305_sub(test->x, test->y);
        CUTE_ASSERT(memcmp(test->x, test->e, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_inv_cmplt_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, e;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x000000000000BEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xFFFFFFFFFFFF4111,
                0xFFFFFFFFFFFFFFFF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0xFFFFFFFFFFFF4111,
                0xFFFFFFFFFFFFFFFF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000BEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
#else
    // TODO(Rafael): Make test vector for 2^32 radix.
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        kryptos_poly1305_inv_cmplt(test->x);
        CUTE_ASSERT(memcmp(test->x, test->e, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_add_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y, e;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000001, // TIP(Rafael): Less significant limb
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,     // ((((((( For practical issues we store all mp numbers "upside-down" )))))))
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000  // TIP(Rafael): Most significant limb
            },
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000002,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0x0000000000000002,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000000A,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000000C,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0x000000000000DEAD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000BEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000019D9C,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0x0000000000006671,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000006671,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0x00000000DEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000BEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000DEAE7DDE,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0x00000000DEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000DEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000001BD5B7DDE,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xBD5B7DDFBD5B7DDE,
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xDEADBEEFDEADBEF0,
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000100,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xDEADBEEFDEADBFEF,
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xDEADBEEFDEADBEEF,
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xBD5B7DDFBD5B7DDE,
                0xBD5B7DDFBD5B7DDF,
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
#else
// TODO(Rafael): Fill up test vector when mp radix bit size is kryptos_u32_t.
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        kryptos_poly1305_add(test->x, test->y);
        CUTE_ASSERT(memcmp(test->x, test->e, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_mul_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x, y, e;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000002,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000004,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000008,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000002,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000044,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000088,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000022,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000044,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000908,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000101,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000001001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000101101,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x000000000000DEAD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000BEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000A6144983,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x000000000000BEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000DEAD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000A6144983, //INFO(Rafael): Does reality solid still? Does multiplication commutative still? ;)
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x00000000000000FF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000000000FF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000FE01,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x000000000000FFFF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000FFFF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000FFFE0001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x00000000FFFFFFFF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000FFFFFFFF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xFFFFFFFE00000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x00000000DEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x000000000000DEAD,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000C1B126FD4983,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0xDEADBEEFDEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000DEADBEEF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0xE31F7033216DA321,
                0x00000000C1B1CD12,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000FD02FF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000000000FF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x00000000FC05FC01,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            {
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
#else
    // INFO(Rafael): Make test vector for builds based on 2^32 radix.
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        kryptos_poly1305_mul(test->x, test->y);
        CUTE_ASSERT(memcmp(test->x, test->e, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_mul_digit_tests)
    struct test_ctx {
        kryptos_poly1305_number_t x;
        kryptos_poly1305_numfrac_t digit;
        kryptos_poly1305_number_t e;
    } test_vector[] = {
#if defined(KRYPTOS_MP_EXTENDED_RADIX)
        {
            {
                0x0000000000000022,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0x0000000000000002,
            {
                0x0000000000000044,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x00000000000000FF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0x0000000000000050,
            {
                0x0000000000004FB0,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x000000FFFFFFFFFF,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0x0000000000000099,
            {
                0x000098FFFFFFFF67,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x0000000000000011,
                0x0000000000000022,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            },
            0x0000000000000002,
            {
                0x0000000000000022,
                0x0000000000000044,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000
            }
        },
        {
            {
                0x1100000000000011,
                0x0011000000001100,
                0x0000110000110000,
                0x0000001111000000,
                0x0000001111000000,
                0x0000110000110000,
                0x0011000000001100
            },
            0x0000000000000002,
            {
                0x2200000000000022,
                0x0022000000002200,
                0x0000220000220000,
                0x0000002222000000,
                0x0000002222000000,
                0x0000220000220000,
                0x0022000000002200
            }
        },
        {
            {
                0x2222222222222222,
                0x2211111111111122,
                0x2211222222221122,
                0x2211221221221122,
                0x2211222222221122,
                0x2211111111111122,
                0x2222222222222222
            },
            0x0000000000000002,
            {
                0x4444444444444444,
                0x4422222222222244,
                0x4422444444442244,
                0x4422442442442244,
                0x4422444444442244,
                0x4422222222222244,
                0x4444444444444444
            }
        },
#else
    // TODO(Rafael): Guess what?
#endif
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);

    while (test != test_end) {
        kryptos_poly1305_mul_digit(test->x, test->digit);
        CUTE_ASSERT(memcmp(test->x, test->e, sizeof(kryptos_poly1305_number_t)) == 0);
        test++;
    }
CUTE_TEST_CASE_END

