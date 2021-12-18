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
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_get_gt_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_ne_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_gt_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_lt_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_ge_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_not_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_inv_cmplt_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_lsh_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_poly1305_rsh_tests)
CUTE_TEST_CASE_END
