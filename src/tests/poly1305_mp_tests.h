/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_POLY1305_MP_TESTS_H
#define KRYPTOS_TESTS_POLY1305_MP_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_le_bytes_to_num_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_le_num_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_ld_raw_bytes_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_eq_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_get_gt_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_ne_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_gt_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_lt_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_ge_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_not_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_lsh_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_rsh_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_add_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_inv_cmplt_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_sub_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_mul_tests);

CUTE_DECLARE_TEST_CASE(kryptos_poly1305_mul_digit_tests);

#endif
