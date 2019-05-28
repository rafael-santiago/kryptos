/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_ECC_TESTS_H
#define KRYPTOS_TESTS_ECC_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_ec_set_point_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ec_set_curve_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ec_add_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ec_dbl_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ec_mul_tests);

#endif
