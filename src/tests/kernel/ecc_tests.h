/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_ECC_TESTS_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_ECC_TESTS_H 1

#include <tests/cutest/src/kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_ec_set_point_tests);

KUTE_DECLARE_TEST_CASE(kryptos_ec_set_curve_tests);

KUTE_DECLARE_TEST_CASE(kryptos_ec_add_tests);

KUTE_DECLARE_TEST_CASE(kryptos_ec_dbl_tests);

KUTE_DECLARE_TEST_CASE(kryptos_ec_mul_tests);

KUTE_DECLARE_TEST_CASE(kryptos_new_standard_curve_tests);

#endif
