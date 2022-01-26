/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SIPHASH_TESTS_H
#define KRYPTOS_TESTS_SIPHASH_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_siphash_basic_tests);

CUTE_DECLARE_TEST_CASE_SUITE(kryptos_siphash_tests);

CUTE_DECLARE_TEST_CASE(kryptos_siphash_sum_tests);

CUTE_DECLARE_TEST_CASE(kryptos_siphash_size_tests);

#endif
