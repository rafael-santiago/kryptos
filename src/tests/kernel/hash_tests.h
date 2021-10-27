/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TEST_KERNEL_HASH_TESTS_H
#define KRYPTOS_KRYPTOS_TEST_KERNEL_HASH_TESTS_H 1

#include <tests/cutest/src/kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_hash_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hmac_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hmac_basic_tests);

KUTE_DECLARE_TEST_CASE(kryptos_blake2sN_tests);

KUTE_DECLARE_TEST_CASE(kryptos_blake2bN_tests);

KUTE_DECLARE_TEST_CASE(kryptos_djb2_tests);

#endif
