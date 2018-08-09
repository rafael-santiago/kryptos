/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_GENERIC_TESTS_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_GENERIC_TESTS_H 1

#include <tests/cutest/src/kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_padding_tests);

KUTE_DECLARE_TEST_CASE(kryptos_sys_get_random_block_tests);

KUTE_DECLARE_TEST_CASE(kryptos_get_random_block_tests);

KUTE_DECLARE_TEST_CASE(kryptos_block_parser_tests);

KUTE_DECLARE_TEST_CASE(kryptos_endianness_utils_tests);

KUTE_DECLARE_TEST_CASE(kryptos_apply_iv_tests);

KUTE_DECLARE_TEST_CASE(kryptos_iv_data_flush_tests);

KUTE_DECLARE_TEST_CASE(kryptos_task_check_tests);

KUTE_DECLARE_TEST_CASE(kryptos_task_check_sign_tests);

KUTE_DECLARE_TEST_CASE(kryptos_task_check_verify_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hex_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hash_common_tests);

KUTE_DECLARE_TEST_CASE(kryptos_fortuna_general_tests);

KUTE_DECLARE_TEST_CASE(kryptos_csprng_context_change_tests);

KUTE_DECLARE_TEST_CASE(kryptos_memset_tests);

#endif