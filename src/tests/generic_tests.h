/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_GENERIC_TESTS_H
#define KRYPTOS_TESTS_GENERIC_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_padding_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sys_get_random_block_tests);

CUTE_DECLARE_TEST_CASE(kryptos_get_random_block_tests);

CUTE_DECLARE_TEST_CASE(kryptos_block_parser_tests);

CUTE_DECLARE_TEST_CASE(kryptos_endianness_utils_tests);

CUTE_DECLARE_TEST_CASE(kryptos_apply_iv_tests);

CUTE_DECLARE_TEST_CASE(kryptos_iv_data_flush_tests);

CUTE_DECLARE_TEST_CASE(kryptos_task_check_tests);

CUTE_DECLARE_TEST_CASE(kryptos_task_check_sign_tests);

CUTE_DECLARE_TEST_CASE(kryptos_task_check_verify_tests);

CUTE_DECLARE_TEST_CASE(kryptos_hex_tests);

CUTE_DECLARE_TEST_CASE(kryptos_hash_common_tests);

CUTE_DECLARE_TEST_CASE(kryptos_iv_inc_u32_tests);

CUTE_DECLARE_TEST_CASE(kryptos_fortuna_general_tests);

CUTE_DECLARE_TEST_CASE(kryptos_csprng_context_change_tests);

CUTE_DECLARE_TEST_CASE(kryptos_memset_tests);

CUTE_DECLARE_TEST_CASE(kryptos_memcmp_tests);

CUTE_DECLARE_TEST_CASE(kryptos_memory_tests);

CUTE_DECLARE_TEST_CASE(kryptos_gcm_gf_mul_tests);

CUTE_DECLARE_TEST_CASE(kryptos_gcm_tests);

CUTE_DECLARE_TEST_CASE(kryptos_u32_rev_tests);

CUTE_DECLARE_TEST_CASE(kryptos_u64_rev_tests);

#endif
