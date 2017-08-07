/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_ASYMMETRIC_CIPHERS_TESTS_H
#define KRYPTOS_TESTS_ASYMMETRIC_CIPHERS_TESTS_H 1

#include <kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_dh_get_modp_tests);

KUTE_DECLARE_TEST_CASE(kryptos_dh_get_random_s_tests);

KUTE_DECLARE_TEST_CASE(kryptos_dh_eval_t_tests);

KUTE_DECLARE_TEST_CASE(kryptos_dh_standard_key_exchange_bare_bone_tests);

KUTE_DECLARE_TEST_CASE(kryptos_dh_process_stdxchg_tests);

KUTE_DECLARE_TEST_CASE(kryptos_dh_mk_key_pair_tests);

KUTE_DECLARE_TEST_CASE(kryptos_dh_process_modxchg_tests);

KUTE_DECLARE_TEST_CASE(kryptos_rsa_mk_key_pair_tests);

KUTE_DECLARE_TEST_CASE(kryptos_rsa_cipher_tests);

KUTE_DECLARE_TEST_CASE(kryptos_rsa_cipher_c99_tests);

#endif
