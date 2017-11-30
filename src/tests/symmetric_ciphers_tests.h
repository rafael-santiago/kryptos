/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SYMMETRIC_CIPHERS_TESTS_H
#define KRYPTOS_TESTS_SYMMETRIC_CIPHERS_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_arc4_tests);

CUTE_DECLARE_TEST_CASE(kryptos_seal_tests);

CUTE_DECLARE_TEST_CASE(kryptos_des_tests);

CUTE_DECLARE_TEST_CASE(kryptos_idea_tests);

CUTE_DECLARE_TEST_CASE(kryptos_blowfish_tests);

CUTE_DECLARE_TEST_CASE(kryptos_feal_tests);

CUTE_DECLARE_TEST_CASE(kryptos_rc2_tests);

CUTE_DECLARE_TEST_CASE(kryptos_camellia_tests);

CUTE_DECLARE_TEST_CASE(kryptos_cast5_tests);

CUTE_DECLARE_TEST_CASE(kryptos_saferk64_tests);

CUTE_DECLARE_TEST_CASE(kryptos_aes128_tests);

CUTE_DECLARE_TEST_CASE(kryptos_aes192_tests);

CUTE_DECLARE_TEST_CASE(kryptos_aes256_tests);

CUTE_DECLARE_TEST_CASE(kryptos_serpent_tests);

CUTE_DECLARE_TEST_CASE(kryptos_triple_des_tests);

CUTE_DECLARE_TEST_CASE(kryptos_triple_des_ede_tests);

CUTE_DECLARE_TEST_CASE(kryptos_tea_tests);

CUTE_DECLARE_TEST_CASE(kryptos_xtea_tests);

#endif
