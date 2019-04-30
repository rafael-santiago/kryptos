/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_KDF_TESTS_H
#define KRYPTOS_TESTS_KDF_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_do_hkdf_tests);

CUTE_DECLARE_TEST_CASE(kryptos_hkdf_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_do_pbkdf2_tests);

CUTE_DECLARE_TEST_CASE(kryptos_pbkdf2_macro_tests);

CUTE_DECLARE_TEST_CASE(kryptos_do_argon2_tests);

CUTE_DECLARE_TEST_CASE(kryptos_argon2_macro_tests);

#endif
