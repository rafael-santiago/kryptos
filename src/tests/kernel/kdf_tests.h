/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_KDF_TESTS_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_KDF_TESTS_H 1

#include <tests/cutest/src/kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_do_hkdf_tests);

KUTE_DECLARE_TEST_CASE(kryptos_hkdf_macro_tests);

KUTE_DECLARE_TEST_CASE(kryptos_do_pbkdf2_tests);

KUTE_DECLARE_TEST_CASE(kryptos_pbkdf2_macro_tests);

#if !defined(__NetBSD__)

KUTE_DECLARE_TEST_CASE(kryptos_do_argon2_tests);

KUTE_DECLARE_TEST_CASE(kryptos_argon2_macro_tests);

KUTE_DECLARE_TEST_CASE(kryptos_do_argon2_bounds_tests);

KUTE_DECLARE_TEST_CASE(kryptos_argon2_macro_bounds_tests);

#endif

#endif
