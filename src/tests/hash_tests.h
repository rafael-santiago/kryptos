/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_HASH_TESTS_H
#define KRYPTOS_TESTS_HASH_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_sha1_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha224_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha256_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha384_tests);

CUTE_DECLARE_TEST_CASE(kryptos_sha512_tests);

CUTE_DECLARE_TEST_CASE(kryptos_md4_tests);

CUTE_DECLARE_TEST_CASE(kryptos_md5_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ripemd128_tests);

CUTE_DECLARE_TEST_CASE(kryptos_ripemd160_tests);

CUTE_DECLARE_TEST_CASE(kryptos_hmac_tests);

#endif
