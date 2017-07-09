/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_ENCODING_TESTS_H
#define KRYPTOS_TESTS_ENCODING_TESTS_H 1

#include <cutest.h>

CUTE_DECLARE_TEST_CASE(kryptos_base64_tests);

CUTE_DECLARE_TEST_CASE(kryptos_uuencode_tests);

CUTE_DECLARE_TEST_CASE(kryptos_huffman_tests);

CUTE_DECLARE_TEST_CASE(kryptos_pem_get_data_tests);

CUTE_DECLARE_TEST_CASE(kryptos_pem_put_data_tests);

#endif
