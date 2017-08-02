/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_ENCODING_TESTS_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_ENCODING_TESTS_H 1

#include <kutest.h>

KUTE_DECLARE_TEST_CASE(kryptos_base64_tests);

KUTE_DECLARE_TEST_CASE(kryptos_uuencode_tests);

KUTE_DECLARE_TEST_CASE(kryptos_huffman_tests);

KUTE_DECLARE_TEST_CASE(kryptos_pem_get_data_tests);

KUTE_DECLARE_TEST_CASE(kryptos_pem_put_data_tests);

KUTE_DECLARE_TEST_CASE(kryptos_pem_get_mp_data_tests);

#endif
