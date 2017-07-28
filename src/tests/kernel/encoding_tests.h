/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_ENCODING_TESTS_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_ENCODING_TESTS_H 1

int kryptos_base64_tests(void);

int kryptos_uuencode_tests(void);

int kryptos_huffman_tests(void);

int kryptos_pem_get_data_tests(void);

int kryptos_pem_put_data_tests(void);

int kryptos_pem_get_mp_data_tests(void);

#endif
