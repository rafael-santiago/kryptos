/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TESTS_KERNEL_GENERIC_TESTS_H
#define KRYPTOS_KRYPTOS_TESTS_KERNEL_GENERIC_TESTS_H 1

int kryptos_padding_tests(void);

int kryptos_get_random_block_tests(void);

int kryptos_block_parser_tests(void);

int kryptos_endianess_utils_tests(void);

int kryptos_apply_iv_tests(void);

int kryptos_iv_data_flush_tests(void);

int kryptos_task_check_tests(void);

int kryptos_hex_tests(void);

int kryptos_hash_common_tests(void);

#endif