/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <ktests.h>
#include <kutest.h>
#include <generic_tests.h>
#include <dsl_tests.h>
#include <encoding_tests.h>

int ktest_monkey(void) {
    KUTE_RUN_TEST(kryptos_padding_tests);
    KUTE_RUN_TEST(kryptos_get_random_block_tests);
    KUTE_RUN_TEST(kryptos_block_parser_tests);
    KUTE_RUN_TEST(kryptos_endianess_utils_tests);
    KUTE_RUN_TEST(kryptos_apply_iv_tests);
    KUTE_RUN_TEST(kryptos_iv_data_flush_tests);
    KUTE_RUN_TEST(kryptos_task_check_tests);
    KUTE_RUN_TEST(kryptos_hex_tests);
    KUTE_RUN_TEST(kryptos_hash_common_tests);

    //KUTE_RUN_TEST(kryptos_dsl_tests);

    KUTE_RUN_TEST(kryptos_base64_tests);
    KUTE_RUN_TEST(kryptos_uuencode_tests);
    //KUTE_RUN_TEST(kryptos_huffman_tests);
    //KUTE_RUN_TEST(kryptos_pem_get_data_tests);
    //KUTE_RUN_TEST(kryptos_pem_put_data_tests);


    //KUTE_RUN_TEST(kryptos_pem_get_mp_data_tests);

    return 0;
}
