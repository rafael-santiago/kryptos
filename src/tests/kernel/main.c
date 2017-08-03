/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kutest.h>
#if defined(__FreeBSD__)
# include <sys/cdefs.h>
# include <sys/malloc.h>
# include <sys/module.h>
# include <sys/param.h>
# include <sys/kernel.h>
# include <sys/systm.h>
#endif

#include <generic_tests.h>
#include <dsl_tests.h>
#include <encoding_tests.h>
#include <hash_tests.h>

KUTE_DECLARE_TEST_CASE(ktest_monkey);

KUTE_TEST_CASE(ktest_monkey)
    KUTE_RUN_TEST(kryptos_padding_tests);
    KUTE_RUN_TEST(kryptos_get_random_block_tests);
    KUTE_RUN_TEST(kryptos_block_parser_tests);
    KUTE_RUN_TEST(kryptos_endianess_utils_tests);
    KUTE_RUN_TEST(kryptos_apply_iv_tests);
    KUTE_RUN_TEST(kryptos_iv_data_flush_tests);
    KUTE_RUN_TEST(kryptos_task_check_tests);
    KUTE_RUN_TEST(kryptos_hex_tests);
    KUTE_RUN_TEST(kryptos_hash_common_tests);

    KUTE_RUN_TEST(kryptos_dsl_tests);

    KUTE_RUN_TEST(kryptos_base64_tests);
    KUTE_RUN_TEST(kryptos_uuencode_tests);
    KUTE_RUN_TEST(kryptos_huffman_tests);
    KUTE_RUN_TEST(kryptos_pem_get_data_tests);
    KUTE_RUN_TEST(kryptos_pem_put_data_tests);

    KUTE_RUN_TEST(kryptos_pem_get_mp_data_tests);

    KUTE_RUN_TEST(kryptos_hash_tests);
    KUTE_RUN_TEST(kryptos_hmac_tests);
KUTE_TEST_CASE_END

KUTE_MAIN(ktest_monkey);
