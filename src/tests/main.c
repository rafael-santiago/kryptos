/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <cutest.h>
#include <kryptos_padding.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <kryptos_task_check.h>
#include <stdlib.h>
#include <string.h>

CUTE_TEST_CASE(kryptos_padding_tests)
    struct padding_tests_ctx {
        const kryptos_u8_t *buffer;
        size_t buffer_size;
        const size_t block_size;
        size_t expected_buffer_size;
        const kryptos_u8_t *pad;
    };
    struct padding_tests_ctx tests[] = {
        { "XXXXXXXXXXXXXXXXXXXXXXXXXXXX", 28, 8, 32, "XXXXXXXXXXXXXXXXXXXXXXXXXXXX\x0\x0\x0\x4" },
        { "ABC",                           3, 4,  4, "ABC\x1"                                   },
        { "ABCD",                          4, 4,  8, "ABCD\x0\x0\x0\x4"                         },
        { "A",                             1, 8,  8, "A\x0\x0\x0\x0\x0\x0\x7"                   }
    };
    size_t tests_nr = sizeof(tests) / sizeof(tests[0]), t = 0;
    kryptos_u8_t *pad = NULL;
//    size_t old_size;

    while (t < tests_nr) {

        pad = kryptos_ansi_x923_padding(tests[t].buffer,
                                        &tests[t].buffer_size,
                                        tests[t].block_size);
        CUTE_ASSERT(pad != NULL);

        CUTE_ASSERT(tests[t].buffer_size == tests[t].expected_buffer_size);

//        for (old_size = 0; old_size < tests[t].buffer_size; old_size++) {
//            printf(" %.2x ", pad[old_size]);
//        }
//        printf("\n");

        CUTE_ASSERT(memcmp(pad, tests[t].pad, tests[t].buffer_size) == 0);

        kryptos_freeseg(pad);

        t++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_get_random_block_tests)
    void *block = NULL;
    size_t b = 0;

    CUTE_ASSERT(kryptos_get_random_block(0) == NULL);

    for (b = 1; b < 101; b++) {
        block = kryptos_get_random_block(b);
        CUTE_ASSERT(block != NULL);
        kryptos_freeseg(block);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_task_check_tests)
    kryptos_u8_t *key = "blah";
    kryptos_u8_t *in = "bleh";
    kryptos_u8_t *iv = "bluh";
    kryptos_task_ctx t;
    kryptos_task_ctx *ktask = &t;

    t.cipher = -1;
    t.mode = kKryptosECB;
    t.key = key;
    t.key_size = 4;
    t.iv = in;
    t.iv_size = 4;
    t.in = in;
    t.out = NULL;
    t.out_size = 0;

    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidCipher);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid cipher.") == 0);

    t.cipher = kKryptosCipherARC4;
    t.key = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid key data.") == 0);

    t.key = key;
    t.key_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid key data.") == 0);

    t.cipher = kKryptosCipherAES;
    t.key_size = 4;
    t.mode = kKryptosCBC;
    t.iv = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid iv data.") == 0);

    t.iv = iv;
    t.iv_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid iv data.") == 0);

    t.iv_size = 4;
    t.in = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "No input.") == 0);

    t.in = in;
    t.in_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "No input.") == 0);

    t.in_size = 4;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherARC4;
    t.iv = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherSEAL;
    t.iv = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherARC4;
    t.iv_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherSEAL;
    t.iv_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_test_monkey)
    CUTE_RUN_TEST(kryptos_padding_tests);
    CUTE_RUN_TEST(kryptos_get_random_block_tests);
    CUTE_RUN_TEST(kryptos_task_check_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(kryptos_test_monkey);
