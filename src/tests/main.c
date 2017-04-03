/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <cutest.h>
#include <padding.h>
#include <stdlib.h>
#include <string.h>

CUTE_TEST_CASE(kryptos_padding_tests)
    struct padding_tests_ctx {
        const unsigned char *buffer;
        size_t buffer_size;
        const size_t block_size;
        size_t expected_buffer_size;
        const unsigned char *pad;
    };
    struct padding_tests_ctx tests[] = {
        { "XXXXXXXXXXXXXXXXXXXXXXXXXXXX", 28, 8, 32, "XXXXXXXXXXXXXXXXXXXXXXXXXXXX\x0\x0\x0\x4" },
        { "ABC",                           3, 4,  4, "ABC\x1"                                   },
        { "ABCD",                          4, 4,  8, "ABCD\x0\x0\x0\x4"                         },
        { "A",                             1, 8,  8, "A\x0\x0\x0\x0\x0\x0\x7"                   }
    };
    size_t tests_nr = sizeof(tests) / sizeof(tests[0]), t = 0;
    unsigned char *pad = NULL;
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

        free(pad);

        t++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_test_monkey)
    CUTE_RUN_TEST(kryptos_padding_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(kryptos_test_monkey);
