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
#include <kryptos_block_parser.h>
#include <kryptos_endianess_utils.h>
#include <kryptos.h>
#include <kryptos_iv_utils.h>
#include <kryptos_base64.h>
#include <kryptos_uuencode.h>
#include <kryptos_hex.h>
#include "test_vectors.h"
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
    size_t buffer_size;
//    size_t old_size;

    while (t < tests_nr) {
        buffer_size = tests[t].buffer_size;
        pad = kryptos_ansi_x923_padding(tests[t].buffer,
                                        &buffer_size,
                                        tests[t].block_size, 0);
        CUTE_ASSERT(pad != NULL);
        CUTE_ASSERT(buffer_size == tests[t].expected_buffer_size);

//        for (old_size = 0; old_size < tests[t].buffer_size; old_size++) {
//            printf(" %.2x ", pad[old_size]);
//        }
//        printf("\n");

        CUTE_ASSERT(memcmp(pad, tests[t].pad, buffer_size) == 0);

        kryptos_freeseg(pad);
        pad = NULL;

        buffer_size = tests[t].buffer_size;
        pad = kryptos_ansi_x923_padding(tests[t].buffer,
                                        &buffer_size,
                                        tests[t].block_size, 1);

        CUTE_ASSERT(pad != NULL);

        CUTE_ASSERT(buffer_size == tests[t].expected_buffer_size);

        CUTE_ASSERT(pad[buffer_size - 1] == tests[t].pad[tests[t].expected_buffer_size - 1]);

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
    t.action = kKryptosEncrypt;
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

    t.mode = kKryptosECB;
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

    t.mode = kKryptosCipherModeNr;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid operation mode.") == 0);

    t.mode = kKryptosECB;
    t.action = kKryptosActionNr;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid task action.") == 0);

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

CUTE_TEST_CASE(kryptos_arc4_tests)
    kryptos_task_ctx t, *ktask = &t;
    struct test_vector_ctx {
        kryptos_u8_t *key;
        size_t key_size;
        kryptos_u8_t *in;
        size_t in_size;
        kryptos_u8_t *out;
        size_t out_size;
    };
    // INFO(Rafael): This is the same test vector data posted by Eric Rescola on 09/13/1994.
    //               [https://groups.google.com/group/comp.security.misc/msg/10a300c9d21afca0]
    struct test_vector_ctx test_vector[] = {
        {
            "\x01\x23\x45\x67\x89\xab\xcd\xef",
            8,
            "\x01\x23\x45\x67\x89\xab\xcd\xef",
            8,
            "\x75\xb7\x87\x80\x99\xe0\xc5\x96",
            8
        },
        {
            "\x01\x23\x45\x67\x89\xab\xcd\xef",
            8,
            "\x00\x00\x00\x00\x00\x00\x00\x00",
            8,
            "\x74\x94\xc2\xe7\x10\x4b\x08\x79",
            8
        },
        {
            "\x00\x00\x00\x00\x00\x00\x00\x00",
            8,
            "\x00\x00\x00\x00\x00\x00\x00\x00",
            8,
            "\xde\x18\x89\x41\xa3\x37\x5d\x3a",
            8
        },
        {
            "\xef\x01\x23\x45",
            4,
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            10,
            "\xd6\xa1\x41\xa7\xec\x3c\x38\xdf\xbd\x61",
            10
        },
        {
            "\x01\x23\x45\x67\x89\xab\xcd\xef",
            8,
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
            "\x01",
            512,
            "\x75\x95\xc3\xe6\x11\x4a\x09\x78\x0c\x4a\xd4"
            "\x52\x33\x8e\x1f\xfd\x9a\x1b\xe9\x49\x8f"
            "\x81\x3d\x76\x53\x34\x49\xb6\x77\x8d\xca"
            "\xd8\xc7\x8a\x8d\x2b\xa9\xac\x66\x08\x5d"
            "\x0e\x53\xd5\x9c\x26\xc2\xd1\xc4\x90\xc1"
            "\xeb\xbe\x0c\xe6\x6d\x1b\x6b\x1b\x13\xb6"
            "\xb9\x19\xb8\x47\xc2\x5a\x91\x44\x7a\x95"
            "\xe7\x5e\x4e\xf1\x67\x79\xcd\xe8\xbf\x0a"
            "\x95\x85\x0e\x32\xaf\x96\x89\x44\x4f\xd3"
            "\x77\x10\x8f\x98\xfd\xcb\xd4\xe7\x26\x56"
            "\x75\x00\x99\x0b\xcc\x7e\x0c\xa3\xc4\xaa"
            "\xa3\x04\xa3\x87\xd2\x0f\x3b\x8f\xbb\xcd"
            "\x42\xa1\xbd\x31\x1d\x7a\x43\x03\xdd\xa5"
            "\xab\x07\x88\x96\xae\x80\xc1\x8b\x0a\xf6"
            "\x6d\xff\x31\x96\x16\xeb\x78\x4e\x49\x5a"
            "\xd2\xce\x90\xd7\xf7\x72\xa8\x17\x47\xb6"
            "\x5f\x62\x09\x3b\x1e\x0d\xb9\xe5\xba\x53"
            "\x2f\xaf\xec\x47\x50\x83\x23\xe6\x71\x32"
            "\x7d\xf9\x44\x44\x32\xcb\x73\x67\xce\xc8"
            "\x2f\x5d\x44\xc0\xd0\x0b\x67\xd6\x50\xa0"
            "\x75\xcd\x4b\x70\xde\xdd\x77\xeb\x9b\x10"
            "\x23\x1b\x6b\x5b\x74\x13\x47\x39\x6d\x62"
            "\x89\x74\x21\xd4\x3d\xf9\xb4\x2e\x44\x6e"
            "\x35\x8e\x9c\x11\xa9\xb2\x18\x4e\xcb\xef"
            "\x0c\xd8\xe7\xa8\x77\xef\x96\x8f\x13\x90"
            "\xec\x9b\x3d\x35\xa5\x58\x5c\xb0\x09\x29"
            "\x0e\x2f\xcd\xe7\xb5\xec\x66\xd9\x08\x4b"
            "\xe4\x40\x55\xa6\x19\xd9\xdd\x7f\xc3\x16"
            "\x6f\x94\x87\xf7\xcb\x27\x29\x12\x42\x64"
            "\x45\x99\x85\x14\xc1\x5d\x53\xa1\x8c\x86"
            "\x4c\xe3\xa2\xb7\x55\x57\x93\x98\x81\x26"
            "\x52\x0e\xac\xf2\xe3\x06\x6e\x23\x0c\x91"
            "\xbe\xe4\xdd\x53\x04\xf5\xfd\x04\x05\xb3"
            "\x5b\xd9\x9c\x73\x13\x5d\x3d\x9b\xc3\x35"
            "\xee\x04\x9e\xf6\x9b\x38\x67\xbf\x2d\x7b"
            "\xd1\xea\xa5\x95\xd8\xbf\xc0\x06\x6f\xf8"
            "\xd3\x15\x09\xeb\x0c\x6c\xaa\x00\x6c\x80"
            "\x7a\x62\x3e\xf8\x4c\x3d\x33\xc1\x95\xd2"
            "\x3e\xe3\x20\xc4\x0d\xe0\x55\x81\x57\xc8"
            "\x22\xd4\xb8\xc5\x69\xd8\x49\xae\xd5\x9d"
            "\x4e\x0f\xd7\xf3\x79\x58\x6b\x4b\x7f\xf6"
            "\x84\xed\x6a\x18\x9f\x74\x86\xd4\x9b\x9c"
            "\x4b\xad\x9b\xa2\x4b\x96\xab\xf9\x24\x37"
            "\x2c\x8a\x8f\xff\xb1\x0d\x55\x35\x49\x00"
            "\xa7\x7a\x3d\xb5\xf2\x05\xe1\xb9\x9f\xcd"
            "\x86\x60\x86\x3a\x15\x9a\xd4\xab\xe4\x0f"
            "\xa4\x89\x34\x16\x3d\xdd\xe5\x42\xa6\x58"
            "\x55\x40\xfd\x68\x3c\xbf\xd8\xc0\x0f\x12"
            "\x12\x9a\x28\x4d\xea\xcc\x4c\xde\xfe\x58"
            "\xbe\x71\x37\x54\x1c\x04\x71\x26\xc8\xd4"
            "\x9e\x27\x55\xab\x18\x1a\xb7\xe9\x40\xb0"
            "\xc0",
            512
        }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), ct;
    kryptos_u8_t *temp = NULL;

    t.cipher = kKryptosCipherARC4;

    for (ct = 0; ct < test_vector_nr; ct++) {
        t.in = test_vector[ct].in;
        t.in_size = test_vector[ct].in_size;
        kryptos_arc4_setup(ktask, test_vector[ct].key, test_vector[ct].key_size);
        kryptos_arc4_cipher(&ktask);
        CUTE_ASSERT(t.result == kKryptosSuccess);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[ct].out_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[ct].out, t.out_size) == 0);
        temp = t.in;
        t.in = t.out;
        kryptos_arc4_cipher(&ktask);
        CUTE_ASSERT(t.result == kKryptosSuccess);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[ct].in_size);
        CUTE_ASSERT(memcmp(t.out, temp, t.out_size) == 0);
        kryptos_freeseg(t.in);
        kryptos_freeseg(t.out);
    }

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_seal_tests)
    // WARN(Rafael): The original SEAL spec does not provide any kind of test based on inputs -> outputs.
    //               In SEAL spec there is only a test vector of the whole generated keystream using a
    //               specific parameters configuration. I have tested my implementation over that data
    //               and then I generated these two following "oracle" test vectors. The configuration
    //               used here comes from the original SEAL paper.
    kryptos_task_ctx t, *ktask = &t;
    kryptos_seal_version_t v = kKryptosSEAL20;
    kryptos_u8_t *in = "The covers of this book are too far apart. -- Ambrose Pierce (Book Review).";
    kryptos_u8_t *expected_out_v20 = "\x63\xc8\x60\xb5\xf8\xeb\xb2\xf9\xd6\xcd\x3e\x6a\x60\x53\x27\x67\x63\xbb\x18"
                                     "\xff\xaa\xe8\xe5\xe8\xbb\x14\x03\xf0\x19\xc8\x7c\x08\x72\x78\xcf\xd2\xb3\x28"
                                     "\xdf\xc9\xc2\x8a\x0a\x60\xa7\x11\x5b\x1f\x14\xd4\x52\x88\x85\x4e\xb5\x1f\x13"
                                     "\xfa\xd4\xff\xcf\x3f\xcc\xc6\x6e\x5c\xff\x5d\x10\x29\x8a\x2b\x0d\x67\x39";
    kryptos_u8_t *expected_out_v30 = "\x63\xc8\x60\xb5\xf8\xeb\xb2\xf9\xd6\xcd\x3e\x6a\x60\x53\x27\x67\x36\xc3\xb7"
                                     "\x9f\x99\xce\x54\x9d\x0d\x5e\xbb\xed\xf5\x92\x81\x5c\x4c\xdc\xb1\xc7\x05\x50"
                                     "\xfb\x8d\x74\x8f\x02\xae\xc2\x47\x11\xe8\xa3\x11\x24\x20\x4d\xb0\x09\x8f\xc2"
                                     "\xd9\x3d\xbc\x68\x24\x43\x84\x23\x0f\x76\xc8\xe8\xb8\x43\x46\x89\xc4\x20";
    size_t n = 0x013577af;
    size_t l = 1024;

    kryptos_seal_setup(ktask,
                       "\x67\x45\x23\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x10\x32\x54\x76\xc3\xd2\xe1\xf0",
                       20, &v, &l, &n);
    t.in = in;
    t.in_size = strlen(t.in);

    // INFO(Rafael): Testing SEAL 2.0 processing.

    kryptos_seal_cipher(&ktask);

    CUTE_ASSERT(t.out != NULL);
    CUTE_ASSERT(t.out_size == t.in_size);
    CUTE_ASSERT(memcmp(t.out, expected_out_v20, t.out_size) == 0);

    t.in = t.out;
    kryptos_seal_cipher(&ktask);

    CUTE_ASSERT(t.out != NULL);
    CUTE_ASSERT(t.out_size == t.in_size);
    CUTE_ASSERT(memcmp(t.out, in, t.out_size) == 0);

    kryptos_freeseg(t.out);
    kryptos_freeseg(t.in);

    //  INFO(Rafael): Testing SEAL 3.0 processing.

    v = kKryptosSEAL30;
    t.in = in;

    kryptos_seal_cipher(&ktask);

    CUTE_ASSERT(t.out != NULL);
    CUTE_ASSERT(t.out_size == t.in_size);
    CUTE_ASSERT(memcmp(t.out, expected_out_v30, t.out_size) == 0);

    t.in = t.out;
    kryptos_seal_cipher(&ktask);

    CUTE_ASSERT(t.out != NULL);
    CUTE_ASSERT(t.out_size == t.in_size);
    CUTE_ASSERT(memcmp(t.out, in, t.out_size) == 0);

    kryptos_freeseg(t.out);
    kryptos_freeseg(t.in);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_dsl_tests)
    // WARN(Rafael): The correctness of each available cipher must not be tested here. It
    //               should be done within a dedicated test case. Here only the mechanics about
    //               using these ciphers indirectly is tested (when C99 support is present).
    //               For testing it is used only one fixed plaintext and short keys.
    kryptos_task_ctx task;
    kryptos_u8_t *data = "IDIOT, n. A member of a large and powerful tribe whose influence in "
                         "human affairs has always been dominant and controlling. The Idiot's "
                         "activity is not confined to any special field of throught or action, but "
                         "'pervades and regulates the whole'. He has the last word in everything; his "
                         "decision is unappealable. He sets the fashions of opinion and taste, dictates "
                         "the limitations of speech and circumscribes conduct with a dead-line."; 
                         //... Everyone can point at least one.
    size_t data_size = strlen(data);
    kryptos_seal_version_t seal_version;
    size_t seal_n, seal_l;
    int feal_rounds;
    kryptos_camellia_keysize_t camellia_keysize;
    int rc2_t1;
    int saferk64_rounds;

    kryptos_task_set_ecb_mode(&task);
    CUTE_ASSERT(task.mode == kKryptosECB);

    kryptos_task_set_cbc_mode(&task);
    CUTE_ASSERT(task.mode == kKryptosCBC);

    kryptos_task_set_encrypt_action(&task);
    CUTE_ASSERT(task.action == kKryptosEncrypt);

    kryptos_task_set_decrypt_action(&task);
    CUTE_ASSERT(task.action == kKryptosDecrypt);

    task.result = kKryptosSuccess;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    task.result = kKryptosKeyError;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosProcessError;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosInvalidParams;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosInvalidCipher;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosTaskResultNr;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    kryptos_task_set_in(&task, data, data_size);
    CUTE_ASSERT(task.in == data);
    CUTE_ASSERT(task.in_size == data_size);

    kryptos_task_init_as_null(&task);

    task.in = NULL;
    task.in_size = 0;
    task.out = data;
    task.out_size = data_size;
    CUTE_ASSERT(kryptos_task_get_out(&task) == data);
    CUTE_ASSERT(kryptos_task_get_out_size(&task) == data_size);

    if (g_cute_leak_check == 1) {
        task.out = (kryptos_u8_t *) kryptos_newseg(0x10);
        task.out_size = 0x10;
        kryptos_task_free(&task, KRYPTOS_TASK_OUT);
        CUTE_ASSERT(task.out == NULL);
        CUTE_ASSERT(task.out_size == 0);

        task.in = (kryptos_u8_t *) kryptos_newseg(0x10);
        task.in_size = 0x10;
        task.out = (kryptos_u8_t *) kryptos_newseg(0x10);
        task.out_size = 0x10;
        kryptos_task_free(&task, KRYPTOS_TASK_OUT|KRYPTOS_TASK_IN);
        CUTE_ASSERT(task.in == NULL);
        CUTE_ASSERT(task.in_size == 0);
        CUTE_ASSERT(task.out == NULL);
        CUTE_ASSERT(task.out_size == 0);
        // WARN(Rafael): If the out block was not actually freed, the cutest leak check system will complain.
    } else {
        printf("=== WARN: The leak check system is deactivated, due to it was not possible test the kryptos_task_free() macro. It was SKIPPED.\n===\n");
    }

#ifdef KRYPTOS_C99
    // INFO(Rafael): The cipher indirect calling tests. Let's test the variadic macro kryptos_run_cipher() variations.

    // INFO(Rafael): Stream ciphers.
    kryptos_task_init_as_null(&task);

    kryptos_task_set_in(&task, data, data_size);

    // ARC4
    kryptos_run_cipher(arc4, &task, "arc4", 4);
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    kryptos_task_set_in(&task, kryptos_task_get_out(&task), kryptos_task_get_out_size(&task));

    kryptos_run_cipher(arc4, &task, "arc4", 4);
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(task.out != NULL);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SEAL 2.0
    kryptos_task_set_in(&task, data, data_size);

    seal_version = kKryptosSEAL20;
    seal_l = 1024;
    seal_n = 0;
    kryptos_run_cipher(seal, &task, "seal", 4, &seal_version, &seal_l, &seal_n);
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    kryptos_task_set_in(&task, kryptos_task_get_out(&task), kryptos_task_get_out_size(&task));

    kryptos_run_cipher(seal, &task, "seal", 4, &seal_version, &seal_l, &seal_n);
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(task.out != NULL);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SEAL 3.0
    kryptos_task_set_in(&task, data, data_size);

    seal_version = kKryptosSEAL30;
    seal_l = 2048;
    seal_n = 0;
    kryptos_run_cipher(seal, &task, "seal", 4, &seal_version, &seal_l, &seal_n);
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    kryptos_task_set_in(&task, kryptos_task_get_out(&task), kryptos_task_get_out_size(&task));

    kryptos_run_cipher(seal, &task, "seal", 4, &seal_version, &seal_l, &seal_n);
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(task.out != NULL);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // INFO(Rafael): Block ciphers.
    kryptos_task_init_as_null(&task);

    // DES ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(des, &task, "des", 3, kKryptosECB);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(des, &task, "des", 3, kKryptosECB);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // DES CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(des, &task, "des", 3, kKryptosCBC);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(des, &task, "des", 3, kKryptosCBC);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // IDEA ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(idea, &task, "idea", 4, kKryptosECB);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(idea, &task, "idea", 4, kKryptosECB);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // IDEA CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(idea, &task, "idea", 4, kKryptosCBC);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(idea, &task, "idea", 4, kKryptosCBC);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // BLOWFISH ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(blowfish, &task, "blowfish", 8, kKryptosECB);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(blowfish, &task, "blowfish", 8, kKryptosECB);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // BLOWFISH CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(blowfish, &task, "blowfish", 8, kKryptosCBC);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(blowfish, &task, "blowfish", 8, kKryptosCBC);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // FEAL ECB
    feal_rounds = 16;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(feal, &task, "feal", 4, kKryptosECB, &feal_rounds);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(feal, &task, "feal", 4, kKryptosECB, &feal_rounds);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // FEAL CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(feal, &task, "feal", 4, kKryptosCBC, &feal_rounds);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(feal, &task, "feal", 4, kKryptosCBC, &feal_rounds);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-128 ECB
    camellia_keysize = kKryptosCAMELLIA128;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosECB, &camellia_keysize);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosECB, &camellia_keysize);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-128 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosCBC, &camellia_keysize);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosCBC, &camellia_keysize);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-192 ECB
    camellia_keysize = kKryptosCAMELLIA192;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosECB, &camellia_keysize);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosECB, &camellia_keysize);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-192 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosCBC, &camellia_keysize);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosCBC, &camellia_keysize);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-256 ECB
    camellia_keysize = kKryptosCAMELLIA256;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosECB, &camellia_keysize);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosECB, &camellia_keysize);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-192 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosCBC, &camellia_keysize);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(camellia, &task, "camellia", 8, kKryptosCBC, &camellia_keysize);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAST5 ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(cast5, &task, "cast5", 5, kKryptosECB);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(cast5, &task, "cast5", 5, kKryptosECB);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAST5 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(cast5, &task, "cast5", 5, kKryptosCBC);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(cast5, &task, "cast5", 5, kKryptosCBC);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC2 ECB
    rc2_t1 = 128;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosECB, &rc2_t1);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosECB, &rc2_t1);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC2 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosCBC, &rc2_t1);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(rc2, &task, "rc2", 3, kKryptosCBC, &rc2_t1);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SAFER K-64 ECB
    saferk64_rounds = 32;

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosECB, &saferk64_rounds);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosECB, &saferk64_rounds);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SAFER K-64 CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosCBC, &saferk64_rounds);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(saferk64, &task, "saferk64", 8, kKryptosCBC, &saferk64_rounds);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(aes, &task, "aes", 3, kKryptosECB);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(aes, &task, "aes", 3, kKryptosECB);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // AES CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(aes, &task, "aes", 3, kKryptosCBC);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(aes, &task, "aes", 3, kKryptosCBC);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SERPENT ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(serpent, &task, "serpent", 7, kKryptosECB);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(serpent, &task, "serpent", 7, kKryptosECB);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SERPENT CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    kryptos_run_cipher(serpent, &task, "serpent", 7, kKryptosCBC);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(serpent, &task, "serpent", 7, kKryptosCBC);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_block_parser_tests)
    kryptos_u8_t *in = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", *in_p;
    kryptos_u8_t *in_end = NULL;
    kryptos_u8_t *out = NULL;

    in_p = in;
    in_end = in_p + 16;

    out = (kryptos_u8_t *) kryptos_newseg(16);
    CUTE_ASSERT(out != NULL);
    memset(out, 0, 16);

    // INFO(Rafael): 16-bit block parsing.

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x00\x01", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x02\x03", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x04\x05", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x06\x07", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x08\x09", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x0a\x0b", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x0c\x0d", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x0e\x0f", 2) == 0);

    CUTE_ASSERT(kryptos_block_parser(out, 2, in_p, in_end, &in_p) == NULL);

    in_p = in;
    in_end = in_p + 16;

    // INFO(Rafael): 32-bit block parsing.

    out = kryptos_block_parser(out, 4, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x00\x01\x02\x03", 4) == 0);

    out = kryptos_block_parser(out, 4, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x04\x05\x06\x07", 4) == 0);

    out = kryptos_block_parser(out, 4, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x08\x09\x0a\x0b", 4) == 0);

    out = kryptos_block_parser(out, 4, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x0c\x0d\x0e\x0f", 4) == 0);

    CUTE_ASSERT(kryptos_block_parser(out, 4, in_p, in_end, &in_p) == NULL);

    in_p = in;
    in_end = in_p + 16;

    // INFO(Rafael): 64-bit block parsing.

    out = kryptos_block_parser(out, 8, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x00\x01\x02\x03\x04\x05\x06\x07", 8) == 0);

    out = kryptos_block_parser(out, 8, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 8) == 0);

    CUTE_ASSERT(kryptos_block_parser(out, 8, in_p, in_end, &in_p) == NULL);

    kryptos_freeseg(out);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_endianess_utils_tests)
    kryptos_u8_t *data = NULL;
    kryptos_u32_t deadbeef = 0L;
    kryptos_u16_t beef = 0L;

    data = (kryptos_u8_t *)kryptos_newseg(4);
    CUTE_ASSERT(data != NULL);
    memcpy(data, "\xde\xad\xbe\xef", 4);
    memcpy(&deadbeef, data, 4);
    deadbeef = kryptos_get_u32_as_big_endian(data, 4);
    CUTE_ASSERT(deadbeef == 0xdeadbeef);
    memset(data, 0, 4);
    data = kryptos_cpy_u32_as_big_endian(data, 4, deadbeef);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(*data == 0xde && *(data + 1) == 0xad && *(data + 2) == 0xbe && *(data + 3) == 0xef);
    kryptos_freeseg(data);

    data = (kryptos_u8_t *)kryptos_newseg(2);
    CUTE_ASSERT(data != NULL);
    memcpy(data, "\xbe\xef", 2);
    memcpy(&beef, data, 2);
    beef = kryptos_get_u16_as_big_endian(data, 2);
    CUTE_ASSERT(beef == 0xbeef);
    memset(data, 0, 2);
    data = kryptos_cpy_u16_as_big_endian(data, 2, beef);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(*data == 0xbe && *(data + 1) == 0xef);
    kryptos_freeseg(data);
CUTE_TEST_CASE_END

// INFO(Rafael): Block cipher testing area.

CUTE_TEST_CASE(kryptos_des_tests)
    // INFO(Rafael): Running the ECB and CBC tests. Once defined the ECB test vector related with the cipher, the following
    //               incantation is all that you should implement inside a test case dedicated to block cipher.
    kryptos_run_block_cipher_tests(des, KRYPTOS_DES_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_idea_tests)
    kryptos_run_block_cipher_tests(idea, KRYPTOS_IDEA_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blowfish_tests)
    kryptos_run_block_cipher_tests(blowfish, KRYPTOS_BLOWFISH_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_feal_tests)
    // INFO(Rafael): To test a block cipher with a custom setup is a little bit tricky.
    //               A custom setup means that the user needs to pass additional parameters besides the key and the key size.
    //
    //               1. In this case is necessary to create a struct array that gathers these additional parameters.
    //
    //               2. Initialize the array and evaluate the count of elements of this array.
    //                  Each item cell inside this array belongs to a specific test iteration (0..n).
    //                  The count of elements is our "n".
    //
    //               3. Declare a kryptos_task_ctx. Do not worry about initialize it.
    //
    //               4. Declare a counter (it will be used as the master index of the test loop).
    //
    //               5. Use the macro kryptos_run_block_cipher_tests_with_custom_setup().

    // INFO(Rafael): 1.
    struct feal_rounds_per_test {
        int rounds;
    };
    // INFO(Rafael): 2.
    struct feal_rounds_per_test feal_rounds[] = {
        { 8 }, { 16 }, { 32 }
    };
    size_t feal_rounds_nr = sizeof(feal_rounds) / sizeof(feal_rounds[0]);
    // INFO(Rafael): 3.
    kryptos_task_ctx t;
    // INFO(Rafael): 4.
    size_t tv;
    // INFO(Rafael): 5.
    kryptos_run_block_cipher_tests_with_custom_setup(feal,
                                                     KRYPTOS_FEAL_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     feal_rounds, feal_rounds_nr,
                                                     kryptos_feal_setup(&t,
                                                                        feal_test_vector[tv % feal_rounds_nr].key,
                                                                        feal_test_vector[tv % feal_rounds_nr].key_size,
                                                                        kKryptosECB,
                                                                        &feal_rounds[tv % feal_rounds_nr].rounds),
                                                     kryptos_feal_setup(&t,
                                                                        feal_test_vector[tv % feal_rounds_nr].key,
                                                                        feal_test_vector[tv % feal_rounds_nr].key_size,
                                                                        kKryptosCBC,
                                                                        &feal_rounds[tv % feal_rounds_nr].rounds));
    // INFO(Rafael): The last two parameters of kryptos_run_block_cipher_test_with_custom_setup()
    //               are related with the exact cipher setup call that must be executed on the test step.
    //               One is used on the ECB tests and another is used on the CBC tests.
    //
    //               The "feal_test_vector" is declared into "feal_test_vector.h". Yes, tricky but works!
    //
    //  Tip: Always use (tv % feal_rounds_nr) to index the test vector and your parameter structure.
    //
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc2_tests)
    struct rc2_T1 {
        int T1;
    };
    struct rc2_T1 rc2_key_bits[] = {
        { 63 }, { 64 }, { 64 }, { 64 }, { 64 }, { 64 }, { 128 }, { 129 }
    };
    size_t rc2_key_bits_nr = sizeof(rc2_key_bits) / sizeof(rc2_key_bits[0]);
    kryptos_task_ctx t;
    size_t tv;
    kryptos_run_block_cipher_tests_with_custom_setup(rc2,
                                                     KRYPTOS_RC2_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     rc2_key_bits, rc2_key_bits_nr,
                                                     kryptos_rc2_setup(&t,
                                                                       rc2_test_vector[tv % rc2_key_bits_nr].key,
                                                                       rc2_test_vector[tv % rc2_key_bits_nr].key_size,
                                                                       kKryptosECB,
                                                                       &rc2_key_bits[tv % rc2_key_bits_nr].T1),
                                                     kryptos_rc2_setup(&t,
                                                                       rc2_test_vector[tv % rc2_key_bits_nr].key,
                                                                       rc2_test_vector[tv % rc2_key_bits_nr].key_size,
                                                                       kKryptosCBC,
                                                                       &rc2_key_bits[tv % rc2_key_bits_nr].T1));

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia_tests)
    struct camellia_key_size {
        kryptos_camellia_keysize_t size;
    };
    struct camellia_key_size key_size[] = {
        { kKryptosCAMELLIA128 }, { kKryptosCAMELLIA128 }, { kKryptosCAMELLIA128 }, { kKryptosCAMELLIA128 },
        { kKryptosCAMELLIA128 }, { kKryptosCAMELLIA128 }, { kKryptosCAMELLIA128 }, { kKryptosCAMELLIA128 },
        { kKryptosCAMELLIA192 }, { kKryptosCAMELLIA192 }, { kKryptosCAMELLIA192 }, { kKryptosCAMELLIA192 },
        { kKryptosCAMELLIA192 }, { kKryptosCAMELLIA192 }, { kKryptosCAMELLIA192 }, { kKryptosCAMELLIA192 },
        { kKryptosCAMELLIA192 }, { kKryptosCAMELLIA256 }, { kKryptosCAMELLIA256 }, { kKryptosCAMELLIA256 },
        { kKryptosCAMELLIA256 }, { kKryptosCAMELLIA256 }, { kKryptosCAMELLIA256 }, { kKryptosCAMELLIA256 },
        { kKryptosCAMELLIA256 }, { kKryptosCAMELLIA256 }
    };
    size_t key_size_nr = sizeof(key_size) / sizeof(key_size[0]);
    kryptos_task_ctx t;
    size_t tv;
    kryptos_run_block_cipher_tests_with_custom_setup(camellia,
                                                     KRYPTOS_CAMELLIA_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     key_size, key_size_nr,
                                                     kryptos_camellia_setup(&t,
                                                                            camellia_test_vector[tv % key_size_nr].key,
                                                                            camellia_test_vector[tv % key_size_nr].key_size,
                                                                            kKryptosECB,
                                                                            &key_size[tv % key_size_nr].size),
                                                     kryptos_camellia_setup(&t,
                                                                            camellia_test_vector[tv % key_size_nr].key,
                                                                            camellia_test_vector[tv % key_size_nr].key_size,
                                                                            kKryptosCBC,
                                                                            &key_size[tv % key_size_nr].size));

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_cast5_tests)
    kryptos_run_block_cipher_tests(cast5, KRYPTOS_CAST5_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_saferk64_tests)
    struct saferk64_rounds {
        int n;
    };
    struct saferk64_rounds rounds[] = {
        { 6 }, { 6 }, { 6 }, { 6 }
    };
    size_t rounds_nr = sizeof(rounds) / sizeof(rounds[0]);
    kryptos_task_ctx t;
    size_t tv;
    kryptos_run_block_cipher_tests_with_custom_setup(saferk64,
                                                     KRYPTOS_SAFERK64_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     rounds, rounds_nr,
                                                     kryptos_saferk64_setup(&t,
                                                                            saferk64_test_vector[tv % rounds_nr].key,
                                                                            saferk64_test_vector[tv % rounds_nr].key_size,
                                                                            kKryptosECB,
                                                                            &rounds[tv % rounds_nr].n),
                                                     kryptos_saferk64_setup(&t,
                                                                            saferk64_test_vector[tv % rounds_nr].key,
                                                                            saferk64_test_vector[tv % rounds_nr].key_size,
                                                                            kKryptosCBC,
                                                                            &rounds[tv % rounds_nr].n));

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes_tests)
    kryptos_run_block_cipher_tests(aes, KRYPTOS_AES_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_serpent_tests)
    kryptos_run_block_cipher_tests(serpent, KRYPTOS_SERPENT_BLOCKSIZE);
CUTE_TEST_CASE_END

// INFO(Rafael): End of the block cipher testing area.

CUTE_TEST_CASE(kryptos_apply_iv_tests)
    kryptos_u8_t *iv = NULL;
    kryptos_u8_t *block = NULL;
    size_t s = 27;
    iv = (kryptos_u8_t *) kryptos_newseg(s + 1);
    CUTE_ASSERT(iv != NULL);
    strncpy(iv, "rofginkoolerautahtsdiordeht", s);
    block = (kryptos_u8_t *) kryptos_newseg(s);
    CUTE_ASSERT(block != NULL);
    strncpy(block, "thedroidsthatuarelookingfor", s);
    CUTE_ASSERT(kryptos_apply_iv(block, iv, s) == block);
    CUTE_ASSERT(kryptos_apply_iv(block, iv, s) == block);
    CUTE_ASSERT(memcmp(block, "thedroidsthatuarelookingfor", 27) == 0);
    kryptos_freeseg(iv);
    kryptos_freeseg(block);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_iv_data_flush_tests)
    kryptos_u8_t *y = "hellyeah!";
    kryptos_u8_t *iv = kryptos_newseg(9);
    size_t s = 9;
    CUTE_ASSERT(iv != NULL);
    kryptos_iv_data_flush(iv, y, s);
    CUTE_ASSERT(memcmp(iv, "hellyeah!", s) == 0);
    kryptos_freeseg(iv);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_base64_tests)
    kryptos_task_ctx t, *ktask = &t;

    struct base64_test {
        kryptos_u8_t *in;
        size_t in_size;
        kryptos_u8_t *out;
        size_t out_size;
    };

    struct base64_test test_vector[] = {
        {      "f", 1,     "Zg==", 4 },
        {     "fo", 2,     "Zm8=", 4 },
        {    "foo", 3,     "Zm9v", 4 },
        {   "foob", 4, "Zm9vYg==", 8 },
        {  "fooba", 5, "Zm9vYmE=", 8 },
        { "foobar", 6, "Zm9vYmFy", 8 }
    }; // INFO(Rafael): Test data from RFC-4648.

    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);

    t.encoder = kKryptosEncodingBASE64;

    for (tv = 0; tv < tv_nr; tv++) {
        t.in = test_vector[tv].in;
        t.in_size = test_vector[tv].in_size;
        kryptos_task_set_encode_action(ktask);
        kryptos_base64_processor(&ktask);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[tv].out_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].out, t.out_size) == 0);

        t.in = t.out;
        t.in_size = t.out_size;
        kryptos_task_set_decode_action(ktask);
        kryptos_base64_processor(&ktask);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[tv].in_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].in, t.out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_uuencode_tests)
    kryptos_task_ctx t, *ktask = &t;

    struct uuencode_test {
        kryptos_u8_t *in;
        kryptos_u8_t in_size;
        kryptos_u8_t *out;
        kryptos_u8_t out_size;
    };

    struct uuencode_test test_vector[] = {
        { "ABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABCABC", 60,
          "M04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#04)#\n"
          "/04)#04)#04)#04)#04)#\n"
          "`\n", 86 }
    };

    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t *out;
    size_t out_size;

    t.encoder = kKryptosEncodingUUENCODE;

    for (tv = 0; tv < tv_nr; tv++) {
        t.in = test_vector[tv].in;
        t.in_size = test_vector[tv].in_size;
        kryptos_task_set_encode_action(ktask);
        kryptos_uuencode_processor(&ktask);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[tv].out_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].out, t.out_size) == 0);

        t.in = t.out;
        t.in_size = t.out_size;
        kryptos_task_set_decode_action(ktask);
        kryptos_uuencode_processor(&ktask);
        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == test_vector[tv].in_size);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].in, t.out_size) == 0);

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hex_tests)
    struct test_ctx {
        kryptos_u32_t value;
        kryptos_u8_t *expected;
    };
    struct test_ctx tv[] = {
        { 0x00000000, "00000000" },
        { 0x11000000, "11000000" },
        { 0x22000000, "22000000" },
        { 0x33000000, "33000000" },
        { 0x44000000, "44000000" },
        { 0x55000000, "55000000" },
        { 0x66000000, "66000000" },
        { 0x77000000, "77000000" },
        { 0x88000000, "88000000" },
        { 0x99000000, "99000000" },
        { 0xAA000000, "AA000000" },
        { 0xBB000000, "BB000000" },
        { 0xCC000000, "CC000000" },
        { 0xDD000000, "DD000000" },
        { 0xEE000000, "EE000000" },
        { 0xFF000000, "FF000000" },
        { 0x00110000, "00110000" },
        { 0x00220000, "00220000" },
        { 0x00330000, "00330000" },
        { 0x00440000, "00440000" },
        { 0x00550000, "00550000" },
        { 0x00660000, "00660000" },
        { 0x00770000, "00770000" },
        { 0x00880000, "00880000" },
        { 0x00990000, "00990000" },
        { 0x00AA0000, "00AA0000" },
        { 0x00BB0000, "00BB0000" },
        { 0x00CC0000, "00CC0000" },
        { 0x00DD0000, "00DD0000" },
        { 0x00EE0000, "00EE0000" },
        { 0x00FF0000, "00FF0000" },
        { 0x00001100, "00001100" },
        { 0x00002200, "00002200" },
        { 0x00003300, "00003300" },
        { 0x00004400, "00004400" },
        { 0x00005500, "00005500" },
        { 0x00006600, "00006600" },
        { 0x00007700, "00007700" },
        { 0x00008800, "00008800" },
        { 0x00009900, "00009900" },
        { 0x0000AA00, "0000AA00" },
        { 0x0000BB00, "0000BB00" },
        { 0x0000CC00, "0000CC00" },
        { 0x0000DD00, "0000DD00" },
        { 0x0000EE00, "0000EE00" },
        { 0x0000FF00, "0000FF00" },
        { 0x00000011, "00000011" },
        { 0x00000022, "00000022" },
        { 0x00000033, "00000033" },
        { 0x00000044, "00000044" },
        { 0x00000055, "00000055" },
        { 0x00000066, "00000066" },
        { 0x00000077, "00000077" },
        { 0x00000088, "00000088" },
        { 0x00000099, "00000099" },
        { 0x000000AA, "000000AA" },
        { 0x000000BB, "000000BB" },
        { 0x000000CC, "000000CC" },
        { 0x000000DD, "000000DD" },
        { 0x000000EE, "000000EE" },
        { 0x000000FF, "000000FF" }
    };
    size_t tv_nr = sizeof(tv) / sizeof(tv[0]), t;
    kryptos_u8_t buf[9];
    for (t = 0; t < tv_nr; t++) {
        kryptos_u32_to_hex(buf, sizeof(buf), tv[t].value);
        CUTE_ASSERT(strcmp(buf, tv[t].expected) == 0);
    }
CUTE_TEST_CASE_END

// INFO(Rafael): Hash validation area.

CUTE_TEST_CASE(kryptos_sha1_tests)
    kryptos_run_hash_tests(sha1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha224_tests)
    kryptos_run_hash_tests(sha224);
CUTE_TEST_CASE_END

// INFO(Rafael): End of hash validation area.

CUTE_TEST_CASE(kryptos_test_monkey)
    // CLUE(Rafael): Before adding a new test try to find out the best place that it fits.
    //               At first glance you should consider the utility that it implements into the library.

    // INFO(Rafael): Generic/shared stuff.
    CUTE_RUN_TEST(kryptos_padding_tests);
    CUTE_RUN_TEST(kryptos_get_random_block_tests);
    CUTE_RUN_TEST(kryptos_block_parser_tests);
    CUTE_RUN_TEST(kryptos_endianess_utils_tests);
    CUTE_RUN_TEST(kryptos_apply_iv_tests);
    CUTE_RUN_TEST(kryptos_iv_data_flush_tests);
    CUTE_RUN_TEST(kryptos_task_check_tests);
    CUTE_RUN_TEST(kryptos_hex_tests);

    // INFO(Rafael): Cipher validation using official test vectors.
    CUTE_RUN_TEST(kryptos_arc4_tests);
    CUTE_RUN_TEST(kryptos_seal_tests);
    CUTE_RUN_TEST(kryptos_des_tests);
    CUTE_RUN_TEST(kryptos_idea_tests);
    CUTE_RUN_TEST(kryptos_blowfish_tests);
    CUTE_RUN_TEST(kryptos_feal_tests);
    CUTE_RUN_TEST(kryptos_rc2_tests);
    CUTE_RUN_TEST(kryptos_camellia_tests);
    CUTE_RUN_TEST(kryptos_cast5_tests);
    CUTE_RUN_TEST(kryptos_saferk64_tests);
    CUTE_RUN_TEST(kryptos_aes_tests);
    CUTE_RUN_TEST(kryptos_serpent_tests);

    // INFO(Rafael): Hash validation.
    CUTE_RUN_TEST(kryptos_sha1_tests);
    CUTE_RUN_TEST(kryptos_sha224_tests);

    //  -=-=-=-=- If you have just added a new cipher take a look in "kryptos_dsl_tests" case, there is some work to
    //                                               be done there too! -=-=-=-=-=-=-

    // INFO(Rafael): Internal DSL stuff.
    CUTE_RUN_TEST(kryptos_dsl_tests);


    // INFO(Rafael): Encoding stuff.
    CUTE_RUN_TEST(kryptos_base64_tests);
    CUTE_RUN_TEST(kryptos_uuencode_tests);

CUTE_TEST_CASE_END

CUTE_MAIN(kryptos_test_monkey);
