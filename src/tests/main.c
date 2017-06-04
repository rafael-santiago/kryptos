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
#include <kryptos_hash_common.h>
#include <kryptos_huffman.h>
#include <kryptos_mp.h>
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
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;

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
        // WARN(Rafael): This is bad. Avoid it. If you have freed every single trinket that you alloc'd,
        //               you should have no fear. ;) The Leak System is your friend or supposed to be...
        printf("=== WARN: The leak check system is deactivated, due to it was not possible test the kryptos_task_free() macro."
               " It was SKIPPED.\n===\n");
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

    // TRIPLE-DES ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    triple_des_key2 = "noel";
    triple_des_key2_size = 4;
    triple_des_key3 = "mitch";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, &task, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(triple_des, &task, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TRIPLE-DES CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, &task, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(triple_des, &task, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES EDE ECB

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    triple_des_key2 = "noel";
    triple_des_key2_size = 4;
    triple_des_key3 = "mitch";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, &task, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(triple_des_ede, &task, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(task.out_size == data_size);
    CUTE_ASSERT(memcmp(task.out, data, task.out_size) == 0);
    kryptos_task_free(&task, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TRIPLE-DES EDE CBC

    kryptos_task_set_in(&task, data, data_size);
    kryptos_task_set_encrypt_action(&task);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, &task, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(task.out != NULL);

    kryptos_task_set_in(&task, task.out, task.out_size);
    kryptos_task_set_decrypt_action(&task);

    kryptos_run_cipher(triple_des_ede, &task, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

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
    kryptos_u32_t deadbeef = 0;
    kryptos_u16_t beef = 0;
    kryptos_u64_t deadbeefdeadbeef = 0;

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

    data = (kryptos_u8_t *)kryptos_newseg(8);
    CUTE_ASSERT(data != NULL);
    deadbeefdeadbeef = 0xdeadbeefdeadbeef;
    memset(data, 0, 8);
    data = kryptos_cpy_u64_as_big_endian(data, 8, deadbeefdeadbeef);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(      *data == 0xde && *(data + 1) == 0xad && *(data + 2) == 0xbe && *(data + 3) == 0xef &&
                *(data + 4) == 0xde && *(data + 5) == 0xad && *(data + 6) == 0xbe && *(data + 7) == 0xef);
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
                                                                        &feal_rounds[tv % feal_rounds_nr].rounds),
                                                     kryptos_feal_setup(&t,
                                                                        feal_test_vector[tv % feal_rounds_nr].key,
                                                                        feal_test_vector[tv % feal_rounds_nr].key_size,
                                                                        kKryptosOFB,
                                                                        &feal_rounds[tv % feal_rounds_nr].rounds));
    // INFO(Rafael): The last three parameters of kryptos_run_block_cipher_test_with_custom_setup()
    //               are related with the exact cipher setup call that must be executed on the test step.
    //               ECB, CBC and OFB tests respectively.
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
                                                                       &rc2_key_bits[tv % rc2_key_bits_nr].T1),
                                                     kryptos_rc2_setup(&t,
                                                                       rc2_test_vector[tv % rc2_key_bits_nr].key,
                                                                       rc2_test_vector[tv % rc2_key_bits_nr].key_size,
                                                                       kKryptosOFB,
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
                                                                            &key_size[tv % key_size_nr].size),
                                                     kryptos_camellia_setup(&t,
                                                                            camellia_test_vector[tv % key_size_nr].key,
                                                                            camellia_test_vector[tv % key_size_nr].key_size,
                                                                            kKryptosOFB,
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
                                                                            &rounds[tv % rounds_nr].n),
                                                     kryptos_saferk64_setup(&t,
                                                                            saferk64_test_vector[tv % rounds_nr].key,
                                                                            saferk64_test_vector[tv % rounds_nr].key_size,
                                                                            kKryptosOFB,
                                                                            &rounds[tv % rounds_nr].n));

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes_tests)
    kryptos_run_block_cipher_tests(aes, KRYPTOS_AES_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_serpent_tests)
    kryptos_run_block_cipher_tests(serpent, KRYPTOS_SERPENT_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_tests)
    struct triple_des_additional_keys {
        kryptos_u8_t *key2;
        size_t key2_size;
        kryptos_u8_t *key3;
        size_t key3_size;
    };
    struct triple_des_additional_keys addkeys[] = {
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 }
    };
    size_t addkeys_nr = sizeof(addkeys) / sizeof(addkeys[0]);
    kryptos_task_ctx t;
    size_t tv;
    kryptos_run_block_cipher_tests_with_custom_setup(triple_des,
                                                     KRYPTOS_DES_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     key_size, key_size_nr,
                                                     kryptos_triple_des_setup(&t,
                                                                              triple_des_test_vector[tv % addkeys_nr].key,
                                                                              triple_des_test_vector[tv % addkeys_nr].key_size,
                                                                              kKryptosECB,
                                                                              addkeys[tv % addkeys_nr].key2,
                                                                              &addkeys[tv % addkeys_nr].key2_size,
                                                                              addkeys[tv % addkeys_nr].key3,
                                                                              &addkeys[tv % addkeys_nr].key3_size),
                                                     kryptos_triple_des_setup(&t,
                                                                              triple_des_test_vector[tv % addkeys_nr].key,
                                                                              triple_des_test_vector[tv % addkeys_nr].key_size,
                                                                              kKryptosCBC,
                                                                              addkeys[tv % addkeys_nr].key2,
                                                                              &addkeys[tv % addkeys_nr].key2_size,
                                                                              addkeys[tv % addkeys_nr].key3,
                                                                              &addkeys[tv % addkeys_nr].key3_size),
                                                     kryptos_triple_des_setup(&t,
                                                                              triple_des_test_vector[tv % addkeys_nr].key,
                                                                              triple_des_test_vector[tv % addkeys_nr].key_size,
                                                                              kKryptosOFB,
                                                                              addkeys[tv % addkeys_nr].key2,
                                                                              &addkeys[tv % addkeys_nr].key2_size,
                                                                              addkeys[tv % addkeys_nr].key3,
                                                                              &addkeys[tv % addkeys_nr].key3_size));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_ede_tests)
    struct triple_des_additional_keys {
        kryptos_u8_t *key2;
        size_t key2_size;
        kryptos_u8_t *key3;
        size_t key3_size;
    };
    struct triple_des_additional_keys addkeys[] = {
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x80\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x40\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x20\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x10\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x00\x00\x00\x00\x00\x00\x00\x00", 8, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
        { "\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 8, "\x10\x11\x12\x13\x14\x15\x16\x17", 8 },
        { "\x95\x2C\x49\x10\x48\x81\xFF\x48", 8, "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00", 8 }
    };
    size_t addkeys_nr = sizeof(addkeys) / sizeof(addkeys[0]);
    kryptos_task_ctx t;
    size_t tv;
    kryptos_run_block_cipher_tests_with_custom_setup(triple_des_ede,
                                                     KRYPTOS_DES_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     key_size, key_size_nr,
                                                     kryptos_triple_des_ede_setup(&t,
                                                                          triple_des_ede_test_vector[tv % addkeys_nr].key,
                                                                          triple_des_ede_test_vector[tv % addkeys_nr].key_size,
                                                                          kKryptosECB,
                                                                          addkeys[tv % addkeys_nr].key2,
                                                                          &addkeys[tv % addkeys_nr].key2_size,
                                                                          addkeys[tv % addkeys_nr].key3,
                                                                          &addkeys[tv % addkeys_nr].key3_size),
                                                     kryptos_triple_des_ede_setup(&t,
                                                                          triple_des_ede_test_vector[tv % addkeys_nr].key,
                                                                          triple_des_ede_test_vector[tv % addkeys_nr].key_size,
                                                                          kKryptosCBC,
                                                                          addkeys[tv % addkeys_nr].key2,
                                                                          &addkeys[tv % addkeys_nr].key2_size,
                                                                          addkeys[tv % addkeys_nr].key3,
                                                                          &addkeys[tv % addkeys_nr].key3_size),
                                                     kryptos_triple_des_ede_setup(&t,
                                                                          triple_des_ede_test_vector[tv % addkeys_nr].key,
                                                                          triple_des_ede_test_vector[tv % addkeys_nr].key_size,
                                                                          kKryptosOFB,
                                                                          addkeys[tv % addkeys_nr].key2,
                                                                          &addkeys[tv % addkeys_nr].key2_size,
                                                                          addkeys[tv % addkeys_nr].key3,
                                                                          &addkeys[tv % addkeys_nr].key3_size));
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
        kryptos_u32_t u32;
        kryptos_u8_t *u32_expected;
        kryptos_u64_t u64;
        kryptos_u8_t *u64_expected;
    };
    struct test_ctx tv[] = {
        { 0x00000000, "00000000", 0x0000000000000000, "0000000000000000" },
        { 0x11000000, "11000000", 0x1100000000000000, "1100000000000000" },
        { 0x22000000, "22000000", 0x2200000000000000, "2200000000000000" },
        { 0x33000000, "33000000", 0x3300000000000000, "3300000000000000" },
        { 0x44000000, "44000000", 0x4400000000000000, "4400000000000000" },
        { 0x55000000, "55000000", 0x5500000000000000, "5500000000000000" },
        { 0x66000000, "66000000", 0x6600000000000000, "6600000000000000" },
        { 0x77000000, "77000000", 0x7700000000000000, "7700000000000000" },
        { 0x88000000, "88000000", 0x8800000000000000, "8800000000000000" },
        { 0x99000000, "99000000", 0x9900000000000000, "9900000000000000" },
        { 0xAA000000, "AA000000", 0xAA00000000000000, "AA00000000000000" },
        { 0xBB000000, "BB000000", 0xBB00000000000000, "BB00000000000000" },
        { 0xCC000000, "CC000000", 0xCC00000000000000, "CC00000000000000" },
        { 0xDD000000, "DD000000", 0xDD00000000000000, "DD00000000000000" },
        { 0xEE000000, "EE000000", 0xEE00000000000000, "EE00000000000000" },
        { 0xFF000000, "FF000000", 0xFF00000000000000, "FF00000000000000" },
        { 0x00110000, "00110000", 0x0011000000000000, "0011000000000000" },
        { 0x00220000, "00220000", 0x0022000000000000, "0022000000000000" },
        { 0x00330000, "00330000", 0x0033000000000000, "0033000000000000" },
        { 0x00440000, "00440000", 0x0044000000000000, "0044000000000000" },
        { 0x00550000, "00550000", 0x0055000000000000, "0055000000000000" },
        { 0x00660000, "00660000", 0x0066000000000000, "0066000000000000" },
        { 0x00770000, "00770000", 0x0077000000000000, "0077000000000000" },
        { 0x00880000, "00880000", 0x0088000000000000, "0088000000000000" },
        { 0x00990000, "00990000", 0x0099000000000000, "0099000000000000" },
        { 0x00AA0000, "00AA0000", 0x00AA000000000000, "00AA000000000000" },
        { 0x00BB0000, "00BB0000", 0x00BB000000000000, "00BB000000000000" },
        { 0x00CC0000, "00CC0000", 0x00CC000000000000, "00CC000000000000" },
        { 0x00DD0000, "00DD0000", 0x00DD000000000000, "00DD000000000000" },
        { 0x00EE0000, "00EE0000", 0x00EE000000000000, "00EE000000000000" },
        { 0x00FF0000, "00FF0000", 0x00FF000000000000, "00FF000000000000" },
        { 0x00001100, "00001100", 0x0000110000000000, "0000110000000000" },
        { 0x00002200, "00002200", 0x0000220000000000, "0000220000000000" },
        { 0x00003300, "00003300", 0x0000330000000000, "0000330000000000" },
        { 0x00004400, "00004400", 0x0000440000000000, "0000440000000000" },
        { 0x00005500, "00005500", 0x0000550000000000, "0000550000000000" },
        { 0x00006600, "00006600", 0x0000660000000000, "0000660000000000" },
        { 0x00007700, "00007700", 0x0000770000000000, "0000770000000000" },
        { 0x00008800, "00008800", 0x0000880000000000, "0000880000000000" },
        { 0x00009900, "00009900", 0x0000990000000000, "0000990000000000" },
        { 0x0000AA00, "0000AA00", 0x0000AA0000000000, "0000AA0000000000" },
        { 0x0000BB00, "0000BB00", 0x0000BB0000000000, "0000BB0000000000" },
        { 0x0000CC00, "0000CC00", 0x0000CC0000000000, "0000CC0000000000" },
        { 0x0000DD00, "0000DD00", 0x0000DD0000000000, "0000DD0000000000" },
        { 0x0000EE00, "0000EE00", 0x0000EE0000000000, "0000EE0000000000" },
        { 0x0000FF00, "0000FF00", 0x0000FF0000000000, "0000FF0000000000" },
        { 0x00000011, "00000011", 0x0000001100000000, "0000001100000000" },
        { 0x00000022, "00000022", 0x0000002200000000, "0000002200000000" },
        { 0x00000033, "00000033", 0x0000003300000000, "0000003300000000" },
        { 0x00000044, "00000044", 0x0000004400000000, "0000004400000000" },
        { 0x00000055, "00000055", 0x0000005500000000, "0000005500000000" },
        { 0x00000066, "00000066", 0x0000006600000000, "0000006600000000" },
        { 0x00000077, "00000077", 0x0000007700000000, "0000007700000000" },
        { 0x00000088, "00000088", 0x0000008800000000, "0000008800000000" },
        { 0x00000099, "00000099", 0x0000009900000000, "0000009900000000" },
        { 0x000000AA, "000000AA", 0x000000AA00000000, "000000AA00000000" },
        { 0x000000BB, "000000BB", 0x000000BB00000000, "000000BB00000000" },
        { 0x000000CC, "000000CC", 0x000000CC00000000, "000000CC00000000" },
        { 0x000000DD, "000000DD", 0x000000DD00000000, "000000DD00000000" },
        { 0x000000EE, "000000EE", 0x000000EE00000000, "000000EE00000000" },
        { 0x000000FF, "000000FF", 0x000000FF00000000, "000000FF00000000" },
        { 0x00000000, "00000000", 0x0000000011000000, "0000000011000000" },
        { 0x00000000, "00000000", 0x0000000022000000, "0000000022000000" },
        { 0x00000000, "00000000", 0x0000000033000000, "0000000033000000" },
        { 0x00000000, "00000000", 0x0000000044000000, "0000000044000000" },
        { 0x00000000, "00000000", 0x0000000055000000, "0000000055000000" },
        { 0x00000000, "00000000", 0x0000000066000000, "0000000066000000" },
        { 0x00000000, "00000000", 0x0000000077000000, "0000000077000000" },
        { 0x00000000, "00000000", 0x0000000088000000, "0000000088000000" },
        { 0x00000000, "00000000", 0x0000000099000000, "0000000099000000" },
        { 0x00000000, "00000000", 0x00000000AA000000, "00000000AA000000" },
        { 0x00000000, "00000000", 0x00000000BB000000, "00000000BB000000" },
        { 0x00000000, "00000000", 0x00000000CC000000, "00000000CC000000" },
        { 0x00000000, "00000000", 0x00000000DD000000, "00000000DD000000" },
        { 0x00000000, "00000000", 0x00000000EE000000, "00000000EE000000" },
        { 0x00000000, "00000000", 0x00000000FF000000, "00000000FF000000" },
        { 0x00000000, "00000000", 0x0000000000110000, "0000000000110000" },
        { 0x00000000, "00000000", 0x0000000000220000, "0000000000220000" },
        { 0x00000000, "00000000", 0x0000000000330000, "0000000000330000" },
        { 0x00000000, "00000000", 0x0000000000440000, "0000000000440000" },
        { 0x00000000, "00000000", 0x0000000000550000, "0000000000550000" },
        { 0x00000000, "00000000", 0x0000000000660000, "0000000000660000" },
        { 0x00000000, "00000000", 0x0000000000770000, "0000000000770000" },
        { 0x00000000, "00000000", 0x0000000000880000, "0000000000880000" },
        { 0x00000000, "00000000", 0x0000000000990000, "0000000000990000" },
        { 0x00000000, "00000000", 0x0000000000AA0000, "0000000000AA0000" },
        { 0x00000000, "00000000", 0x0000000000BB0000, "0000000000BB0000" },
        { 0x00000000, "00000000", 0x0000000000CC0000, "0000000000CC0000" },
        { 0x00000000, "00000000", 0x0000000000DD0000, "0000000000DD0000" },
        { 0x00000000, "00000000", 0x0000000000EE0000, "0000000000EE0000" },
        { 0x00000000, "00000000", 0x0000000000FF0000, "0000000000FF0000" },
        { 0x00000000, "00000000", 0x0000000000001100, "0000000000001100" },
        { 0x00000000, "00000000", 0x0000000000002200, "0000000000002200" },
        { 0x00000000, "00000000", 0x0000000000003300, "0000000000003300" },
        { 0x00000000, "00000000", 0x0000000000004400, "0000000000004400" },
        { 0x00000000, "00000000", 0x0000000000005500, "0000000000005500" },
        { 0x00000000, "00000000", 0x0000000000006600, "0000000000006600" },
        { 0x00000000, "00000000", 0x0000000000007700, "0000000000007700" },
        { 0x00000000, "00000000", 0x0000000000008800, "0000000000008800" },
        { 0x00000000, "00000000", 0x0000000000009900, "0000000000009900" },
        { 0x00000000, "00000000", 0x000000000000AA00, "000000000000AA00" },
        { 0x00000000, "00000000", 0x000000000000BB00, "000000000000BB00" },
        { 0x00000000, "00000000", 0x000000000000CC00, "000000000000CC00" },
        { 0x00000000, "00000000", 0x000000000000DD00, "000000000000DD00" },
        { 0x00000000, "00000000", 0x000000000000EE00, "000000000000EE00" },
        { 0x00000000, "00000000", 0x000000000000FF00, "000000000000FF00" },
        { 0x00000000, "00000000", 0x0000000000000011, "0000000000000011" },
        { 0x00000000, "00000000", 0x0000000000000022, "0000000000000022" },
        { 0x00000000, "00000000", 0x0000000000000033, "0000000000000033" },
        { 0x00000000, "00000000", 0x0000000000000044, "0000000000000044" },
        { 0x00000000, "00000000", 0x0000000000000055, "0000000000000055" },
        { 0x00000000, "00000000", 0x0000000000000066, "0000000000000066" },
        { 0x00000000, "00000000", 0x0000000000000077, "0000000000000077" },
        { 0x00000000, "00000000", 0x0000000000000088, "0000000000000088" },
        { 0x00000000, "00000000", 0x0000000000000099, "0000000000000099" },
        { 0x00000000, "00000000", 0x00000000000000AA, "00000000000000AA" },
        { 0x00000000, "00000000", 0x00000000000000BB, "00000000000000BB" },
        { 0x00000000, "00000000", 0x00000000000000CC, "00000000000000CC" },
        { 0x00000000, "00000000", 0x00000000000000DD, "00000000000000DD" },
        { 0x00000000, "00000000", 0x00000000000000EE, "00000000000000EE" },
        { 0x00000000, "00000000", 0x00000000000000FF, "00000000000000FF" },
    };
    size_t tv_nr = sizeof(tv) / sizeof(tv[0]), t;
    kryptos_u8_t buf[9];
    for (t = 0; t < tv_nr; t++) {
        kryptos_u32_to_hex(buf, sizeof(buf), tv[t].u32);
        CUTE_ASSERT(strcmp(buf, tv[t].u32_expected) == 0);
        kryptos_u64_to_hex(buf, sizeof(buf), tv[t].u64);
        CUTE_ASSERT(strcmp(buf, tv[t].u64_expected) == 0);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hash_common_tests)
    size_t index_decision_table32[] = {
         0,  0,  0,  0,
         1,  1,  1,  1,
         2,  2,  2,  2,
         3,  3,  3,  3,
         4,  4,  4,  4,
         5,  5,  5,  5,
         6,  6,  6,  6,
         7,  7,  7,  7,
         8,  8,  8,  8,
         9,  9,  9,  9,
        10, 10, 10, 10,
        11, 11, 11, 11,
        12, 12, 12, 12,
        13, 13, 13, 13,
        14, 14, 14, 14,
        15, 15, 15, 15
    };
    kryptos_u32_t u32_input[16];
    size_t index_decision_table64[] = {
         0,  0,  0,  0,  0,  0,  0,  0,
         1,  1,  1,  1,  1,  1,  1,  1,
         2,  2,  2,  2,  2,  2,  2,  2,
         3,  3,  3,  3,  3,  3,  3,  3,
         4,  4,  4,  4,  4,  4,  4,  4,
         5,  5,  5,  5,  5,  5,  5,  5,
         6,  6,  6,  6,  6,  6,  6,  6,
         7,  7,  7,  7,  7,  7,  7,  7,
         8,  8,  8,  8,  8,  8,  8,  8,
         9,  9,  9,  9,  9,  9,  9,  9,
        10, 10, 10, 10, 10, 10, 10, 10,
        11, 11, 11, 11, 11, 11, 11, 11,
        12, 12, 12, 12, 12, 12, 12, 12,
        13, 13, 13, 13, 13, 13, 13, 13,
        14, 14, 14, 14, 14, 14, 14, 14,
        15, 15, 15, 15, 15, 15, 15, 15
    };
    kryptos_u64_t u64_input[16];
    kryptos_u64_t curr_len, total_len;
    int paddin2times = 0;

    kryptos_hash_ld_u8buf_as_u32_blocks("abc", 3,
                                        u32_input, 16,
                                        index_decision_table32);

    CUTE_ASSERT(u32_input[ 0] == 0x616263);
    CUTE_ASSERT(u32_input[ 1] == 0x0);
    CUTE_ASSERT(u32_input[ 2] == 0x0);
    CUTE_ASSERT(u32_input[ 3] == 0x0);
    CUTE_ASSERT(u32_input[ 4] == 0x0);
    CUTE_ASSERT(u32_input[ 5] == 0x0);
    CUTE_ASSERT(u32_input[ 6] == 0x0);
    CUTE_ASSERT(u32_input[ 7] == 0x0);
    CUTE_ASSERT(u32_input[ 8] == 0x0);
    CUTE_ASSERT(u32_input[ 9] == 0x0);
    CUTE_ASSERT(u32_input[10] == 0x0);
    CUTE_ASSERT(u32_input[11] == 0x0);
    CUTE_ASSERT(u32_input[12] == 0x0);
    CUTE_ASSERT(u32_input[13] == 0x0);
    CUTE_ASSERT(u32_input[14] == 0x0);
    CUTE_ASSERT(u32_input[15] == 0x0);

    curr_len = 3;
    total_len = 24;

    kryptos_hash_apply_pad_on_u32_block(u32_input, 16,
                                        index_decision_table32,
                                        curr_len, total_len,
                                        &paddin2times, 56);

    CUTE_ASSERT(u32_input[ 0] == 0x61626380);
    CUTE_ASSERT(u32_input[ 1] == 0x0);
    CUTE_ASSERT(u32_input[ 2] == 0x0);
    CUTE_ASSERT(u32_input[ 3] == 0x0);
    CUTE_ASSERT(u32_input[ 4] == 0x0);
    CUTE_ASSERT(u32_input[ 5] == 0x0);
    CUTE_ASSERT(u32_input[ 6] == 0x0);
    CUTE_ASSERT(u32_input[ 7] == 0x0);
    CUTE_ASSERT(u32_input[ 8] == 0x0);
    CUTE_ASSERT(u32_input[ 9] == 0x0);
    CUTE_ASSERT(u32_input[10] == 0x0);
    CUTE_ASSERT(u32_input[11] == 0x0);
    CUTE_ASSERT(u32_input[12] == 0x0);
    CUTE_ASSERT(u32_input[13] == 0x0);
    CUTE_ASSERT(u32_input[14] == 0x0);
    CUTE_ASSERT(u32_input[15] == 0x18);


    curr_len = 56;
    total_len = 24;
    paddin2times = 0;

    kryptos_hash_apply_pad_on_u32_block(u32_input, 16,
                                        index_decision_table32,
                                        curr_len, total_len,
                                        &paddin2times, 56);
    CUTE_ASSERT(paddin2times == 1);

    paddin2times = 0;

    kryptos_hash_ld_u8buf_as_u64_blocks("abc", 3,
                                        u64_input, 16,
                                        index_decision_table64);

    CUTE_ASSERT(u64_input[ 0] == 0x616263);
    CUTE_ASSERT(u64_input[ 1] == 0x0);
    CUTE_ASSERT(u64_input[ 2] == 0x0);
    CUTE_ASSERT(u64_input[ 3] == 0x0);
    CUTE_ASSERT(u64_input[ 4] == 0x0);
    CUTE_ASSERT(u64_input[ 5] == 0x0);
    CUTE_ASSERT(u64_input[ 6] == 0x0);
    CUTE_ASSERT(u64_input[ 7] == 0x0);
    CUTE_ASSERT(u64_input[ 8] == 0x0);
    CUTE_ASSERT(u64_input[ 9] == 0x0);
    CUTE_ASSERT(u64_input[10] == 0x0);
    CUTE_ASSERT(u64_input[11] == 0x0);
    CUTE_ASSERT(u64_input[12] == 0x0);
    CUTE_ASSERT(u64_input[13] == 0x0);
    CUTE_ASSERT(u64_input[14] == 0x0);
    CUTE_ASSERT(u64_input[15] == 0x0);

    curr_len = 3;
    total_len = 24;

    kryptos_hash_apply_pad_on_u64_block(u64_input, 16,
                                        index_decision_table64,
                                        curr_len, total_len,
                                        &paddin2times, 120);

    CUTE_ASSERT(u64_input[ 0] == 0x6162638000000000);
    CUTE_ASSERT(u64_input[ 1] == 0x0);
    CUTE_ASSERT(u64_input[ 2] == 0x0);
    CUTE_ASSERT(u64_input[ 3] == 0x0);
    CUTE_ASSERT(u64_input[ 4] == 0x0);
    CUTE_ASSERT(u64_input[ 5] == 0x0);
    CUTE_ASSERT(u64_input[ 6] == 0x0);
    CUTE_ASSERT(u64_input[ 7] == 0x0);
    CUTE_ASSERT(u64_input[ 8] == 0x0);
    CUTE_ASSERT(u64_input[ 9] == 0x0);
    CUTE_ASSERT(u64_input[10] == 0x0);
    CUTE_ASSERT(u64_input[11] == 0x0);
    CUTE_ASSERT(u64_input[12] == 0x0);
    CUTE_ASSERT(u64_input[13] == 0x0);
    CUTE_ASSERT(u64_input[14] == 0x0);
    CUTE_ASSERT(u64_input[15] == 0x18);


    curr_len = 120;
    total_len = 24;
    paddin2times = 0;

    kryptos_hash_apply_pad_on_u64_block(u64_input, 16,
                                        index_decision_table64,
                                        curr_len, total_len,
                                        &paddin2times, 120);
    CUTE_ASSERT(paddin2times == 1);
CUTE_TEST_CASE_END

// INFO(Rafael): Hash validation area.

CUTE_TEST_CASE(kryptos_sha1_tests)
    kryptos_run_hash_tests(sha1, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha224_tests)
    kryptos_run_hash_tests(sha224, 64, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha256_tests)
    kryptos_run_hash_tests(sha256, 64, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha384_tests)
    kryptos_run_hash_tests(sha384, 128, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha512_tests)
    kryptos_run_hash_tests(sha512, 128, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md4_tests)
    kryptos_run_hash_tests(md4, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md5_tests)
    kryptos_run_hash_tests(md5, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd128_tests)
    kryptos_run_hash_tests(ripemd128, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd160_tests)
    kryptos_run_hash_tests(ripemd160, 64, 20);
CUTE_TEST_CASE_END

// INFO(Rafael): End of hash validation area.

CUTE_TEST_CASE(kryptos_hmac_tests)

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)
    kryptos_u8_t *key = "nooneknows";
    size_t key_size = 10;
    int feal_rounds = 8, rc2_T1 = 64, saferk64_rounds = 6;
    kryptos_camellia_keysize_t camellia_size;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha1, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md4, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md5, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd128, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd160, key, key_size, kKryptosECB, &feal_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha1, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md4, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md5, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd128, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd160, key, key_size, kKryptosCBC, &feal_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha1, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md4, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md5, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd128, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd160, key, key_size, kKryptosECB, &rc2_T1);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha1, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md4, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md5, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd128, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd160, key, key_size, kKryptosCBC, &rc2_T1);

    camellia_size = kKryptosCAMELLIA128;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);

    camellia_size = kKryptosCAMELLIA192;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);

    camellia_size = kKryptosCAMELLIA256;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha1, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md4, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md5, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd128, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd160, key, key_size, kKryptosECB, &saferk64_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha1, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md4, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md5, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd128, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd160, key, key_size, kKryptosCBC, &saferk64_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd160, key, key_size, kKryptosCBC);

    triple_des_key2 = "gowithflow";
    triple_des_key2_size = 10;
    triple_des_key3 = "hangintree";
    triple_des_key3_size = 10;
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha1, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha1, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    triple_des_key2 = "gowithflow";
    triple_des_key2_size = 10;
    triple_des_key3 = "hangintree";
    triple_des_key3_size = 10;
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha1, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha1, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
#else
# if !defined(KRYPTOS_NO_HMAC_TESTS)
    // TODO(Rafael): When there is no C99 support add a simple bare bone test with at least one block cipher and all
    //               available hash functions.
    printf("WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
# else
    printf("WARN: You have requested build this binary without the HMAC tests.\n");
# endif // !defined(KRYPTOS_SKIP_HMAC_TESTS)
#endif // defined(KRYPTOS_C99) && !defined(KRYPTOS_SKIP_HMAC_TESTS)

CUTE_TEST_CASE_END

// INFO(Rafael): End of hash validation area.

CUTE_TEST_CASE(kryptos_huffman_tests)
    kryptos_u8_t *test_vector[] = {
        "AAAAAAAAAABBBBBCCDEEEEEFFFGGGGZZZZYYXXXXXXXX",

        "ACAAGATGCCATTGTCCCCCGGCCTCCTGCTGCTGCTGCTCTCCGGGGCCACGGCCACCGCTGCCCTGCC"
        "CCTGGAGGGTGGCCCCACCGGCCGAGACAGCGAGCATATGCAGGAAGCGGCAGGAATAAGGAAAAGCAGC"
        "CTCCTGACTTTCCTCGCTTGGTGGTTTGAGTGGACCTCCCAGGCCAGTGCCGGGCCCCTCATAGGAGAGG"
        "AAGCTCGGGAGGTGGCCAGGCGGCAGGAAGGCGCACCCCCCCAGCAATCCGCGCGCCGGGACAGAATGCC"
        "CTGCAGGAACTTCTTCTGGAAGACCTTCTCCTCCTGCAAATAAAACCTCACCCATGAATGCTCACGCAAG"
        "TTTAATTACAGACCTGAA",

        "E como eu palmilhasse vagamente\n"
        "uma estrada de Minas, pedregosa,\n"
        "e no fecho da tarde um sino rouco\n\n"
        "se misturasse ao som de meus sapatos\n"
        "que era pausado e seco; e aves pairassem\n"
        "no céu de chumbo, e suas formas pretas\n\n"
        "lentamente se fossem diluindo\n"
        "na escuridão maior, vinda dos montes\n"
        "e de meu próprio ser desenganado,\n\n"
        "a máquina do mundo se entreabriu\n"
        "para quem de a romper já se esquivava\n"
        "e só de o ter pensado se carpia.\n\n"
        "Abriu-se majestosa e circunspecta,\n"
        "sem emitir um som que fosse impuro\n"
        "nem um clarão maior que o tolerável\n\n"
        "pelas pupilas gastas na inspeção\n"
        "contínua e dolorosa do deserto,\n"
        "e pela mente exausta de mentar\n\n"
        "toda uma realidade que transcende\n"
        "a própria imagem sua debuxada\n"
        "no rosto do mistério, nos abismos.\n\n"
        "Abriu-se em calma pura, e convidando\n"
        "quantos sentidos e intuições restavam\n"
        "a quem de os ter usado os já perdera\n\n"
        "e nem desejaria recobrá-los,\n"
        "se em vão e para sempre repetimos\n"
        "os mesmos sem roteiro tristes périplos,\n\n"
        "convidando-os a todos, em coorte,\n"
        "a se aplicarem sobre o pasto inédito\n"
        "da natureza mítica das coisas,\n\n"
        "assim me disse, embora voz alguma\n"
        "ou sopro ou eco ou simples percussão\n"
        "atestasse que alguém, sobre a montanha,\n\n"
        "a outro alguém, noturno e miserável,\n"
        "em colóquio se estava dirigindo:\n"
        "O que procuraste em ti ou fora de\n\n"
        "teu ser restrito e nunca se mostrou,\n"
        "mesmo afetando dar-se ou se rendendo,\n"
        "e a cada instante mais se retraindo,\n\n"
        "olha, repara, ausculta: essa riqueza\n"
        "sobrante a toda pérola, essa ciência\n"
        "sublime e formidável, mas hermética,\n\n"
        "essa total explicação da vida,\n"
        "esse nexo primeiro e singular,\n"
        "que nem concebes mais, pois tão esquivo\n\n"
        "se revelou ante a pesquisa ardente\n"
        "em que te consumiste... vê, contempla,\n"
        "abre teu peito para agasalhá-lo.\n\n"
        "As mais soberbas pontes e edifícios,\n"
        "o que nas oficinas se elabora,\n"
        "o que pensado foi e logo atinge\n\n"
        "distância superior ao pensamento,\n"
        "os recursos da terra dominados,\n"
        "e as paixões e os impulsos e os tormentos\n\n"
        "e tudo que define o ser terrestre\n"
        "ou se prolonga até nos animais\n"
        "e chega às plantas para se embeber\n\n"
        "no sono rancoroso dos minérios,\n"
        "dá volta ao mundo e torna a se engolfar,\n"
        "na estranha ordem geométrica de tudo,\n\n"
        "e o absurdo original e seus enigmas,\n"
        "suas verdades altas mais que todos\n"
        "monumentos erguidos à verdade:\n\n"
        "e a memória dos deuses, e o solene\n"
        "sentimento de morte, que floresce\n"
        "no caule da existência mais gloriosa,\n\n"
        "tudo se apresentou nesse relance\n"
        "e me chamou para seu reino augusto,\n"
        "afinal submetido à vista humana.\n\n"
        "Mas, como eu relutasse em responder\n"
        "a tal apelo assim maravilhoso,\n"
        "pois a fé se abrandara, e mesmo o anseio,\n\n"
        "a esperança mais mínima — esse anelo\n"
        "de ver desvanecida a treva espessa\n"
        "que entre os raios do sol inda se filtra;\n\n"
        "como defuntas crenças convocadas\n"
        "presto e fremente não se produzissem\n"
        "a de novo tingir a neutra face\n\n"
        "que vou pelos caminhos demonstrando,\n"
        "e como se outro ser, não mais aquele\n"
        "habitante de mim há tantos anos,\n\n"
        "passasse a comandar minha vontade\n"
        "que, já de si volúvel, se cerrava\n"
        "semelhante a essas flores reticentes\n\n"
        "em si mesmas abertas e fechadas;\n"
        "como se um dom tardio já não fora\n"
        "apetecível, antes despiciendo,\n\n"
        "baixei os olhos, incurioso, lasso,\n"
        "desdenhando colher a coisa oferta\n"
        "que se abria gratuita a meu engenho.\n\n"
        "A treva mais estrita já pousara\n"
        "sobre a estrada de Minas, pedregosa,\n"
        "e a máquina do mundo, repelida,\n\n"
        "se foi miudamente recompondo,\n"
        "enquanto eu, avaliando o que perdera,\n"
        "seguia vagaroso, de mãos pensas.\n\n\n\n"
        "-- A Máquina do Mundo - Carlos Drummond de Andrade"
    };
    size_t tv, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    size_t in_size, deflated_buffer_size, inflated_buffer_size;
    kryptos_u8_t *deflated_buffer = NULL, *inflated_buffer = NULL;

    for (tv = 0; tv < tv_nr; tv++) {
        in_size = strlen(test_vector[tv]);
        deflated_buffer = kryptos_huffman_deflate(test_vector[tv], in_size, &deflated_buffer_size);
        CUTE_ASSERT(deflated_buffer != NULL);
        inflated_buffer = kryptos_huffman_inflate(deflated_buffer, deflated_buffer_size, &inflated_buffer_size);
        CUTE_ASSERT(inflated_buffer != NULL);
        CUTE_ASSERT(inflated_buffer_size == in_size);
        CUTE_ASSERT(memcmp(inflated_buffer, test_vector[tv], inflated_buffer_size) == 0);
        kryptos_freeseg(deflated_buffer);
        kryptos_freeseg(inflated_buffer);
    }
CUTE_TEST_CASE_END

// INFO(Rafael): Multiprecision testing area.

CUTE_TEST_CASE(kryptos_mp_new_value_tests)
    // INFO(Rafael): This test also includes kryptos_del_mp_value(). Assuming the leak-check system is enabled, of course.
    kryptos_mp_value_t *mp;
    size_t d;
    mp = kryptos_new_mp_value(1024);
    CUTE_ASSERT(mp != NULL);
    CUTE_ASSERT(mp->data != NULL);
    CUTE_ASSERT(mp->data_size == 128);
    for (d = 0; d < mp->data_size; d++) {
        CUTE_ASSERT(mp->data[d] == 0);
    }
    kryptos_del_mp_value(mp);
    // INFO(Rafael): If something is still wrong the leak system should complain.
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_hex_value_as_mp_tests)
    kryptos_mp_value_t *mp;
    mp = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    CUTE_ASSERT(mp != NULL);
    CUTE_ASSERT(mp->data_size == 16);
    CUTE_ASSERT(mp->data[ 0] == 0x99);
    CUTE_ASSERT(mp->data[ 1] == 0x88);
    CUTE_ASSERT(mp->data[ 2] == 0x77);
    CUTE_ASSERT(mp->data[ 3] == 0x66);
    CUTE_ASSERT(mp->data[ 4] == 0x55);
    CUTE_ASSERT(mp->data[ 5] == 0x44);
    CUTE_ASSERT(mp->data[ 6] == 0x33);
    CUTE_ASSERT(mp->data[ 7] == 0x22);
    CUTE_ASSERT(mp->data[ 8] == 0x11);
    CUTE_ASSERT(mp->data[ 9] == 0x00);
    CUTE_ASSERT(mp->data[10] == 0xAA);
    CUTE_ASSERT(mp->data[11] == 0xBB);
    CUTE_ASSERT(mp->data[12] == 0xCC);
    CUTE_ASSERT(mp->data[13] == 0xDD);
    CUTE_ASSERT(mp->data[14] == 0xEE);
    CUTE_ASSERT(mp->data[15] == 0xFF);
    kryptos_del_mp_value(mp);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_value_as_hex_tests)
    kryptos_mp_value_t *mp;
    kryptos_u8_t *x;
    size_t x_size;
    mp = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    CUTE_ASSERT(mp != NULL);
    x = kryptos_mp_value_as_hex(mp, &x_size);
    CUTE_ASSERT(x != NULL);
    CUTE_ASSERT(x_size == 32);
    CUTE_ASSERT(memcmp(x, "FFEEDDCCBBAA00112233445566778899", x_size) == 0);
    kryptos_del_mp_value(mp);
    kryptos_freeseg(x);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_assign_mp_value_tests)
    kryptos_mp_value_t *a = NULL, *b;
    size_t d;

    // INFO(Rafael): with a equals to NULL.
    b = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    CUTE_ASSERT(b != NULL);

    a = kryptos_assign_mp_value(&a, b);
    CUTE_ASSERT(a != NULL);

    CUTE_ASSERT(a->data_size == b->data_size);

    CUTE_ASSERT(memcmp(a->data, b->data, a->data_size) == 0);

    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    // INFO(Rafael): with a->data_size < b->data_size.
    b = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    CUTE_ASSERT(b != NULL);

    a = kryptos_new_mp_value(16);
    CUTE_ASSERT(a != NULL);

    a = kryptos_assign_mp_value(&a, b);
    CUTE_ASSERT(a != NULL);

    CUTE_ASSERT(a->data_size == b->data_size);

    CUTE_ASSERT(memcmp(a->data, b->data, a->data_size) == 0);

    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    // INFO(Rafael): with a->data_size > b->data_size.
    b = kryptos_hex_value_as_mp("FFEEDDCCBBAA00112233445566778899", 32);
    CUTE_ASSERT(b != NULL);

    a = kryptos_new_mp_value(160);
    CUTE_ASSERT(a != NULL);

    memset(a->data, 0xf, a->data_size);
    a = kryptos_assign_mp_value(&a, b);
    CUTE_ASSERT(a != NULL);

    CUTE_ASSERT(a->data_size == 20);

    CUTE_ASSERT(memcmp(a->data, b->data, b->data_size) == 0);
    for (d = b->data_size; d < a->data_size; d++) {
        CUTE_ASSERT(a->data[d] == 0);
    }

    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_assign_hex_value_to_mp_tests)
    kryptos_mp_value_t *mp = NULL;
    // INFO(Rafael): mp == NULL.
    mp = kryptos_assign_hex_value_to_mp(&mp, "DEADBEEF", 8);
    CUTE_ASSERT(mp != NULL);
    CUTE_ASSERT(mp->data_size == 4);
    CUTE_ASSERT(mp->data[0] == 0xEF);
    CUTE_ASSERT(mp->data[1] == 0xBE);
    CUTE_ASSERT(mp->data[2] == 0xAD);
    CUTE_ASSERT(mp->data[3] == 0xDE);

    kryptos_del_mp_value(mp);

    // INFO(Rafael): mp != NULL && mp->data_size < hex-value-bitsize
    mp = kryptos_new_mp_value(16);
    CUTE_ASSERT(mp != NULL);
    CUTE_ASSERT(mp->data_size == 2);
    mp = kryptos_assign_hex_value_to_mp(&mp, "DEADBEEF", 8);
    CUTE_ASSERT(mp->data[0] == 0xAD);
    CUTE_ASSERT(mp->data[1] == 0xDE);
    kryptos_del_mp_value(mp);

    // INFO(Rafael): mp != NULL && mp->data_size > hex-value-bitsize
    mp = kryptos_new_mp_value(64);
    CUTE_ASSERT(mp != NULL);
    CUTE_ASSERT(mp->data_size == 8);
    mp = kryptos_assign_hex_value_to_mp(&mp, "DEADBEEF", 8);
    CUTE_ASSERT(mp->data[0] == 0xEF);
    CUTE_ASSERT(mp->data[1] == 0xBE);
    CUTE_ASSERT(mp->data[2] == 0xAD);
    CUTE_ASSERT(mp->data[3] == 0xDE);
    CUTE_ASSERT(mp->data[4] == 0x00);
    CUTE_ASSERT(mp->data[5] == 0x00);
    CUTE_ASSERT(mp->data[6] == 0x00);
    CUTE_ASSERT(mp->data[7] == 0x00);
    kryptos_del_mp_value(mp);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_eq_tests)
    char *values[] = {
        "01010100",

        "0202020202020200",

        "030303030303030303030303030A0A00",

        "0B0C0D000000A000010010000000000000000000000000000920000000000001",

        "FFFFFFFFFFDEABCD514272388123881293192378129319238129312312312300"
        "0000000128381238172387123102301023012030120310239192399231200000",

        "018239128381293192381283129319293982834872377283487238748239ABC0"
        "CBCBCBCBCBDBEDBDBEDBDBC7C7363817BCBE2123162631723712371236162631"
        "1111111111111111111111111111111111111111111111111112231231231231"
        "9999992391293912931923919239129319239129391231231626316236126362"
    };
    char *same_values[] = {
        "DEADBEEF",
        "00000000DEADBEEF",
        "0000000000000000DEADBEEF",
        "000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000DEADBEEF",
        "0000000000000000000000000000000000000000DEADBEEF",
        "000000000000000000000000000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000000000000000000000000000DEADBEEF",
        "0000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEF"
    };
    char *almost_same_values[] = {
        "DEADBEEF",
        "80000000DEADBEEF",
        "0000000000000000DEADBEE1",
        "000000000000000000000000DEADBEE2",
        "00000000000000000000000000000000DEADBEE3",
        "0000000000000000000000000000000000000000DEADBEE4",
        "000000000008000000000000000000000000000000000000DEADBEEF",
        "00000000000000000000000000000000000000000000000000000000DEADBEE6",
        "0000000000000000000000000000000000000000000000000000000000000000DEADBEE7",
        "000000000000000000000000000000000000000000000000000000000000000000000000DEADBEE8",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEE9",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEA",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEB",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000DEADBEEC"
    };
    struct eq_tests_ctx {
        kryptos_u8_t *a, *b;
        int expected;
    };
    struct eq_tests_ctx test_vector[] = {
        {values[0], values[0], 1}, {values[0], values[1], 0}, {values[0], values[2], 0}, {values[0], values[3], 0},
        {values[0], values[4], 0}, {values[0], values[5], 0}, {values[1], values[0], 0}, {values[1], values[1], 1},
        {values[1], values[2], 0}, {values[1], values[3], 0}, {values[1], values[4], 0}, {values[1], values[5], 0},
        {values[2], values[0], 0}, {values[2], values[1], 0}, {values[2], values[2], 1}, {values[2], values[3], 0},
        {values[2], values[4], 0}, {values[2], values[5], 0}, {values[3], values[0], 0}, {values[3], values[1], 0},
        {values[3], values[2], 0}, {values[3], values[3], 1}, {values[3], values[4], 0}, {values[3], values[5], 0},
        {values[4], values[0], 0}, {values[4], values[1], 0}, {values[4], values[2], 0}, {values[4], values[3], 0},
        {values[4], values[4], 1}, {values[4], values[5], 0}, {values[5], values[0], 0}, {values[5], values[1], 0},
        {values[5], values[2], 0}, {values[5], values[3], 0}, {values[5], values[4], 0}, {values[5], values[5], 1},

        {same_values[ 0], same_values[ 0], 1}, {same_values[ 0], same_values[ 1], 1}, {same_values[ 0], same_values[ 2], 1},
        {same_values[ 0], same_values[ 3], 1}, {same_values[ 0], same_values[ 4], 1}, {same_values[ 0], same_values[ 5], 1},
        {same_values[ 0], same_values[ 6], 1}, {same_values[ 0], same_values[ 7], 1}, {same_values[ 0], same_values[ 8], 1},
        {same_values[ 0], same_values[ 9], 1}, {same_values[ 0], same_values[10], 1}, {same_values[ 0], same_values[11], 1},
        {same_values[ 0], same_values[12], 1}, {same_values[ 0], same_values[13], 1}, {same_values[ 1], same_values[ 0], 1},
        {same_values[ 1], same_values[ 1], 1}, {same_values[ 1], same_values[ 2], 1}, {same_values[ 1], same_values[ 3], 1},
        {same_values[ 1], same_values[ 4], 1}, {same_values[ 1], same_values[ 5], 1}, {same_values[ 1], same_values[ 6], 1},
        {same_values[ 1], same_values[ 7], 1}, {same_values[ 1], same_values[ 8], 1}, {same_values[ 1], same_values[ 9], 1},
        {same_values[ 1], same_values[10], 1}, {same_values[ 1], same_values[11], 1}, {same_values[ 1], same_values[12], 1},
        {same_values[ 1], same_values[13], 1}, {same_values[ 2], same_values[ 0], 1}, {same_values[ 2], same_values[ 1], 1},
        {same_values[ 2], same_values[ 2], 1}, {same_values[ 2], same_values[ 3], 1}, {same_values[ 2], same_values[ 4], 1},
        {same_values[ 2], same_values[ 5], 1}, {same_values[ 2], same_values[ 6], 1}, {same_values[ 2], same_values[ 7], 1},
        {same_values[ 2], same_values[ 8], 1}, {same_values[ 2], same_values[ 9], 1}, {same_values[ 2], same_values[10], 1},
        {same_values[ 2], same_values[11], 1}, {same_values[ 2], same_values[12], 1}, {same_values[ 2], same_values[13], 1},
        {same_values[ 3], same_values[ 0], 1}, {same_values[ 3], same_values[ 1], 1}, {same_values[ 3], same_values[ 2], 1},
        {same_values[ 3], same_values[ 3], 1}, {same_values[ 3], same_values[ 4], 1}, {same_values[ 3], same_values[ 5], 1},
        {same_values[ 3], same_values[ 6], 1}, {same_values[ 3], same_values[ 7], 1}, {same_values[ 3], same_values[ 8], 1},
        {same_values[ 3], same_values[ 9], 1}, {same_values[ 3], same_values[10], 1}, {same_values[ 3], same_values[11], 1},
        {same_values[ 3], same_values[12], 1}, {same_values[ 3], same_values[13], 1}, {same_values[ 4], same_values[ 0], 1},
        {same_values[ 4], same_values[ 1], 1}, {same_values[ 4], same_values[ 2], 1}, {same_values[ 4], same_values[ 3], 1},
        {same_values[ 4], same_values[ 4], 1}, {same_values[ 4], same_values[ 5], 1}, {same_values[ 4], same_values[ 6], 1},
        {same_values[ 4], same_values[ 7], 1}, {same_values[ 4], same_values[ 8], 1}, {same_values[ 4], same_values[ 9], 1},
        {same_values[ 4], same_values[10], 1}, {same_values[ 4], same_values[11], 1}, {same_values[ 4], same_values[12], 1},
        {same_values[ 4], same_values[13], 1}, {same_values[ 5], same_values[ 0], 1}, {same_values[ 5], same_values[ 1], 1},
        {same_values[ 5], same_values[ 2], 1}, {same_values[ 5], same_values[ 3], 1}, {same_values[ 5], same_values[ 4], 1},
        {same_values[ 5], same_values[ 5], 1}, {same_values[ 5], same_values[ 6], 1}, {same_values[ 5], same_values[ 7], 1},
        {same_values[ 5], same_values[ 8], 1}, {same_values[ 5], same_values[ 9], 1}, {same_values[ 5], same_values[10], 1},
        {same_values[ 5], same_values[11], 1}, {same_values[ 5], same_values[12], 1}, {same_values[ 5], same_values[13], 1},
        {same_values[ 6], same_values[ 0], 1}, {same_values[ 6], same_values[ 1], 1}, {same_values[ 6], same_values[ 2], 1},
        {same_values[ 6], same_values[ 3], 1}, {same_values[ 6], same_values[ 4], 1}, {same_values[ 6], same_values[ 5], 1},
        {same_values[ 6], same_values[ 6], 1}, {same_values[ 6], same_values[ 7], 1}, {same_values[ 6], same_values[ 8], 1},
        {same_values[ 6], same_values[ 9], 1}, {same_values[ 6], same_values[10], 1}, {same_values[ 6], same_values[11], 1},
        {same_values[ 6], same_values[12], 1}, {same_values[ 6], same_values[13], 1}, {same_values[ 7], same_values[ 0], 1},
        {same_values[ 7], same_values[ 1], 1}, {same_values[ 7], same_values[ 2], 1}, {same_values[ 7], same_values[ 3], 1},
        {same_values[ 7], same_values[ 4], 1}, {same_values[ 7], same_values[ 5], 1}, {same_values[ 7], same_values[ 6], 1},
        {same_values[ 7], same_values[ 7], 1}, {same_values[ 7], same_values[ 8], 1}, {same_values[ 7], same_values[ 9], 1},
        {same_values[ 7], same_values[10], 1}, {same_values[ 7], same_values[11], 1}, {same_values[ 7], same_values[12], 1},
        {same_values[ 7], same_values[13], 1}, {same_values[ 8], same_values[ 0], 1}, {same_values[ 8], same_values[ 1], 1},
        {same_values[ 8], same_values[ 2], 1}, {same_values[ 8], same_values[ 3], 1}, {same_values[ 8], same_values[ 4], 1},
        {same_values[ 8], same_values[ 5], 1}, {same_values[ 8], same_values[ 6], 1}, {same_values[ 8], same_values[ 7], 1},
        {same_values[ 8], same_values[ 8], 1}, {same_values[ 8], same_values[ 9], 1}, {same_values[ 8], same_values[10], 1},
        {same_values[ 8], same_values[11], 1}, {same_values[ 8], same_values[12], 1}, {same_values[ 8], same_values[13], 1},
        {same_values[ 9], same_values[ 0], 1}, {same_values[ 9], same_values[ 1], 1}, {same_values[ 9], same_values[ 2], 1},
        {same_values[ 9], same_values[ 3], 1}, {same_values[ 9], same_values[ 4], 1}, {same_values[ 9], same_values[ 5], 1},
        {same_values[ 9], same_values[ 6], 1}, {same_values[ 9], same_values[ 7], 1}, {same_values[ 9], same_values[ 8], 1},
        {same_values[ 9], same_values[ 9], 1}, {same_values[ 9], same_values[10], 1}, {same_values[ 9], same_values[11], 1},
        {same_values[ 9], same_values[12], 1}, {same_values[ 9], same_values[13], 1}, {same_values[10], same_values[ 0], 1},
        {same_values[10], same_values[ 1], 1}, {same_values[10], same_values[ 2], 1}, {same_values[10], same_values[ 3], 1},
        {same_values[10], same_values[ 4], 1}, {same_values[10], same_values[ 5], 1}, {same_values[10], same_values[ 6], 1},
        {same_values[10], same_values[ 7], 1}, {same_values[10], same_values[ 8], 1}, {same_values[10], same_values[ 9], 1},
        {same_values[10], same_values[10], 1}, {same_values[10], same_values[11], 1}, {same_values[10], same_values[12], 1},
        {same_values[10], same_values[13], 1}, {same_values[11], same_values[ 0], 1}, {same_values[11], same_values[ 1], 1},
        {same_values[11], same_values[ 2], 1}, {same_values[11], same_values[ 3], 1}, {same_values[11], same_values[ 4], 1},
        {same_values[11], same_values[ 5], 1}, {same_values[11], same_values[ 6], 1}, {same_values[11], same_values[ 7], 1},
        {same_values[11], same_values[ 8], 1}, {same_values[11], same_values[ 9], 1}, {same_values[11], same_values[10], 1},
        {same_values[11], same_values[11], 1}, {same_values[11], same_values[12], 1}, {same_values[11], same_values[13], 1},
        {same_values[12], same_values[ 0], 1}, {same_values[12], same_values[ 1], 1}, {same_values[12], same_values[ 2], 1},
        {same_values[12], same_values[ 3], 1}, {same_values[12], same_values[ 4], 1}, {same_values[12], same_values[ 5], 1},
        {same_values[12], same_values[ 6], 1}, {same_values[12], same_values[ 7], 1}, {same_values[12], same_values[ 8], 1},
        {same_values[12], same_values[ 9], 1}, {same_values[12], same_values[10], 1}, {same_values[12], same_values[11], 1},
        {same_values[12], same_values[12], 1}, {same_values[12], same_values[13], 1}, {same_values[13], same_values[ 0], 1},
        {same_values[13], same_values[ 1], 1}, {same_values[13], same_values[ 2], 1}, {same_values[13], same_values[ 3], 1},
        {same_values[13], same_values[ 4], 1}, {same_values[13], same_values[ 5], 1}, {same_values[13], same_values[ 6], 1},
        {same_values[13], same_values[ 7], 1}, {same_values[13], same_values[ 8], 1}, {same_values[13], same_values[ 9], 1},
        {same_values[13], same_values[10], 1}, {same_values[13], same_values[11], 1}, {same_values[13], same_values[12], 1},
        {same_values[13], same_values[13], 1},

        {almost_same_values[ 0], almost_same_values[ 1], 0}, {almost_same_values[ 0], almost_same_values[ 2], 0},
        {almost_same_values[ 0], almost_same_values[ 3], 0}, {almost_same_values[ 0], almost_same_values[ 4], 0},
        {almost_same_values[ 0], almost_same_values[ 5], 0}, {almost_same_values[ 0], almost_same_values[ 6], 0},
        {almost_same_values[ 0], almost_same_values[ 7], 0}, {almost_same_values[ 0], almost_same_values[ 8], 0},
        {almost_same_values[ 0], almost_same_values[ 9], 0}, {almost_same_values[ 0], almost_same_values[10], 0},
        {almost_same_values[ 0], almost_same_values[11], 0}, {almost_same_values[ 0], almost_same_values[12], 0},
        {almost_same_values[ 0], almost_same_values[13], 0}, {almost_same_values[ 1], almost_same_values[ 0], 0},
        {almost_same_values[ 1], almost_same_values[ 2], 0}, {almost_same_values[ 1], almost_same_values[ 3], 0},
        {almost_same_values[ 1], almost_same_values[ 4], 0}, {almost_same_values[ 1], almost_same_values[ 5], 0},
        {almost_same_values[ 1], almost_same_values[ 6], 0}, {almost_same_values[ 1], almost_same_values[ 7], 0},
        {almost_same_values[ 1], almost_same_values[ 8], 0}, {almost_same_values[ 1], almost_same_values[ 9], 0},
        {almost_same_values[ 1], almost_same_values[10], 0}, {almost_same_values[ 1], almost_same_values[11], 0},
        {almost_same_values[ 1], almost_same_values[12], 0}, {almost_same_values[ 1], almost_same_values[13], 0},
        {almost_same_values[ 2], almost_same_values[ 0], 0}, {almost_same_values[ 2], almost_same_values[ 1], 0},
        {almost_same_values[ 2], almost_same_values[ 3], 0}, {almost_same_values[ 2], almost_same_values[ 4], 0},
        {almost_same_values[ 2], almost_same_values[ 5], 0}, {almost_same_values[ 2], almost_same_values[ 6], 0},
        {almost_same_values[ 2], almost_same_values[ 7], 0}, {almost_same_values[ 2], almost_same_values[ 8], 0},
        {almost_same_values[ 2], almost_same_values[ 9], 0}, {almost_same_values[ 2], almost_same_values[10], 0},
        {almost_same_values[ 2], almost_same_values[11], 0}, {almost_same_values[ 2], almost_same_values[12], 0},
        {almost_same_values[ 2], almost_same_values[13], 0}, {almost_same_values[ 3], almost_same_values[ 0], 0},
        {almost_same_values[ 3], almost_same_values[ 1], 0}, {almost_same_values[ 3], almost_same_values[ 2], 0},
        {almost_same_values[ 3], almost_same_values[ 4], 0}, {almost_same_values[ 3], almost_same_values[ 5], 0},
        {almost_same_values[ 3], almost_same_values[ 6], 0}, {almost_same_values[ 3], almost_same_values[ 7], 0},
        {almost_same_values[ 3], almost_same_values[ 8], 0}, {almost_same_values[ 3], almost_same_values[ 9], 0},
        {almost_same_values[ 3], almost_same_values[10], 0}, {almost_same_values[ 3], almost_same_values[11], 0},
        {almost_same_values[ 3], almost_same_values[12], 0}, {almost_same_values[ 3], almost_same_values[13], 0},
        {almost_same_values[ 4], almost_same_values[ 0], 0}, {almost_same_values[ 4], almost_same_values[ 1], 0},
        {almost_same_values[ 4], almost_same_values[ 2], 0}, {almost_same_values[ 4], almost_same_values[ 3], 0},
        {almost_same_values[ 4], almost_same_values[ 5], 0}, {almost_same_values[ 4], almost_same_values[ 6], 0},
        {almost_same_values[ 4], almost_same_values[ 7], 0}, {almost_same_values[ 4], almost_same_values[ 8], 0},
        {almost_same_values[ 4], almost_same_values[ 9], 0}, {almost_same_values[ 4], almost_same_values[10], 0},
        {almost_same_values[ 4], almost_same_values[11], 0}, {almost_same_values[ 4], almost_same_values[12], 0},
        {almost_same_values[ 4], almost_same_values[13], 0}, {almost_same_values[ 5], almost_same_values[ 0], 0},
        {almost_same_values[ 5], almost_same_values[ 1], 0}, {almost_same_values[ 5], almost_same_values[ 2], 0},
        {almost_same_values[ 5], almost_same_values[ 3], 0}, {almost_same_values[ 5], almost_same_values[ 4], 0},
        {almost_same_values[ 5], almost_same_values[ 6], 0}, {almost_same_values[ 5], almost_same_values[ 7], 0},
        {almost_same_values[ 5], almost_same_values[ 8], 0}, {almost_same_values[ 5], almost_same_values[ 9], 0},
        {almost_same_values[ 5], almost_same_values[10], 0}, {almost_same_values[ 5], almost_same_values[11], 0},
        {almost_same_values[ 5], almost_same_values[12], 0}, {almost_same_values[ 5], almost_same_values[13], 0},
        {almost_same_values[ 6], almost_same_values[ 0], 0}, {almost_same_values[ 6], almost_same_values[ 1], 0},
        {almost_same_values[ 6], almost_same_values[ 2], 0}, {almost_same_values[ 6], almost_same_values[ 3], 0},
        {almost_same_values[ 6], almost_same_values[ 4], 0}, {almost_same_values[ 6], almost_same_values[ 5], 0},
        {almost_same_values[ 6], almost_same_values[ 7], 0}, {almost_same_values[ 6], almost_same_values[ 8], 0},
        {almost_same_values[ 6], almost_same_values[ 9], 0}, {almost_same_values[ 6], almost_same_values[10], 0},
        {almost_same_values[ 6], almost_same_values[11], 0}, {almost_same_values[ 6], almost_same_values[12], 0},
        {almost_same_values[ 6], almost_same_values[13], 0}, {almost_same_values[ 7], almost_same_values[ 0], 0},
        {almost_same_values[ 7], almost_same_values[ 1], 0}, {almost_same_values[ 7], almost_same_values[ 2], 0},
        {almost_same_values[ 7], almost_same_values[ 3], 0}, {almost_same_values[ 7], almost_same_values[ 4], 0},
        {almost_same_values[ 7], almost_same_values[ 5], 0}, {almost_same_values[ 7], almost_same_values[ 6], 0},
        {almost_same_values[ 7], almost_same_values[ 8], 0}, {almost_same_values[ 7], almost_same_values[ 9], 0},
        {almost_same_values[ 7], almost_same_values[10], 0}, {almost_same_values[ 7], almost_same_values[11], 0},
        {almost_same_values[ 7], almost_same_values[12], 0}, {almost_same_values[ 7], almost_same_values[13], 0},
        {almost_same_values[ 8], almost_same_values[ 0], 0}, {almost_same_values[ 8], almost_same_values[ 1], 0},
        {almost_same_values[ 8], almost_same_values[ 2], 0}, {almost_same_values[ 8], almost_same_values[ 3], 0},
        {almost_same_values[ 8], almost_same_values[ 4], 0}, {almost_same_values[ 8], almost_same_values[ 5], 0},
        {almost_same_values[ 8], almost_same_values[ 6], 0}, {almost_same_values[ 8], almost_same_values[ 7], 0},
        {almost_same_values[ 8], almost_same_values[ 9], 0}, {almost_same_values[ 8], almost_same_values[10], 0},
        {almost_same_values[ 8], almost_same_values[11], 0}, {almost_same_values[ 8], almost_same_values[12], 0},
        {almost_same_values[ 8], almost_same_values[13], 0}, {almost_same_values[ 9], almost_same_values[ 0], 0},
        {almost_same_values[ 9], almost_same_values[ 1], 0}, {almost_same_values[ 9], almost_same_values[ 2], 0},
        {almost_same_values[ 9], almost_same_values[ 3], 0}, {almost_same_values[ 9], almost_same_values[ 4], 0},
        {almost_same_values[ 9], almost_same_values[ 5], 0}, {almost_same_values[ 9], almost_same_values[ 6], 0},
        {almost_same_values[ 9], almost_same_values[ 7], 0}, {almost_same_values[ 9], almost_same_values[ 8], 0},
        {almost_same_values[ 9], almost_same_values[10], 0}, {almost_same_values[ 9], almost_same_values[11], 0},
        {almost_same_values[ 9], almost_same_values[12], 0}, {almost_same_values[ 9], almost_same_values[13], 0},
        {almost_same_values[10], almost_same_values[ 0], 0}, {almost_same_values[10], almost_same_values[ 1], 0},
        {almost_same_values[10], almost_same_values[ 2], 0}, {almost_same_values[10], almost_same_values[ 3], 0},
        {almost_same_values[10], almost_same_values[ 4], 0}, {almost_same_values[10], almost_same_values[ 5], 0},
        {almost_same_values[10], almost_same_values[ 6], 0}, {almost_same_values[10], almost_same_values[ 7], 0},
        {almost_same_values[10], almost_same_values[ 8], 0}, {almost_same_values[10], almost_same_values[ 9], 0},
        {almost_same_values[10], almost_same_values[11], 0}, {almost_same_values[10], almost_same_values[12], 0},
        {almost_same_values[10], almost_same_values[13], 0}, {almost_same_values[11], almost_same_values[ 0], 0},
        {almost_same_values[11], almost_same_values[ 1], 0}, {almost_same_values[11], almost_same_values[ 2], 0},
        {almost_same_values[11], almost_same_values[ 3], 0}, {almost_same_values[11], almost_same_values[ 4], 0},
        {almost_same_values[11], almost_same_values[ 5], 0}, {almost_same_values[11], almost_same_values[ 6], 0},
        {almost_same_values[11], almost_same_values[ 7], 0}, {almost_same_values[11], almost_same_values[ 8], 0},
        {almost_same_values[11], almost_same_values[ 9], 0}, {almost_same_values[11], almost_same_values[10], 0},
        {almost_same_values[11], almost_same_values[12], 0}, {almost_same_values[11], almost_same_values[13], 0},
        {almost_same_values[12], almost_same_values[ 0], 0}, {almost_same_values[12], almost_same_values[ 1], 0},
        {almost_same_values[12], almost_same_values[ 2], 0}, {almost_same_values[12], almost_same_values[ 3], 0},
        {almost_same_values[12], almost_same_values[ 4], 0}, {almost_same_values[12], almost_same_values[ 5], 0},
        {almost_same_values[12], almost_same_values[ 6], 0}, {almost_same_values[12], almost_same_values[ 7], 0},
        {almost_same_values[12], almost_same_values[ 8], 0}, {almost_same_values[12], almost_same_values[ 9], 0},
        {almost_same_values[12], almost_same_values[10], 0}, {almost_same_values[12], almost_same_values[11], 0},
        {almost_same_values[12], almost_same_values[13], 0}, {almost_same_values[13], almost_same_values[ 0], 0},
        {almost_same_values[13], almost_same_values[ 1], 0}, {almost_same_values[13], almost_same_values[ 2], 0},
        {almost_same_values[13], almost_same_values[ 3], 0}, {almost_same_values[13], almost_same_values[ 4], 0},
        {almost_same_values[13], almost_same_values[ 5], 0}, {almost_same_values[13], almost_same_values[ 6], 0},
        {almost_same_values[13], almost_same_values[ 7], 0}, {almost_same_values[13], almost_same_values[ 8], 0},
        {almost_same_values[13], almost_same_values[ 9], 0}, {almost_same_values[13], almost_same_values[10], 0},
        {almost_same_values[13], almost_same_values[11], 0}, {almost_same_values[13], almost_same_values[12], 0}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_mp_value_t *a, *b;

    for (t = 0; t < test_vector_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, strlen(test_vector[t].a));
        CUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[t].b, strlen(test_vector[t].b));
        CUTE_ASSERT(b != NULL);
        CUTE_ASSERT(kryptos_mp_eq(a, b) == test_vector[t].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_get_gt_tests)
    char *values[] = {
        "00000002",
        "0000000000000001",
        "000000000000000000000000000000000000000000000000000000A",
        "FF"
    };
    kryptos_mp_value_t *a, *b;

    a = kryptos_hex_value_as_mp(values[0], strlen(values[0]));
    b = kryptos_hex_value_as_mp(values[1], strlen(values[1]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[0], strlen(values[0]));
    b = kryptos_hex_value_as_mp(values[2], strlen(values[2]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[0], strlen(values[0]));
    b = kryptos_hex_value_as_mp(values[3], strlen(values[3]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[1], strlen(values[1]));
    b = kryptos_hex_value_as_mp(values[0], strlen(values[0]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[1], strlen(values[1]));
    b = kryptos_hex_value_as_mp(values[2], strlen(values[2]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[1], strlen(values[1]));
    b = kryptos_hex_value_as_mp(values[3], strlen(values[3]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[2], strlen(values[2]));
    b = kryptos_hex_value_as_mp(values[1], strlen(values[1]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[2], strlen(values[2]));
    b = kryptos_hex_value_as_mp(values[0], strlen(values[0]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[2], strlen(values[2]));
    b = kryptos_hex_value_as_mp(values[3], strlen(values[3]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == b);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[3], strlen(values[3]));
    b = kryptos_hex_value_as_mp(values[1], strlen(values[1]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[3], strlen(values[3]));
    b = kryptos_hex_value_as_mp(values[2], strlen(values[2]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    a = kryptos_hex_value_as_mp(values[3], strlen(values[3]));
    b = kryptos_hex_value_as_mp(values[0], strlen(values[0]));
    CUTE_ASSERT(a != NULL && b != NULL);
    CUTE_ASSERT(kryptos_mp_get_gt(a, b) == a);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_ne_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct ne_tests_ctx {
        kryptos_u8_t *a, *b;
        int expected;
    };
    struct ne_tests_ctx test_vector[] = {
        {values[0], values[0], 0},
        {values[0], values[1], 1},
        {values[0], values[2], 1},
        {values[0], values[3], 1},
        {values[1], values[0], 1},
        {values[1], values[1], 0},
        {values[1], values[2], 1},
        {values[1], values[3], 1},
        {values[2], values[0], 1},
        {values[2], values[1], 1},
        {values[2], values[2], 0},
        {values[2], values[3], 1},
        {values[3], values[0], 1},
        {values[3], values[1], 1},
        {values[3], values[2], 1},
        {values[3], values[3], 0}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        CUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        CUTE_ASSERT(b != NULL);
        CUTE_ASSERT(kryptos_mp_ne(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_gt_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct gt_tests_ctx {
        kryptos_u8_t *a, *b;
        int expected;
    };
    struct gt_tests_ctx test_vector[] = {
        {values[0], values[0], 0},
        {values[0], values[1], 0},
        {values[0], values[2], 0},
        {values[0], values[3], 0},
        {values[1], values[0], 1},
        {values[1], values[1], 0},
        {values[1], values[2], 0},
        {values[1], values[3], 0},
        {values[2], values[0], 1},
        {values[2], values[1], 1},
        {values[2], values[2], 0},
        {values[2], values[3], 0},
        {values[3], values[0], 1},
        {values[3], values[1], 1},
        {values[3], values[2], 1},
        {values[3], values[3], 0}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        CUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        CUTE_ASSERT(b != NULL);
        CUTE_ASSERT(kryptos_mp_gt(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_lt_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct lt_tests_ctx {
        kryptos_u8_t *a, *b;
        int expected;
    };
    struct lt_tests_ctx test_vector[] = {
        {values[0], values[0], 0},
        {values[0], values[1], 1},
        {values[0], values[2], 1},
        {values[0], values[3], 1},
        {values[1], values[0], 0},
        {values[1], values[1], 0},
        {values[1], values[2], 1},
        {values[1], values[3], 1},
        {values[2], values[0], 0},
        {values[2], values[1], 0},
        {values[2], values[2], 0},
        {values[2], values[3], 1},
        {values[3], values[0], 0},
        {values[3], values[1], 0},
        {values[3], values[2], 0},
        {values[3], values[3], 0}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        CUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        CUTE_ASSERT(b != NULL);
        CUTE_ASSERT(kryptos_mp_lt(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_ge_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct ge_tests_ctx {
        kryptos_u8_t *a, *b;
        int expected;
    };
    struct ge_tests_ctx test_vector[] = {
        {values[0], values[0], 1},
        {values[0], values[1], 0},
        {values[0], values[2], 0},
        {values[0], values[3], 0},
        {values[1], values[0], 1},
        {values[1], values[1], 1},
        {values[1], values[2], 0},
        {values[1], values[3], 0},
        {values[2], values[0], 1},
        {values[2], values[1], 1},
        {values[2], values[2], 1},
        {values[2], values[3], 0},
        {values[3], values[0], 1},
        {values[3], values[1], 1},
        {values[3], values[2], 1},
        {values[3], values[3], 1}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        CUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        CUTE_ASSERT(b != NULL);
        CUTE_ASSERT(kryptos_mp_ge(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_le_tests)
    char *values[] = {
        "0000000000000000018",
        "0000000000000000029",
        "0000000000000000039",
        "0000001000001000010"
    };
    struct le_tests_ctx {
        kryptos_u8_t *a, *b;
        int expected;
    };
    struct le_tests_ctx test_vector[] = {
        {values[0], values[0], 1},
        {values[0], values[1], 1},
        {values[0], values[2], 1},
        {values[0], values[3], 1},
        {values[1], values[0], 0},
        {values[1], values[1], 1},
        {values[1], values[2], 1},
        {values[1], values[3], 1},
        {values[2], values[0], 0},
        {values[2], values[1], 0},
        {values[2], values[2], 1},
        {values[2], values[3], 1},
        {values[3], values[0], 0},
        {values[3], values[1], 0},
        {values[3], values[2], 0},
        {values[3], values[3], 1}
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *a, *b;

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        CUTE_ASSERT(a != NULL);
        b = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        CUTE_ASSERT(b != NULL);
        CUTE_ASSERT(kryptos_mp_le(a, b) == test_vector[tv].expected);
        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_add_tests)
    kryptos_mp_value_t *a, *b, *e;
    struct add_tests_ctx {
        kryptos_u8_t *a, *b, *e;
    };
    struct add_tests_ctx test_vector[] = {
        {   "01",   "01",    "02" },
        {   "02",   "0A",    "0C" },
        { "DEAD", "BEEF", "19D9C" }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    // INFO(Rafael): (null) = (null) + 1;
    b = kryptos_hex_value_as_mp("01", 2);
    CUTE_ASSERT(b != NULL);
    a = NULL;
    a = kryptos_mp_add(&a, b);
    CUTE_ASSERT(a != NULL);
    CUTE_ASSERT(kryptos_mp_eq(a, b) == 1);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        b = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, strlen(test_vector[tv].e));

        CUTE_ASSERT(a != NULL && b != NULL && e != NULL);

        a = kryptos_mp_add(&a, b);

        CUTE_ASSERT(a != NULL);

        CUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(e);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_sub_tests)
    kryptos_mp_value_t *a, *b, *e;
    struct sub_tests_ctx {
        kryptos_u8_t *a, *b, *e;
    };
    struct sub_tests_ctx test_vector[] = {
        {               "01",        "1",                "0" },
        {               "06",       "02",               "04" },
        {             "2001",     "1006",              "FFB" },
        {             "DEAD",     "BEEF",             "1FBE" },
        {             "BEEF",     "DEAD",            "FE042" },
        {               "01",       "02",              "FFF" },
        {         "DEADBEEF", "BEEFDEAD",         "1FBDE042" },
        {                "5",     "1006",            "FEFFF" },
        {               "10",     "1006",            "FF00A" },
        { "BABABABABABABABA",       "FD", "BABABABABABAB9BD" }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    ssize_t x;

    a = NULL;
    b = kryptos_hex_value_as_mp("101", 3);

    CUTE_ASSERT(b != NULL);

    a = kryptos_mp_sub(&a, b);

    CUTE_ASSERT(a != NULL);

    CUTE_ASSERT(kryptos_mp_eq(a, b) == 1);

    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        b = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, strlen(test_vector[tv].e));

        CUTE_ASSERT(a != NULL && b != NULL && e != NULL);

        a = kryptos_mp_sub(&a, b);

        CUTE_ASSERT(a != NULL);

        CUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(e);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_mul_tests)
    kryptos_mp_value_t *a, *b, *e;
    struct mul_tests_ctx {
        kryptos_u8_t *a, *b, *e;
    };
    struct mul_tests_ctx test_vector[] = {
        {                "2",        "4",                        "8" },
        {                "2",       "44",                       "88" },
        {               "22",       "44",                      "908" },
        {              "101",     "1001",                   "101101" },
        {             "DEAD",     "BEEF",                 "A6144983" },
        {             "BEEF",     "DEAD",                 "A6144983" },
        {               "FF",       "FF",                     "FE01" },
        {             "FFFF",     "FFFF",                 "FFFE0001" },
        {         "FFFFFFFF", "FFFFFFFF",         "FFFFFFFE00000001" },
        {         "DEADBEEF",     "DEAD",             "C1B126FD4983" },
        { "DEADBEEFDEADBEEF", "DEADBEEF", "C1B1CD12E31F7033216DA321" },
        {           "FD02FF",       "FF",                 "FC05FC01" }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    a = NULL;
    b = kryptos_hex_value_as_mp("2", 1);
    CUTE_ASSERT(b != NULL);
    a = kryptos_mp_mul(&a, b);
    CUTE_ASSERT(a != NULL);
    CUTE_ASSERT(kryptos_mp_eq(a, b) == 1);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);

    for (tv = 0; tv < test_vector_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        b = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, strlen(test_vector[tv].e));

        CUTE_ASSERT(a != NULL && b != NULL && e != NULL);

        a = kryptos_mp_mul(&a, b);

        CUTE_ASSERT(a != NULL);

        CUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(e);
    }

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_div_tests)
    kryptos_mp_value_t *x, *y, *q, *r, *eq, *er;
    struct div_tests_ctx {
        kryptos_u8_t *x, *y, *eq, *er;
    };
    struct div_tests_ctx test_vector[] = {
        {            "0002",                "1",       "2",           "0" },
        {            "0002",                "2",       "1",           "0" },
        {            "0003",                "2",       "1",           "1" },
        {            "0004",                "2",       "2",           "0" },
        {            "0007",                "2",       "3",           "1" },
        {            "0008",                "2",       "4",           "0" },
        {          "ABC",              "BAD",       "0",         "ABC" },
        {          "BAD",              "ABC",       "1",          "F1" },
        {         "DEAD",             "BEEF",       "1",        "1FBE" },
        {          "100",               "50",       "3",          "10" },
//        {     "DEADBEEF",            "DEADB",    "1000",         "EEF" },
//        { "DEADBEEFDEAD",         "DEADBEEF",   "10000",        "DEAD" },
//        {        "10001",              "100",     "100",           "1" },
        { "BABACABABACA",     "252525252525",       "5", "10111010111" },
        {  "ABCDEF01023",      "32010FEDCBA",       "3", "15CABF379F5" },
//        {      "9876546",             "6671",    "17D0",         "276" },
//        {      "9876546",                "2", "4C3B2A3",           "0" },
        {   "41C21CB8E1",                "D", "50EEE8460",         "1" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    ssize_t d;

    x = NULL;
    y = NULL;
    r = NULL;

    CUTE_ASSERT(kryptos_mp_div(x, y, &r) == NULL);

    // INFO(Rafael): Division by zero.

    x = kryptos_hex_value_as_mp("2", 1);
    y = kryptos_hex_value_as_mp("0", 1);
    CUTE_ASSERT(x != NULL && y != NULL);
    CUTE_ASSERT(kryptos_mp_div(x, y, &r) == NULL);
    CUTE_ASSERT(r == NULL);
    kryptos_del_mp_value(x);
    kryptos_del_mp_value(y);


    // INFO(Rafael): 0 / y.

    x = kryptos_hex_value_as_mp("0", 1);
    y = kryptos_hex_value_as_mp("2", 1);
    CUTE_ASSERT(x != NULL && y != NULL);
    eq = kryptos_hex_value_as_mp("0", 1);
    er = kryptos_hex_value_as_mp("0", 1);
    CUTE_ASSERT(eq != NULL && er != NULL);
    q = kryptos_mp_div(x, y, &r);
    CUTE_ASSERT(q != NULL);
    CUTE_ASSERT(r != NULL);
    CUTE_ASSERT(kryptos_mp_eq(q, eq) == 1);
    CUTE_ASSERT(kryptos_mp_eq(r, er) == 1);
    kryptos_del_mp_value(x);
    kryptos_del_mp_value(y);
    kryptos_del_mp_value(r);
    kryptos_del_mp_value(q);
    kryptos_del_mp_value(eq);
    kryptos_del_mp_value(er);

    for (tv = 0; tv < tv_nr; tv++) {
        x = kryptos_hex_value_as_mp(test_vector[tv].x, strlen(test_vector[tv].x));
        y = kryptos_hex_value_as_mp(test_vector[tv].y, strlen(test_vector[tv].y));
        eq = kryptos_hex_value_as_mp(test_vector[tv].eq, strlen(test_vector[tv].eq));
        er = kryptos_hex_value_as_mp(test_vector[tv].er, strlen(test_vector[tv].er));

        CUTE_ASSERT(x != NULL && y != NULL && eq != NULL && er != NULL);

        q = kryptos_mp_div(x, y, &r);

        CUTE_ASSERT(q != NULL);
        CUTE_ASSERT(r != NULL);

printf("*** %s / %s\n", test_vector[tv].x, test_vector[tv].y);

printf("Q  = ");
for (d = q->data_size - 1; d >= 0; d--) printf("%.2X ", q->data[d]);
printf("\n");

printf("EQ = ");
for (d = eq->data_size - 1; d >= 0; d--) printf("%.2X ", eq->data[d]);
printf("\n");

printf("R  = ");
for (d = r->data_size - 1; d >= 0; d--) printf("%.2X ", r->data[d]);
printf("\n");

printf("ER = ");
for (d = er->data_size - 1; d >= 0; d--) printf("%.2X ", er->data[d]);
printf("\n--\n");

        CUTE_ASSERT(kryptos_mp_eq(q, eq) == 1);
        CUTE_ASSERT(kryptos_mp_eq(r, er) == 1);

        kryptos_del_mp_value(r);
        kryptos_del_mp_value(q);
        kryptos_del_mp_value(er);
        kryptos_del_mp_value(eq);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(x);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_pow_tests)
    kryptos_mp_value_t *b, *e, *pe, *p;
    struct pow_tests_ctx {
        kryptos_u8_t *b, *e, *pe;
    };
    struct pow_tests_ctx test_vector[] = {
        {  "2",  "0",                    "1" },
        {  "2",  "8",                  "100" },
        {  "2",  "2",                    "4" },
        {  "2",  "0",                    "1" },
        {  "2",  "1",                    "2" },
        { "FF",  "3",               "FD02FF" },
        { "FF",  "5",           "FB09F604FF" },
        { "FF", "0A", "F62C88D104D1882CF601" }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    ssize_t d;

    for (tv = 0; tv < test_vector_nr; tv++) {
        b  = kryptos_hex_value_as_mp(test_vector[tv].b, strlen(test_vector[tv].b));
        e  = kryptos_hex_value_as_mp(test_vector[tv].e, strlen(test_vector[tv].e));
        pe = kryptos_hex_value_as_mp(test_vector[tv].pe, strlen(test_vector[tv].pe));

        CUTE_ASSERT(b != NULL && e != NULL && pe != NULL);

        p = kryptos_mp_pow(b, e);

        CUTE_ASSERT(kryptos_mp_eq(p, pe) == 1);

        kryptos_del_mp_value(b);
        kryptos_del_mp_value(e);
        kryptos_del_mp_value(pe);
        kryptos_del_mp_value(p);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_is_odd_tests)
    kryptos_mp_value_t *a;
    struct odd_tests_ctx {
        kryptos_u8_t *a;
        int e;
    };
    struct odd_tests_ctx test_vector[] = {
        { "0", 0 },
        { "1", 1 },
        { "2", 0 },
        { "3", 1 },
        { "4", 0 },
        { "5", 1 },
        { "6", 0 },
        { "7", 1 },
        { "8", 0 },
        { "9", 1 },
        { "A", 0 },
        { "B", 1 },
        { "C", 0 },
        { "D", 1 },
        { "E", 0 },
        { "F", 1 }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    for (tv = 0; tv < tv_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        CUTE_ASSERT(a != NULL);
        CUTE_ASSERT(kryptos_mp_is_odd(a) == test_vector[tv].e);
        kryptos_del_mp_value(a);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_is_even_tests)
    kryptos_mp_value_t *a;
    struct odd_tests_ctx {
        kryptos_u8_t *a;
        int e;
    };
    struct odd_tests_ctx test_vector[] = {
        { "0", 1 },
        { "1", 0 },
        { "2", 1 },
        { "3", 0 },
        { "4", 1 },
        { "5", 0 },
        { "6", 1 },
        { "7", 0 },
        { "8", 1 },
        { "9", 0 },
        { "A", 1 },
        { "B", 0 },
        { "C", 1 },
        { "D", 0 },
        { "E", 1 },
        { "F", 0 }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    for (tv = 0; tv < tv_nr; tv++) {
        a = kryptos_hex_value_as_mp(test_vector[tv].a, strlen(test_vector[tv].a));
        CUTE_ASSERT(a != NULL);
        CUTE_ASSERT(kryptos_mp_is_even(a) == test_vector[tv].e);
        kryptos_del_mp_value(a);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_me_mod_n_tests)
    struct mp_me_mod_n_tests_ctx {
        kryptos_u8_t *m, *e, *n, *exp;
    };
    struct mp_me_mod_n_tests_ctx test_vector[] = {
        {  "5", "2",   "D",  "C" },
        {  "9", "2",   "5",  "1" },
        {  "3", "4",  "15", "12" },
        {  "4", "8",  "3B", "2E" },
        {  "5", "3",   "2",  "1" },
        { "28", "2", "190",  "0" }
    };
    size_t tv_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;
    kryptos_mp_value_t *m, *e, *n, *exp, *me_mod_n;

    for (tv = 0; tv < tv_nr; tv++) {
        m = kryptos_hex_value_as_mp(test_vector[tv].m, strlen(test_vector[tv].m));
        e = kryptos_hex_value_as_mp(test_vector[tv].e, strlen(test_vector[tv].e));
        n = kryptos_hex_value_as_mp(test_vector[tv].n, strlen(test_vector[tv].n));
        exp = kryptos_hex_value_as_mp(test_vector[tv].exp, strlen(test_vector[tv].exp));

        CUTE_ASSERT(m != NULL && e != NULL && n != NULL && exp != NULL);

        me_mod_n = kryptos_mp_me_mod_n(m, e, n);

        CUTE_ASSERT(me_mod_n != NULL);

        CUTE_ASSERT(kryptos_mp_eq(me_mod_n, exp) == 1);

        kryptos_del_mp_value(m);
        kryptos_del_mp_value(e);
        kryptos_del_mp_value(n);
        kryptos_del_mp_value(exp);
        kryptos_del_mp_value(me_mod_n);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_fermat_test_tests)
    struct fermat_test_ctx {
        kryptos_u8_t *n;
        int is_prime;
    };
    struct fermat_test_ctx test_vector[] = {
        { "3", 1 }, { "4", 0 }, { "5", 1 }, { "6", 0 }, { "7", 1 }, { "8", 0 }, { "9", 0 },
        { "A", 0 }, { "B", 1 }, { "C", 0 }, { "D", 1 }, { "E", 0 }, { "F", 0 }
    };
    size_t test_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_mp_value_t *n;

    for (t = 0; t < test_nr; t++) {
        printf("N: %s\n", test_vector[t].n);
        n = kryptos_hex_value_as_mp(test_vector[t].n, strlen(test_vector[t].n));
        CUTE_ASSERT(n != NULL);
        CUTE_ASSERT(kryptos_mp_fermat_test(n, 10) == test_vector[t].is_prime);
        kryptos_del_mp_value(n);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_lsh_tests)
    struct lsh_tests_ctx {
        kryptos_u8_t *a;
        int l;
        kryptos_u8_t *e;
    };
    struct lsh_tests_ctx test_vector[] = {
        {       "50",  7,          "2800" },
        {        "2",  1,             "4" },
        {       "10",  4,           "100" },
        {       "10", 16,        "100000" },
        {     "DEAD", 10,       "37AB400" },
        {     "BEEF", 34, "2FBBC00000000" },
        { "DEADBEEF",  8,    "DEADBEEF00" }
    };
    size_t test_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_mp_value_t *a, *e;
    ssize_t d;

    for (t = 0; t < test_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, strlen(test_vector[t].a));
        e = kryptos_hex_value_as_mp(test_vector[t].e, strlen(test_vector[t].e));

        CUTE_ASSERT(a != NULL && e != NULL);

        a = kryptos_mp_lsh(&a, test_vector[t].l);

        CUTE_ASSERT(a != NULL);

        CUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(e);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mp_rsh_tests)
    struct lsh_tests_ctx {
        kryptos_u8_t *a;
        int l;
        kryptos_u8_t *e;
    };
    struct lsh_tests_ctx test_vector[] = {
        {        "2",  1,             "1" },
        {       "10",  4,             "1" },
        {       "10", 16,             "0" },
        {     "DEAD", 10,            "37" },
        {     "BEEF", 34,             "0" },
        {     "BEEF",  4,           "BEE" },
        {     "BEEF",  8,            "BE" },
        {     "BEEF", 12,             "B" },
        {     "BEEF", 15,             "1" },
        {     "BEEF", 16,             "0" },
        { "DEADBEEF",  8,        "DEADBE" }
    };
    size_t test_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_mp_value_t *a, *e;
    ssize_t d;

    for (t = 0; t < test_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, strlen(test_vector[t].a));
        e = kryptos_hex_value_as_mp(test_vector[t].e, strlen(test_vector[t].e));

        CUTE_ASSERT(a != NULL && e != NULL);

        a = kryptos_mp_rsh(&a, test_vector[t].l);

        CUTE_ASSERT(a != NULL);

        CUTE_ASSERT(kryptos_mp_eq(a, e) == 1);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(e);
    }
CUTE_TEST_CASE_END

// INFO(Rafael): End of multiprecision testing area.

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
    CUTE_RUN_TEST(kryptos_hash_common_tests);

    //  -=-=-=-=- If you have just added a new cipher take a look in "kryptos_dsl_tests" case, there is some work to
    //                                               be done there too! -=-=-=-=-=-=-

    // INFO(Rafael): Internal DSL stuff.
    CUTE_RUN_TEST(kryptos_dsl_tests);

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
    CUTE_RUN_TEST(kryptos_triple_des_tests);
    CUTE_RUN_TEST(kryptos_triple_des_ede_tests);

    // INFO(Rafael): Hash validation (also official data).
    CUTE_RUN_TEST(kryptos_sha1_tests);
    CUTE_RUN_TEST(kryptos_sha224_tests);
    CUTE_RUN_TEST(kryptos_sha256_tests);
    CUTE_RUN_TEST(kryptos_sha384_tests);
    CUTE_RUN_TEST(kryptos_sha512_tests);
    CUTE_RUN_TEST(kryptos_md4_tests);
    CUTE_RUN_TEST(kryptos_md5_tests);
    CUTE_RUN_TEST(kryptos_ripemd128_tests);
    CUTE_RUN_TEST(kryptos_ripemd160_tests);

    //  -=-=-=-=-=-=- New block ciphers/hash functions should be added to HMAC tests. -=-=-=-=-=-=-=-

    // INFO(Rafael): HMAC tests.
    CUTE_RUN_TEST(kryptos_hmac_tests);

    // INFO(Rafael): Encoding stuff.
    CUTE_RUN_TEST(kryptos_base64_tests);
    CUTE_RUN_TEST(kryptos_uuencode_tests);
    CUTE_RUN_TEST(kryptos_huffman_tests);

    // INFO(Rafael): Multiprecision stuff.
    CUTE_RUN_TEST(kryptos_mp_new_value_tests);
    CUTE_RUN_TEST(kryptos_mp_hex_value_as_mp_tests);
    CUTE_RUN_TEST(kryptos_mp_value_as_hex_tests);
    CUTE_RUN_TEST(kryptos_assign_mp_value_tests);
    CUTE_RUN_TEST(kryptos_assign_hex_value_to_mp_tests);
    CUTE_RUN_TEST(kryptos_mp_eq_tests);
    CUTE_RUN_TEST(kryptos_mp_ne_tests);
    CUTE_RUN_TEST(kryptos_mp_get_gt_tests);
    CUTE_RUN_TEST(kryptos_mp_gt_tests);
    CUTE_RUN_TEST(kryptos_mp_ge_tests);
    CUTE_RUN_TEST(kryptos_mp_lt_tests);
    CUTE_RUN_TEST(kryptos_mp_le_tests);
    CUTE_RUN_TEST(kryptos_mp_add_tests);
    CUTE_RUN_TEST(kryptos_mp_sub_tests);
    CUTE_RUN_TEST(kryptos_mp_mul_tests);
    CUTE_RUN_TEST(kryptos_mp_lsh_tests);
    CUTE_RUN_TEST(kryptos_mp_rsh_tests);
    CUTE_RUN_TEST(kryptos_mp_div_tests);
    CUTE_RUN_TEST(kryptos_mp_pow_tests);
    CUTE_RUN_TEST(kryptos_mp_is_odd_tests);
    CUTE_RUN_TEST(kryptos_mp_is_even_tests);
    //CUTE_RUN_TEST(kryptos_mp_me_mod_n_tests);
    //CUTE_RUN_TEST(kryptos_mp_fermat_test_tests);

CUTE_TEST_CASE_END

CUTE_MAIN(kryptos_test_monkey);
