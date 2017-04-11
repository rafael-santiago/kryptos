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
#include <kryptos_arc4.h>
#include <kryptos_seal.h>
#include <kryptos.h>
#include <kryptos_iv_utils.h>
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
    size_t data_size = strlen(data);
    kryptos_seal_version_t seal_version;
    size_t seal_n, seal_l;

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
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_des_tests)
    kryptos_task_ctx t, *ktask = &t;
    struct des_test_vector_ctx {
        kryptos_u8_t *key;
        kryptos_u8_t *plain;
        kryptos_u8_t *cipher;
        kryptos_u8_t *decrypted;
        size_t block_size;
    };
#define add_new_des_test_data(k, p, c, d, b) { (k), (p), (c), (d), (b) }
    struct des_test_vector_ctx test_vector[] = {
        add_new_des_test_data("\x80\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x95\xA8\xD7\x28\x13\xDA\xA9\x4D",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x40\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x0E\xEC\x14\x87\xDD\x8C\x26\xD5",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x20\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x7A\xD1\x6F\xFB\x79\xC4\x59\x26",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x10\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xD3\x74\x62\x94\xCA\x6A\x6C\xF3",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x08\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x80\x9F\x5F\x87\x3C\x1F\xD7\x61",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x04\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xC0\x2F\xAF\xFE\xC9\x89\xD1\xFC",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x02\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x46\x15\xAA\x1D\x33\xE7\x2F\x10",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x01\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x80\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x20\x55\x12\x33\x50\xC0\x08\x58",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x40\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xDF\x3B\x99\xD6\x57\x73\x97\xC8",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x20\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x31\xFE\x17\x36\x9B\x52\x88\xC9",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x10\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xDF\xDD\x3C\xC6\x4D\xAE\x16\x42",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x08\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x17\x8C\x83\xCE\x2B\x39\x9D\x94",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x04\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x50\xF6\x36\x32\x4A\x9B\x7F\x80",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x02\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xA8\x46\x8E\xE3\xBC\x18\xF0\x6D",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x01\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x80\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xA2\xDC\x9E\x92\xFD\x3C\xDE\x92",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x40\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xCA\xC0\x9F\x79\x7D\x03\x12\x87",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x20\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x90\xBA\x68\x0B\x22\xAE\xB5\x25",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x10\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xCE\x7A\x24\xF3\x50\xE2\x80\xB6",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x08\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x88\x2B\xFF\x0A\xA0\x1A\x0B\x87",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x04\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x25\x61\x02\x88\x92\x45\x11\xC2",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x02\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xC7\x15\x16\xC2\x9C\x75\xD1\x70",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x01\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x80\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x51\x99\xC2\x9A\x52\xC9\xF0\x59",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x40\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xC2\x2F\x0A\x29\x4A\x71\xF2\x9F",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x20\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xEE\x37\x14\x83\x71\x4C\x02\xEA",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x10\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xA8\x1F\xBD\x44\x8F\x9E\x52\x2F",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x08\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x4F\x64\x4C\x92\xE1\x92\xDF\xED",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x04\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x1A\xFA\x9A\x66\xA6\xDF\x92\xAE",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x02\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xB3\xC1\xCC\x71\x5C\xB8\x79\xD8",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x01\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x80\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x19\xD0\x32\xE6\x4A\xB0\xBD\x8B",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x40\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x3C\xFA\xA7\xA7\xDC\x87\x20\xDC",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x20\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xB7\x26\x5F\x7F\x44\x7A\xC6\xF3",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x10\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x9D\xB7\x3B\x3C\x0D\x16\x3F\x54",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x08\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x81\x81\xB6\x5B\xAB\xF4\xA9\x75",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x04\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x93\xC9\xB6\x40\x42\xEA\xA2\x40",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x02\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x55\x70\x53\x08\x29\x70\x55\x92",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x01\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x80\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x86\x38\x80\x9E\x87\x87\x87\xA0",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x40\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x41\xB9\xA7\x9A\xF7\x9A\xC2\x08",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x20\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x7A\x9B\xE4\x2F\x20\x09\xA8\x92",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x10\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x29\x03\x8D\x56\xBA\x6D\x27\x45",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x08\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x54\x95\xC6\xAB\xF1\xE5\xDF\x51",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x04\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xAE\x13\xDB\xD5\x61\x48\x89\x33",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x02\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x02\x4D\x1F\xFA\x89\x04\xE3\x89",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x01\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x80\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xD1\x39\x97\x12\xF9\x9B\xF0\x2E",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x40\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x14\xC1\xD7\xC1\xCF\xFE\xC7\x9E",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x20\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x1D\xE5\x27\x9D\xAE\x3B\xED\x6F",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x10\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xE9\x41\xA3\x3F\x85\x50\x13\x03",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x08\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xDA\x99\xDB\xBC\x9A\x03\xF3\x79",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x04\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xB7\xFC\x92\xF9\x1D\x8E\x92\xE9",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x02\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xAE\x8E\x5C\xAA\x3C\xA0\x4E\x85",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x01\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x80",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x9C\xC6\x2D\xF4\x3B\x6E\xED\x74",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x40",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xD8\x63\xDB\xB5\xC5\x9A\x91\xA0",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x20",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xA1\xAB\x21\x90\x54\x5B\x91\xD7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x10",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x08\x75\x04\x1E\x64\xC5\x70\xF7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x08",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x5A\x59\x45\x28\xBE\xBE\xF1\xCC",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x04",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\xFC\xDB\x32\x91\xDE\x21\xF0\xC0",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x02",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x86\x9E\xFD\x7F\x9F\x26\x5A\x09",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x01",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x80\x00\x00\x00\x00\x00\x00\x00",
                              "\x95\xF8\xA5\xE5\xDD\x31\xD9\x00",
                              "\x80\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x40\x00\x00\x00\x00\x00\x00\x00",
                              "\xDD\x7F\x12\x1C\xA5\x01\x56\x19",
                              "\x40\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x20\x00\x00\x00\x00\x00\x00\x00",
                              "\x2E\x86\x53\x10\x4F\x38\x34\xEA",
                              "\x20\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x10\x00\x00\x00\x00\x00\x00\x00",
                              "\x4B\xD3\x88\xFF\x6C\xD8\x1D\x4F",
                              "\x10\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x08\x00\x00\x00\x00\x00\x00\x00",
                              "\x20\xB9\xE7\x67\xB2\xFB\x14\x56",
                              "\x08\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x04\x00\x00\x00\x00\x00\x00\x00",
                              "\x55\x57\x93\x80\xD7\x71\x38\xEF",
                              "\x04\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x02\x00\x00\x00\x00\x00\x00\x00",
                              "\x6C\xC5\xDE\xFA\xAF\x04\x51\x2F",
                              "\x02\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x01\x00\x00\x00\x00\x00\x00\x00",
                              "\x0D\x9F\x27\x9B\xA5\xD8\x72\x60",
                              "\x01\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x80\x00\x00\x00\x00\x00\x00",
                              "\xD9\x03\x1B\x02\x71\xBD\x5A\x0A",
                              "\x00\x80\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x40\x00\x00\x00\x00\x00\x00",
                              "\x42\x42\x50\xB3\x7C\x3D\xD9\x51",
                              "\x00\x40\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x20\x00\x00\x00\x00\x00\x00",
                              "\xB8\x06\x1B\x7E\xCD\x9A\x21\xE5",
                              "\x00\x20\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x10\x00\x00\x00\x00\x00\x00",
                              "\xF1\x5D\x0F\x28\x6B\x65\xBD\x28",
                              "\x00\x10\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x08\x00\x00\x00\x00\x00\x00",
                              "\xAD\xD0\xCC\x8D\x6E\x5D\xEB\xA1",
                              "\x00\x08\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x04\x00\x00\x00\x00\x00\x00",
                              "\xE6\xD5\xF8\x27\x52\xAD\x63\xD1",
                              "\x00\x04\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x02\x00\x00\x00\x00\x00\x00",
                              "\xEC\xBF\xE3\xBD\x3F\x59\x1A\x5E",
                              "\x00\x02\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x01\x00\x00\x00\x00\x00\x00",
                              "\xF3\x56\x83\x43\x79\xD1\x65\xCD",
                              "\x00\x01\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x80\x00\x00\x00\x00\x00",
                              "\x2B\x9F\x98\x2F\x20\x03\x7F\xA9",
                              "\x00\x00\x80\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x40\x00\x00\x00\x00\x00",
                              "\x88\x9D\xE0\x68\xA1\x6F\x0B\xE6",
                              "\x00\x00\x40\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x20\x00\x00\x00\x00\x00",
                              "\xE1\x9E\x27\x5D\x84\x6A\x12\x98",
                              "\x00\x00\x20\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x10\x00\x00\x00\x00\x00",
                              "\x32\x9A\x8E\xD5\x23\xD7\x1A\xEC",
                              "\x00\x00\x10\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x08\x00\x00\x00\x00\x00",
                              "\xE7\xFC\xE2\x25\x57\xD2\x3C\x97",
                              "\x00\x00\x08\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x04\x00\x00\x00\x00\x00",
                              "\x12\xA9\xF5\x81\x7F\xF2\xD6\x5D",
                              "\x00\x00\x04\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x02\x00\x00\x00\x00\x00",
                              "\xA4\x84\xC3\xAD\x38\xDC\x9C\x19",
                              "\x00\x00\x02\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x01\x00\x00\x00\x00\x00",
                              "\xFB\xE0\x0A\x8A\x1E\xF8\xAD\x72",
                              "\x00\x00\x01\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x80\x00\x00\x00\x00",
                              "\x75\x0D\x07\x94\x07\x52\x13\x63",
                              "\x00\x00\x00\x80\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x40\x00\x00\x00\x00",
                              "\x64\xFE\xED\x9C\x72\x4C\x2F\xAF",
                              "\x00\x00\x00\x40\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x20\x00\x00\x00\x00",
                              "\xF0\x2B\x26\x3B\x32\x8E\x2B\x60",
                              "\x00\x00\x00\x20\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x10\x00\x00\x00\x00",
                              "\x9D\x64\x55\x5A\x9A\x10\xB8\x52",
                              "\x00\x00\x00\x10\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x08\x00\x00\x00\x00",
                              "\xD1\x06\xFF\x0B\xED\x52\x55\xD7",
                              "\x00\x00\x00\x08\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x04\x00\x00\x00\x00",
                              "\xE1\x65\x2C\x6B\x13\x8C\x64\xA5",
                              "\x00\x00\x00\x04\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x02\x00\x00\x00\x00",
                              "\xE4\x28\x58\x11\x86\xEC\x8F\x46",
                              "\x00\x00\x00\x02\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x01\x00\x00\x00\x00",
                              "\xAE\xB5\xF5\xED\xE2\x2D\x1A\x36",
                              "\x00\x00\x00\x01\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x80\x00\x00\x00",
                              "\xE9\x43\xD7\x56\x8A\xEC\x0C\x5C",
                              "\x00\x00\x00\x00\x80\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x40\x00\x00\x00",
                              "\xDF\x98\xC8\x27\x6F\x54\xB0\x4B",
                              "\x00\x00\x00\x00\x40\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x20\x00\x00\x00",
                              "\xB1\x60\xE4\x68\x0F\x6C\x69\x6F",
                              "\x00\x00\x00\x00\x20\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x10\x00\x00\x00",
                              "\xFA\x07\x52\xB0\x7D\x9C\x4A\xB8",
                              "\x00\x00\x00\x00\x10\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x08\x00\x00\x00",
                              "\xCA\x3A\x2B\x03\x6D\xBC\x85\x02",
                              "\x00\x00\x00\x00\x08\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x04\x00\x00\x00",
                              "\x5E\x09\x05\x51\x7B\xB5\x9B\xCF",
                              "\x00\x00\x00\x00\x04\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x02\x00\x00\x00",
                              "\x81\x4E\xEB\x3B\x91\xD9\x07\x26",
                              "\x00\x00\x00\x00\x02\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x01\x00\x00\x00",
                              "\x4D\x49\xDB\x15\x32\x91\x9C\x9F",
                              "\x00\x00\x00\x00\x01\x00\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x80\x00\x00",
                              "\x25\xEB\x5F\xC3\xF8\xCF\x06\x21",
                              "\x00\x00\x00\x00\x00\x80\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x40\x00\x00",
                              "\xAB\x6A\x20\xC0\x62\x0D\x1C\x6F",
                              "\x00\x00\x00\x00\x00\x40\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x20\x00\x00",
                              "\x79\xE9\x0D\xBC\x98\xF9\x2C\xCA",
                              "\x00\x00\x00\x00\x00\x20\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x10\x00\x00",
                              "\x86\x6E\xCE\xDD\x80\x72\xBB\x0E",
                              "\x00\x00\x00\x00\x00\x10\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x08\x00\x00",
                              "\x8B\x54\x53\x6F\x2F\x3E\x64\xA8",
                              "\x00\x00\x00\x00\x00\x08\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x04\x00\x00",
                              "\xEA\x51\xD3\x97\x55\x95\xB8\x6B",
                              "\x00\x00\x00\x00\x00\x04\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x02\x00\x00",
                              "\xCA\xFF\xC6\xAC\x45\x42\xDE\x31",
                              "\x00\x00\x00\x00\x00\x02\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x01\x00\x00",
                              "\x8D\xD4\x5A\x2D\xDF\x90\x79\x6C",
                              "\x00\x00\x00\x00\x00\x01\x00\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x80\x00",
                              "\x10\x29\xD5\x5E\x88\x0E\xC2\xD0",
                              "\x00\x00\x00\x00\x00\x00\x80\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x40\x00",
                              "\x5D\x86\xCB\x23\x63\x9D\xBE\xA9",
                              "\x00\x00\x00\x00\x00\x00\x40\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x20\x00",
                              "\x1D\x1C\xA8\x53\xAE\x7C\x0C\x5F",
                              "\x00\x00\x00\x00\x00\x00\x20\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x10\x00",
                              "\xCE\x33\x23\x29\x24\x8F\x32\x28",
                              "\x00\x00\x00\x00\x00\x00\x10\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x08\x00",
                              "\x84\x05\xD1\xAB\xE2\x4F\xB9\x42",
                              "\x00\x00\x00\x00\x00\x00\x08\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x04\x00",
                              "\xE6\x43\xD7\x80\x90\xCA\x42\x07",
                              "\x00\x00\x00\x00\x00\x00\x04\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x02\x00",
                              "\x48\x22\x1B\x99\x37\x74\x8A\x23",
                              "\x00\x00\x00\x00\x00\x00\x02\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x01\x00",
                              "\xDD\x7C\x0B\xBD\x61\xFA\xFD\x54",
                              "\x00\x00\x00\x00\x00\x00\x01\x00", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x80",
                              "\x2F\xBC\x29\x1A\x57\x0D\xB5\xC4",
                              "\x00\x00\x00\x00\x00\x00\x00\x80", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x40",
                              "\xE0\x7C\x30\xD7\xE4\xE2\x6E\x12",
                              "\x00\x00\x00\x00\x00\x00\x00\x40", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x20",
                              "\x09\x53\xE2\x25\x8E\x8E\x90\xA1",
                              "\x00\x00\x00\x00\x00\x00\x00\x20", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x10",
                              "\x5B\x71\x1B\xC4\xCE\xEB\xF2\xEE",
                              "\x00\x00\x00\x00\x00\x00\x00\x10", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x08",
                              "\xCC\x08\x3F\x1E\x6D\x9E\x85\xF6",
                              "\x00\x00\x00\x00\x00\x00\x00\x08", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x04",
                              "\xD2\xFD\x88\x67\xD5\x0D\x2D\xFE",
                              "\x00\x00\x00\x00\x00\x00\x00\x04", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x02",
                              "\x06\xE7\xEA\x22\xCE\x92\x70\x8F",
                              "\x00\x00\x00\x00\x00\x00\x00\x02", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x01",
                              "\x16\x6B\x40\xB4\x4A\xBA\x4B\xD6",
                              "\x00\x00\x00\x00\x00\x00\x00\x01", 8),
        add_new_des_test_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x00\x00\x00\x00\x00\x00\x00\x00",
                              "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                              "\x00\x00\x00\x00\x00\x00\x00\x00", 8),
        add_new_des_test_data("\x01\x01\x01\x01\x01\x01\x01\x01",
                              "\x01\x01\x01\x01\x01\x01\x01\x01",
                              "\x99\x4D\x4D\xC1\x57\xB9\x6C\x52",
                              "\x01\x01\x01\x01\x01\x01\x01\x01", 8),
        add_new_des_test_data("\x02\x02\x02\x02\x02\x02\x02\x02",
                              "\x02\x02\x02\x02\x02\x02\x02\x02",
                              "\xE1\x27\xC2\xB6\x1D\x98\xE6\xE2",
                              "\x02\x02\x02\x02\x02\x02\x02\x02", 8),
        add_new_des_test_data("\x03\x03\x03\x03\x03\x03\x03\x03",
                              "\x03\x03\x03\x03\x03\x03\x03\x03",
                              "\x98\x4C\x91\xD7\x8A\x26\x9C\xE3",
                              "\x03\x03\x03\x03\x03\x03\x03\x03", 8),
        add_new_des_test_data("\x04\x04\x04\x04\x04\x04\x04\x04",
                              "\x04\x04\x04\x04\x04\x04\x04\x04",
                              "\x1F\x45\x70\xBB\x77\x55\x06\x83",
                              "\x04\x04\x04\x04\x04\x04\x04\x04", 8),
        add_new_des_test_data("\x05\x05\x05\x05\x05\x05\x05\x05",
                              "\x05\x05\x05\x05\x05\x05\x05\x05",
                              "\x39\x90\xAB\xF9\x8D\x67\x2B\x16",
                              "\x05\x05\x05\x05\x05\x05\x05\x05", 8),
        add_new_des_test_data("\x06\x06\x06\x06\x06\x06\x06\x06",
                              "\x06\x06\x06\x06\x06\x06\x06\x06",
                              "\x3F\x51\x50\xBB\xA0\x81\xD5\x85",
                              "\x06\x06\x06\x06\x06\x06\x06\x06", 8),
        add_new_des_test_data("\x07\x07\x07\x07\x07\x07\x07\x07",
                              "\x07\x07\x07\x07\x07\x07\x07\x07",
                              "\xC6\x52\x42\x24\x8C\x9C\xF6\xF2",
                              "\x07\x07\x07\x07\x07\x07\x07\x07", 8),
        add_new_des_test_data("\x08\x08\x08\x08\x08\x08\x08\x08",
                              "\x08\x08\x08\x08\x08\x08\x08\x08",
                              "\x10\x77\x2D\x40\xFA\xD2\x42\x57",
                              "\x08\x08\x08\x08\x08\x08\x08\x08", 8),
        add_new_des_test_data("\x09\x09\x09\x09\x09\x09\x09\x09",
                              "\x09\x09\x09\x09\x09\x09\x09\x09",
                              "\xF0\x13\x94\x40\x64\x7A\x6E\x7B",
                              "\x09\x09\x09\x09\x09\x09\x09\x09", 8),
        add_new_des_test_data("\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",
                              "\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",
                              "\x0A\x28\x86\x03\x04\x4D\x74\x0C",
                              "\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A", 8),
        add_new_des_test_data("\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B",
                              "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B",
                              "\x63\x59\x91\x69\x42\xF7\x43\x8F",
                              "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B", 8),
        add_new_des_test_data("\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C",
                              "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C",
                              "\x93\x43\x16\xAE\x44\x3C\xF0\x8B",
                              "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C", 8),
        add_new_des_test_data("\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D",
                              "\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D",
                              "\xE3\xF5\x6D\x7F\x11\x30\xA2\xB7",
                              "\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D", 8),
        add_new_des_test_data("\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E",
                              "\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E",
                              "\xA2\xE4\x70\x50\x87\xC6\xB6\xB4",
                              "\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E", 8),
        add_new_des_test_data("\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F",
                              "\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F",
                              "\xD5\xD7\x6E\x09\xA4\x47\xE8\xC3",
                              "\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F", 8),
        add_new_des_test_data("\x10\x10\x10\x10\x10\x10\x10\x10",
                              "\x10\x10\x10\x10\x10\x10\x10\x10",
                              "\xDD\x75\x15\xF2\xBF\xC1\x7F\x85",
                              "\x10\x10\x10\x10\x10\x10\x10\x10", 8),
        add_new_des_test_data("\x11\x11\x11\x11\x11\x11\x11\x11",
                              "\x11\x11\x11\x11\x11\x11\x11\x11",
                              "\xF4\x03\x79\xAB\x9E\x0E\xC5\x33",
                              "\x11\x11\x11\x11\x11\x11\x11\x11", 8),
        add_new_des_test_data("\x12\x12\x12\x12\x12\x12\x12\x12",
                              "\x12\x12\x12\x12\x12\x12\x12\x12",
                              "\x96\xCD\x27\x78\x4D\x15\x63\xE5",
                              "\x12\x12\x12\x12\x12\x12\x12\x12", 8),
        add_new_des_test_data("\x13\x13\x13\x13\x13\x13\x13\x13",
                              "\x13\x13\x13\x13\x13\x13\x13\x13",
                              "\x29\x11\xCF\x5E\x94\xD3\x3F\xE1",
                              "\x13\x13\x13\x13\x13\x13\x13\x13", 8),
        add_new_des_test_data("\x14\x14\x14\x14\x14\x14\x14\x14",
                              "\x14\x14\x14\x14\x14\x14\x14\x14",
                              "\x37\x7B\x7F\x7C\xA3\xE5\xBB\xB3",
                              "\x14\x14\x14\x14\x14\x14\x14\x14", 8),
        add_new_des_test_data("\x15\x15\x15\x15\x15\x15\x15\x15",
                              "\x15\x15\x15\x15\x15\x15\x15\x15",
                              "\x70\x1A\xA6\x38\x32\x90\x5A\x92",
                              "\x15\x15\x15\x15\x15\x15\x15\x15", 8),
        add_new_des_test_data("\x16\x16\x16\x16\x16\x16\x16\x16",
                              "\x16\x16\x16\x16\x16\x16\x16\x16",
                              "\x20\x06\xE7\x16\xC4\x25\x2D\x6D",
                              "\x16\x16\x16\x16\x16\x16\x16\x16", 8),
        add_new_des_test_data("\x17\x17\x17\x17\x17\x17\x17\x17",
                              "\x17\x17\x17\x17\x17\x17\x17\x17",
                              "\x45\x2C\x11\x97\x42\x24\x69\xF8",
                              "\x17\x17\x17\x17\x17\x17\x17\x17", 8),
        add_new_des_test_data("\x18\x18\x18\x18\x18\x18\x18\x18",
                              "\x18\x18\x18\x18\x18\x18\x18\x18",
                              "\xC3\x3F\xD1\xEB\x49\xCB\x64\xDA",
                              "\x18\x18\x18\x18\x18\x18\x18\x18", 8),
        add_new_des_test_data("\x19\x19\x19\x19\x19\x19\x19\x19",
                              "\x19\x19\x19\x19\x19\x19\x19\x19",
                              "\x75\x72\x27\x8F\x36\x4E\xB5\x0D",
                              "\x19\x19\x19\x19\x19\x19\x19\x19", 8),
        add_new_des_test_data("\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A",
                              "\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A",
                              "\x69\xE5\x14\x88\x40\x3E\xF4\xC3",
                              "\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A", 8),
        add_new_des_test_data("\x1B\x1B\x1B\x1B\x1B\x1B\x1B\x1B",
                              "\x1B\x1B\x1B\x1B\x1B\x1B\x1B\x1B",
                              "\xFF\x84\x7E\x0A\xDF\x19\x28\x25",
                              "\x1B\x1B\x1B\x1B\x1B\x1B\x1B\x1B", 8),
        add_new_des_test_data("\x1C\x1C\x1C\x1C\x1C\x1C\x1C\x1C",
                              "\x1C\x1C\x1C\x1C\x1C\x1C\x1C\x1C",
                              "\x52\x1B\x7F\xB3\xB4\x1B\xB7\x91",
                              "\x1C\x1C\x1C\x1C\x1C\x1C\x1C\x1C", 8),
        add_new_des_test_data("\x1D\x1D\x1D\x1D\x1D\x1D\x1D\x1D",
                              "\x1D\x1D\x1D\x1D\x1D\x1D\x1D\x1D",
                              "\x26\x05\x9A\x6A\x0F\x3F\x6B\x35",
                              "\x1D\x1D\x1D\x1D\x1D\x1D\x1D\x1D", 8),
        add_new_des_test_data("\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E",
                              "\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E",
                              "\xF2\x4A\x8D\x22\x31\xC7\x75\x38",
                              "\x1E\x1E\x1E\x1E\x1E\x1E\x1E\x1E", 8),
        add_new_des_test_data("\x1F\x1F\x1F\x1F\x1F\x1F\x1F\x1F",
                              "\x1F\x1F\x1F\x1F\x1F\x1F\x1F\x1F",
                              "\x4F\xD9\x6E\xC0\xD3\x30\x4E\xF6",
                              "\x1F\x1F\x1F\x1F\x1F\x1F\x1F\x1F", 8),
        add_new_des_test_data("\x20\x20\x20\x20\x20\x20\x20\x20",
                              "\x20\x20\x20\x20\x20\x20\x20\x20",
                              "\x18\xA9\xD5\x80\xA9\x00\xB6\x99",
                              "\x20\x20\x20\x20\x20\x20\x20\x20", 8),
        add_new_des_test_data("\x21\x21\x21\x21\x21\x21\x21\x21",
                              "\x21\x21\x21\x21\x21\x21\x21\x21",
                              "\x88\x58\x6E\x1D\x75\x5B\x9B\x5A",
                              "\x21\x21\x21\x21\x21\x21\x21\x21", 8),
        add_new_des_test_data("\x22\x22\x22\x22\x22\x22\x22\x22",
                              "\x22\x22\x22\x22\x22\x22\x22\x22",
                              "\x0F\x8A\xDF\xFB\x11\xDC\x27\x84",
                              "\x22\x22\x22\x22\x22\x22\x22\x22", 8),
        add_new_des_test_data("\x23\x23\x23\x23\x23\x23\x23\x23",
                              "\x23\x23\x23\x23\x23\x23\x23\x23",
                              "\x2F\x30\x44\x6C\x83\x12\x40\x4A",
                              "\x23\x23\x23\x23\x23\x23\x23\x23", 8),
        add_new_des_test_data("\x24\x24\x24\x24\x24\x24\x24\x24",
                              "\x24\x24\x24\x24\x24\x24\x24\x24",
                              "\x0B\xA0\x3D\x9E\x6C\x19\x65\x11",
                              "\x24\x24\x24\x24\x24\x24\x24\x24", 8),
        add_new_des_test_data("\x25\x25\x25\x25\x25\x25\x25\x25",
                              "\x25\x25\x25\x25\x25\x25\x25\x25",
                              "\x3E\x55\xE9\x97\x61\x1E\x4B\x7D",
                              "\x25\x25\x25\x25\x25\x25\x25\x25", 8),
        add_new_des_test_data("\x26\x26\x26\x26\x26\x26\x26\x26",
                              "\x26\x26\x26\x26\x26\x26\x26\x26",
                              "\xB2\x52\x2F\xB5\xF1\x58\xF0\xDF",
                              "\x26\x26\x26\x26\x26\x26\x26\x26", 8),
        add_new_des_test_data("\x27\x27\x27\x27\x27\x27\x27\x27",
                              "\x27\x27\x27\x27\x27\x27\x27\x27",
                              "\x21\x09\x42\x59\x35\x40\x6A\xB8",
                              "\x27\x27\x27\x27\x27\x27\x27\x27", 8),
        add_new_des_test_data("\x28\x28\x28\x28\x28\x28\x28\x28",
                              "\x28\x28\x28\x28\x28\x28\x28\x28",
                              "\x11\xA1\x60\x28\xF3\x10\xFF\x16",
                              "\x28\x28\x28\x28\x28\x28\x28\x28", 8),
        add_new_des_test_data("\x29\x29\x29\x29\x29\x29\x29\x29",
                              "\x29\x29\x29\x29\x29\x29\x29\x29",
                              "\x73\xF0\xC4\x5F\x37\x9F\xE6\x7F",
                              "\x29\x29\x29\x29\x29\x29\x29\x29", 8),
        add_new_des_test_data("\x2A\x2A\x2A\x2A\x2A\x2A\x2A\x2A",
                              "\x2A\x2A\x2A\x2A\x2A\x2A\x2A\x2A",
                              "\xDC\xAD\x43\x38\xF7\x52\x38\x16",
                              "\x2A\x2A\x2A\x2A\x2A\x2A\x2A\x2A", 8),
        add_new_des_test_data("\x2B\x2B\x2B\x2B\x2B\x2B\x2B\x2B",
                              "\x2B\x2B\x2B\x2B\x2B\x2B\x2B\x2B",
                              "\xB8\x16\x34\xC1\xCE\xAB\x29\x8C",
                              "\x2B\x2B\x2B\x2B\x2B\x2B\x2B\x2B", 8),
        add_new_des_test_data("\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C",
                              "\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C",
                              "\xDD\x2C\xCB\x29\xB6\xC4\xC3\x49",
                              "\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C", 8),
        add_new_des_test_data("\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D",
                              "\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D",
                              "\x7D\x07\xA7\x7A\x2A\xBD\x50\xA7",
                              "\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D", 8),
        add_new_des_test_data("\x2E\x2E\x2E\x2E\x2E\x2E\x2E\x2E",
                              "\x2E\x2E\x2E\x2E\x2E\x2E\x2E\x2E",
                              "\x30\xC1\xB0\xC1\xFD\x91\xD3\x71",
                              "\x2E\x2E\x2E\x2E\x2E\x2E\x2E\x2E", 8),
        add_new_des_test_data("\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F",
                              "\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F",
                              "\xC4\x42\x7B\x31\xAC\x61\x97\x3B",
                              "\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F", 8),
        add_new_des_test_data("\x30\x30\x30\x30\x30\x30\x30\x30",
                              "\x30\x30\x30\x30\x30\x30\x30\x30",
                              "\xF4\x7B\xB4\x62\x73\xB1\x5E\xB5",
                              "\x30\x30\x30\x30\x30\x30\x30\x30", 8),
        add_new_des_test_data("\x31\x31\x31\x31\x31\x31\x31\x31",
                              "\x31\x31\x31\x31\x31\x31\x31\x31",
                              "\x65\x5E\xA6\x28\xCF\x62\x58\x5F",
                              "\x31\x31\x31\x31\x31\x31\x31\x31", 8),
        add_new_des_test_data("\x32\x32\x32\x32\x32\x32\x32\x32",
                              "\x32\x32\x32\x32\x32\x32\x32\x32",
                              "\xAC\x97\x8C\x24\x78\x63\x38\x8F",
                              "\x32\x32\x32\x32\x32\x32\x32\x32", 8),
        add_new_des_test_data("\x33\x33\x33\x33\x33\x33\x33\x33",
                              "\x33\x33\x33\x33\x33\x33\x33\x33",
                              "\x04\x32\xED\x38\x6F\x2D\xE3\x28",
                              "\x33\x33\x33\x33\x33\x33\x33\x33", 8),
        add_new_des_test_data("\x34\x34\x34\x34\x34\x34\x34\x34",
                              "\x34\x34\x34\x34\x34\x34\x34\x34",
                              "\xD2\x54\x01\x4C\xB9\x86\xB3\xC2",
                              "\x34\x34\x34\x34\x34\x34\x34\x34", 8),
        add_new_des_test_data("\x35\x35\x35\x35\x35\x35\x35\x35",
                              "\x35\x35\x35\x35\x35\x35\x35\x35",
                              "\xB2\x56\xE3\x4B\xED\xB4\x98\x01",
                              "\x35\x35\x35\x35\x35\x35\x35\x35", 8),
        add_new_des_test_data("\x36\x36\x36\x36\x36\x36\x36\x36",
                              "\x36\x36\x36\x36\x36\x36\x36\x36",
                              "\x37\xF8\x75\x9E\xB7\x7E\x7B\xFC",
                              "\x36\x36\x36\x36\x36\x36\x36\x36", 8),
        add_new_des_test_data("\x37\x37\x37\x37\x37\x37\x37\x37",
                              "\x37\x37\x37\x37\x37\x37\x37\x37",
                              "\x50\x13\xCA\x4F\x62\xC9\xCE\xA0",
                              "\x37\x37\x37\x37\x37\x37\x37\x37", 8),
        add_new_des_test_data("\x38\x38\x38\x38\x38\x38\x38\x38",
                              "\x38\x38\x38\x38\x38\x38\x38\x38",
                              "\x89\x40\xF7\xB3\xEA\xCA\x59\x39",
                              "\x38\x38\x38\x38\x38\x38\x38\x38", 8),
        add_new_des_test_data("\x39\x39\x39\x39\x39\x39\x39\x39",
                              "\x39\x39\x39\x39\x39\x39\x39\x39",
                              "\xE2\x2B\x19\xA5\x50\x86\x77\x4B",
                              "\x39\x39\x39\x39\x39\x39\x39\x39", 8),
        add_new_des_test_data("\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A",
                              "\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A",
                              "\xB0\x4A\x2A\xAC\x92\x5A\xBB\x0B",
                              "\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A", 8),
        add_new_des_test_data("\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B",
                              "\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B",
                              "\x8D\x25\x0D\x58\x36\x15\x97\xFC",
                              "\x3B\x3B\x3B\x3B\x3B\x3B\x3B\x3B", 8),
        add_new_des_test_data("\x3C\x3C\x3C\x3C\x3C\x3C\x3C\x3C",
                              "\x3C\x3C\x3C\x3C\x3C\x3C\x3C\x3C",
                              "\x51\xF0\x11\x4F\xB6\xA6\xCD\x37",
                              "\x3C\x3C\x3C\x3C\x3C\x3C\x3C\x3C", 8),
        add_new_des_test_data("\x3D\x3D\x3D\x3D\x3D\x3D\x3D\x3D",
                              "\x3D\x3D\x3D\x3D\x3D\x3D\x3D\x3D",
                              "\x9D\x0B\xB4\xDB\x83\x0E\xCB\x73",
                              "\x3D\x3D\x3D\x3D\x3D\x3D\x3D\x3D", 8),
        add_new_des_test_data("\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E",
                              "\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E",
                              "\xE9\x60\x89\xD6\x36\x8F\x3E\x1A",
                              "\x3E\x3E\x3E\x3E\x3E\x3E\x3E\x3E", 8),
        add_new_des_test_data("\x3F\x3F\x3F\x3F\x3F\x3F\x3F\x3F",
                              "\x3F\x3F\x3F\x3F\x3F\x3F\x3F\x3F",
                              "\x5C\x4C\xA8\x77\xA4\xE1\xE9\x2D",
                              "\x3F\x3F\x3F\x3F\x3F\x3F\x3F\x3F", 8),
        add_new_des_test_data("\x40\x40\x40\x40\x40\x40\x40\x40",
                              "\x40\x40\x40\x40\x40\x40\x40\x40",
                              "\x6D\x55\xDD\xBC\x8D\xEA\x95\xFF",
                              "\x40\x40\x40\x40\x40\x40\x40\x40", 8),
        add_new_des_test_data("\x41\x41\x41\x41\x41\x41\x41\x41",
                              "\x41\x41\x41\x41\x41\x41\x41\x41",
                              "\x19\xDF\x84\xAC\x95\x55\x10\x03",
                              "\x41\x41\x41\x41\x41\x41\x41\x41", 8),
        add_new_des_test_data("\x42\x42\x42\x42\x42\x42\x42\x42",
                              "\x42\x42\x42\x42\x42\x42\x42\x42",
                              "\x72\x4E\x73\x32\x69\x6D\x08\xA7",
                              "\x42\x42\x42\x42\x42\x42\x42\x42", 8),
        add_new_des_test_data("\x43\x43\x43\x43\x43\x43\x43\x43",
                              "\x43\x43\x43\x43\x43\x43\x43\x43",
                              "\xB9\x18\x10\xB8\xCD\xC5\x8F\xE2",
                              "\x43\x43\x43\x43\x43\x43\x43\x43", 8),
        add_new_des_test_data("\x44\x44\x44\x44\x44\x44\x44\x44",
                              "\x44\x44\x44\x44\x44\x44\x44\x44",
                              "\x06\xE2\x35\x26\xED\xCC\xD0\xC4",
                              "\x44\x44\x44\x44\x44\x44\x44\x44", 8),
        add_new_des_test_data("\x45\x45\x45\x45\x45\x45\x45\x45",
                              "\x45\x45\x45\x45\x45\x45\x45\x45",
                              "\xEF\x52\x49\x1D\x54\x68\xD4\x41",
                              "\x45\x45\x45\x45\x45\x45\x45\x45", 8),
        add_new_des_test_data("\x46\x46\x46\x46\x46\x46\x46\x46",
                              "\x46\x46\x46\x46\x46\x46\x46\x46",
                              "\x48\x01\x9C\x59\xE3\x9B\x90\xC5",
                              "\x46\x46\x46\x46\x46\x46\x46\x46", 8),
        add_new_des_test_data("\x47\x47\x47\x47\x47\x47\x47\x47",
                              "\x47\x47\x47\x47\x47\x47\x47\x47",
                              "\x05\x44\x08\x3F\xB9\x02\xD8\xC0",
                              "\x47\x47\x47\x47\x47\x47\x47\x47", 8),
        add_new_des_test_data("\x48\x48\x48\x48\x48\x48\x48\x48",
                              "\x48\x48\x48\x48\x48\x48\x48\x48",
                              "\x63\xB1\x5C\xAD\xA6\x68\xCE\x12",
                              "\x48\x48\x48\x48\x48\x48\x48\x48", 8),
        add_new_des_test_data("\x49\x49\x49\x49\x49\x49\x49\x49",
                              "\x49\x49\x49\x49\x49\x49\x49\x49",
                              "\xEA\xCC\x0C\x12\x64\x17\x10\x71",
                              "\x49\x49\x49\x49\x49\x49\x49\x49", 8),
        add_new_des_test_data("\x4A\x4A\x4A\x4A\x4A\x4A\x4A\x4A",
                              "\x4A\x4A\x4A\x4A\x4A\x4A\x4A\x4A",
                              "\x9D\x2B\x8C\x0A\xC6\x05\xF2\x74",
                              "\x4A\x4A\x4A\x4A\x4A\x4A\x4A\x4A", 8),
        add_new_des_test_data("\x4B\x4B\x4B\x4B\x4B\x4B\x4B\x4B",
                              "\x4B\x4B\x4B\x4B\x4B\x4B\x4B\x4B",
                              "\xC9\x0F\x2F\x4C\x98\xA8\xFB\x2A",
                              "\x4B\x4B\x4B\x4B\x4B\x4B\x4B\x4B", 8),
        add_new_des_test_data("\x4C\x4C\x4C\x4C\x4C\x4C\x4C\x4C",
                              "\x4C\x4C\x4C\x4C\x4C\x4C\x4C\x4C",
                              "\x03\x48\x1B\x48\x28\xFD\x1D\x04",
                              "\x4C\x4C\x4C\x4C\x4C\x4C\x4C\x4C", 8),
        add_new_des_test_data("\x4D\x4D\x4D\x4D\x4D\x4D\x4D\x4D",
                              "\x4D\x4D\x4D\x4D\x4D\x4D\x4D\x4D",
                              "\xC7\x8F\xC4\x5A\x1D\xCE\xA2\xE2",
                              "\x4D\x4D\x4D\x4D\x4D\x4D\x4D\x4D", 8),
        add_new_des_test_data("\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E",
                              "\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E",
                              "\xDB\x96\xD8\x8C\x34\x60\xD8\x01",
                              "\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E", 8),
        add_new_des_test_data("\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F",
                              "\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F",
                              "\x6C\x69\xE7\x20\xF5\x10\x55\x18",
                              "\x4F\x4F\x4F\x4F\x4F\x4F\x4F\x4F", 8),
        add_new_des_test_data("\x50\x50\x50\x50\x50\x50\x50\x50",
                              "\x50\x50\x50\x50\x50\x50\x50\x50",
                              "\x0D\x26\x2E\x41\x8B\xC8\x93\xF3",
                              "\x50\x50\x50\x50\x50\x50\x50\x50", 8),
        add_new_des_test_data("\x51\x51\x51\x51\x51\x51\x51\x51",
                              "\x51\x51\x51\x51\x51\x51\x51\x51",
                              "\x6A\xD8\x4F\xD7\x84\x8A\x0A\x5C",
                              "\x51\x51\x51\x51\x51\x51\x51\x51", 8),
        add_new_des_test_data("\x52\x52\x52\x52\x52\x52\x52\x52",
                              "\x52\x52\x52\x52\x52\x52\x52\x52",
                              "\xC3\x65\xCB\x35\xB3\x4B\x61\x14",
                              "\x52\x52\x52\x52\x52\x52\x52\x52", 8),
        add_new_des_test_data("\x53\x53\x53\x53\x53\x53\x53\x53",
                              "\x53\x53\x53\x53\x53\x53\x53\x53",
                              "\x11\x55\x39\x2E\x87\x7F\x42\xA9",
                              "\x53\x53\x53\x53\x53\x53\x53\x53", 8),
        add_new_des_test_data("\x54\x54\x54\x54\x54\x54\x54\x54",
                              "\x54\x54\x54\x54\x54\x54\x54\x54",
                              "\x53\x1B\xE5\xF9\x40\x5D\xA7\x15",
                              "\x54\x54\x54\x54\x54\x54\x54\x54", 8),
        add_new_des_test_data("\x55\x55\x55\x55\x55\x55\x55\x55",
                              "\x55\x55\x55\x55\x55\x55\x55\x55",
                              "\x3B\xCD\xD4\x1E\x61\x65\xA5\xE8",
                              "\x55\x55\x55\x55\x55\x55\x55\x55", 8),
        add_new_des_test_data("\x56\x56\x56\x56\x56\x56\x56\x56",
                              "\x56\x56\x56\x56\x56\x56\x56\x56",
                              "\x2B\x1F\xF5\x61\x0A\x19\x27\x0C",
                              "\x56\x56\x56\x56\x56\x56\x56\x56", 8),
        add_new_des_test_data("\x57\x57\x57\x57\x57\x57\x57\x57",
                              "\x57\x57\x57\x57\x57\x57\x57\x57",
                              "\xD9\x07\x72\xCF\x3F\x04\x7C\xFD",
                              "\x57\x57\x57\x57\x57\x57\x57\x57", 8),
        add_new_des_test_data("\x58\x58\x58\x58\x58\x58\x58\x58",
                              "\x58\x58\x58\x58\x58\x58\x58\x58",
                              "\x1B\xEA\x27\xFF\xB7\x24\x57\xB7",
                              "\x58\x58\x58\x58\x58\x58\x58\x58", 8),
        add_new_des_test_data("\x59\x59\x59\x59\x59\x59\x59\x59",
                              "\x59\x59\x59\x59\x59\x59\x59\x59",
                              "\x85\xC3\xE0\xC4\x29\xF3\x4C\x27",
                              "\x59\x59\x59\x59\x59\x59\x59\x59", 8),
        add_new_des_test_data("\x5A\x5A\x5A\x5A\x5A\x5A\x5A\x5A",
                              "\x5A\x5A\x5A\x5A\x5A\x5A\x5A\x5A",
                              "\xF9\x03\x80\x21\xE3\x7C\x76\x18",
                              "\x5A\x5A\x5A\x5A\x5A\x5A\x5A\x5A", 8),
        add_new_des_test_data("\x5B\x5B\x5B\x5B\x5B\x5B\x5B\x5B",
                              "\x5B\x5B\x5B\x5B\x5B\x5B\x5B\x5B",
                              "\x35\xBC\x6F\xF8\x38\xDB\xA3\x2F",
                              "\x5B\x5B\x5B\x5B\x5B\x5B\x5B\x5B", 8),
        add_new_des_test_data("\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C",
                              "\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C",
                              "\x49\x27\xAC\xC8\xCE\x45\xEC\xE7",
                              "\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C", 8),
        add_new_des_test_data("\x5D\x5D\x5D\x5D\x5D\x5D\x5D\x5D",
                              "\x5D\x5D\x5D\x5D\x5D\x5D\x5D\x5D",
                              "\xE8\x12\xEE\x6E\x35\x72\x98\x5C",
                              "\x5D\x5D\x5D\x5D\x5D\x5D\x5D\x5D", 8),
        add_new_des_test_data("\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E",
                              "\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E",
                              "\x9B\xB9\x3A\x89\x62\x7B\xF6\x5F",
                              "\x5E\x5E\x5E\x5E\x5E\x5E\x5E\x5E", 8),
        add_new_des_test_data("\x5F\x5F\x5F\x5F\x5F\x5F\x5F\x5F",
                              "\x5F\x5F\x5F\x5F\x5F\x5F\x5F\x5F",
                              "\xEF\x12\x47\x68\x84\xCB\x74\xCA",
                              "\x5F\x5F\x5F\x5F\x5F\x5F\x5F\x5F", 8),
        add_new_des_test_data("\x60\x60\x60\x60\x60\x60\x60\x60",
                              "\x60\x60\x60\x60\x60\x60\x60\x60",
                              "\x1B\xF1\x7E\x00\xC0\x9E\x7C\xBF",
                              "\x60\x60\x60\x60\x60\x60\x60\x60", 8),
        add_new_des_test_data("\x61\x61\x61\x61\x61\x61\x61\x61",
                              "\x61\x61\x61\x61\x61\x61\x61\x61",
                              "\x29\x93\x23\x50\xC0\x98\xDB\x5D",
                              "\x61\x61\x61\x61\x61\x61\x61\x61", 8),
        add_new_des_test_data("\x62\x62\x62\x62\x62\x62\x62\x62",
                              "\x62\x62\x62\x62\x62\x62\x62\x62",
                              "\xB4\x76\xE6\x49\x98\x42\xAC\x54",
                              "\x62\x62\x62\x62\x62\x62\x62\x62", 8),
        add_new_des_test_data("\x63\x63\x63\x63\x63\x63\x63\x63",
                              "\x63\x63\x63\x63\x63\x63\x63\x63",
                              "\x5C\x66\x2C\x29\xC1\xE9\x60\x56",
                              "\x63\x63\x63\x63\x63\x63\x63\x63", 8),
        add_new_des_test_data("\x64\x64\x64\x64\x64\x64\x64\x64",
                              "\x64\x64\x64\x64\x64\x64\x64\x64",
                              "\x3A\xF1\x70\x3D\x76\x44\x27\x89",
                              "\x64\x64\x64\x64\x64\x64\x64\x64", 8),
        add_new_des_test_data("\x65\x65\x65\x65\x65\x65\x65\x65",
                              "\x65\x65\x65\x65\x65\x65\x65\x65",
                              "\x86\x40\x5D\x9B\x42\x5A\x8C\x8C",
                              "\x65\x65\x65\x65\x65\x65\x65\x65", 8),
        add_new_des_test_data("\x66\x66\x66\x66\x66\x66\x66\x66",
                              "\x66\x66\x66\x66\x66\x66\x66\x66",
                              "\xEB\xBF\x48\x10\x61\x9C\x2C\x55",
                              "\x66\x66\x66\x66\x66\x66\x66\x66", 8),
        add_new_des_test_data("\x67\x67\x67\x67\x67\x67\x67\x67",
                              "\x67\x67\x67\x67\x67\x67\x67\x67",
                              "\xF8\xD1\xCD\x73\x67\xB2\x1B\x5D",
                              "\x67\x67\x67\x67\x67\x67\x67\x67", 8),
        add_new_des_test_data("\x68\x68\x68\x68\x68\x68\x68\x68",
                              "\x68\x68\x68\x68\x68\x68\x68\x68",
                              "\x9E\xE7\x03\x14\x2B\xF8\xD7\xE2",
                              "\x68\x68\x68\x68\x68\x68\x68\x68", 8),
        add_new_des_test_data("\x69\x69\x69\x69\x69\x69\x69\x69",
                              "\x69\x69\x69\x69\x69\x69\x69\x69",
                              "\x5F\xDF\xFF\xC3\xAA\xAB\x0C\xB3",
                              "\x69\x69\x69\x69\x69\x69\x69\x69", 8),
        add_new_des_test_data("\x6A\x6A\x6A\x6A\x6A\x6A\x6A\x6A",
                              "\x6A\x6A\x6A\x6A\x6A\x6A\x6A\x6A",
                              "\x26\xC9\x40\xAB\x13\x57\x42\x31",
                              "\x6A\x6A\x6A\x6A\x6A\x6A\x6A\x6A", 8),
        add_new_des_test_data("\x6B\x6B\x6B\x6B\x6B\x6B\x6B\x6B",
                              "\x6B\x6B\x6B\x6B\x6B\x6B\x6B\x6B",
                              "\x1E\x2D\xC7\x7E\x36\xA8\x46\x93",
                              "\x6B\x6B\x6B\x6B\x6B\x6B\x6B\x6B", 8),
        add_new_des_test_data("\x6C\x6C\x6C\x6C\x6C\x6C\x6C\x6C",
                              "\x6C\x6C\x6C\x6C\x6C\x6C\x6C\x6C",
                              "\x0F\x4F\xF4\xD9\xBC\x7E\x22\x44",
                              "\x6C\x6C\x6C\x6C\x6C\x6C\x6C\x6C", 8),
        add_new_des_test_data("\x6D\x6D\x6D\x6D\x6D\x6D\x6D\x6D",
                              "\x6D\x6D\x6D\x6D\x6D\x6D\x6D\x6D",
                              "\xA4\xC9\xA0\xD0\x4D\x32\x80\xCD",
                              "\x6D\x6D\x6D\x6D\x6D\x6D\x6D\x6D", 8),
        add_new_des_test_data("\x6E\x6E\x6E\x6E\x6E\x6E\x6E\x6E",
                              "\x6E\x6E\x6E\x6E\x6E\x6E\x6E\x6E",
                              "\x9F\xAF\x2C\x96\xFE\x84\x91\x9D",
                              "\x6E\x6E\x6E\x6E\x6E\x6E\x6E\x6E", 8),
        add_new_des_test_data("\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F",
                              "\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F",
                              "\x11\x5D\xBC\x96\x5E\x60\x96\xC8",
                              "\x6F\x6F\x6F\x6F\x6F\x6F\x6F\x6F", 8),
        add_new_des_test_data("\x70\x70\x70\x70\x70\x70\x70\x70",
                              "\x70\x70\x70\x70\x70\x70\x70\x70",
                              "\xAF\x53\x1E\x95\x20\x99\x40\x17",
                              "\x70\x70\x70\x70\x70\x70\x70\x70", 8),
        add_new_des_test_data("\x71\x71\x71\x71\x71\x71\x71\x71",
                              "\x71\x71\x71\x71\x71\x71\x71\x71",
                              "\xB9\x71\xAD\xE7\x0E\x5C\x89\xEE",
                              "\x71\x71\x71\x71\x71\x71\x71\x71", 8),
        add_new_des_test_data("\x72\x72\x72\x72\x72\x72\x72\x72",
                              "\x72\x72\x72\x72\x72\x72\x72\x72",
                              "\x41\x5D\x81\xC8\x6A\xF9\xC3\x76",
                              "\x72\x72\x72\x72\x72\x72\x72\x72", 8),
        add_new_des_test_data("\x73\x73\x73\x73\x73\x73\x73\x73",
                              "\x73\x73\x73\x73\x73\x73\x73\x73",
                              "\x8D\xFB\x86\x4F\xDB\x3C\x68\x11",
                              "\x73\x73\x73\x73\x73\x73\x73\x73", 8),
        add_new_des_test_data("\x74\x74\x74\x74\x74\x74\x74\x74",
                              "\x74\x74\x74\x74\x74\x74\x74\x74",
                              "\x10\xB1\xC1\x70\xE3\x39\x8F\x91",
                              "\x74\x74\x74\x74\x74\x74\x74\x74", 8),
        add_new_des_test_data("\x75\x75\x75\x75\x75\x75\x75\x75",
                              "\x75\x75\x75\x75\x75\x75\x75\x75",
                              "\xCF\xEF\x7A\x1C\x02\x18\xDB\x1E",
                              "\x75\x75\x75\x75\x75\x75\x75\x75", 8),
        add_new_des_test_data("\x76\x76\x76\x76\x76\x76\x76\x76",
                              "\x76\x76\x76\x76\x76\x76\x76\x76",
                              "\xDB\xAC\x30\xA2\xA4\x0B\x1B\x9C",
                              "\x76\x76\x76\x76\x76\x76\x76\x76", 8),
        add_new_des_test_data("\x77\x77\x77\x77\x77\x77\x77\x77",
                              "\x77\x77\x77\x77\x77\x77\x77\x77",
                              "\x89\xD3\xBF\x37\x05\x21\x62\xE9",
                              "\x77\x77\x77\x77\x77\x77\x77\x77", 8),
        add_new_des_test_data("\x78\x78\x78\x78\x78\x78\x78\x78",
                              "\x78\x78\x78\x78\x78\x78\x78\x78",
                              "\x80\xD9\x23\x0B\xDA\xEB\x67\xDC",
                              "\x78\x78\x78\x78\x78\x78\x78\x78", 8),
        add_new_des_test_data("\x79\x79\x79\x79\x79\x79\x79\x79",
                              "\x79\x79\x79\x79\x79\x79\x79\x79",
                              "\x34\x40\x91\x10\x19\xAD\x68\xD7",
                              "\x79\x79\x79\x79\x79\x79\x79\x79", 8),
        add_new_des_test_data("\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A",
                              "\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A",
                              "\x96\x26\xFE\x57\x59\x6E\x19\x9E",
                              "\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A", 8),
        add_new_des_test_data("\x7B\x7B\x7B\x7B\x7B\x7B\x7B\x7B",
                              "\x7B\x7B\x7B\x7B\x7B\x7B\x7B\x7B",
                              "\xDE\xA0\xB7\x96\x62\x4B\xB5\xBA",
                              "\x7B\x7B\x7B\x7B\x7B\x7B\x7B\x7B", 8),
        add_new_des_test_data("\x7C\x7C\x7C\x7C\x7C\x7C\x7C\x7C",
                              "\x7C\x7C\x7C\x7C\x7C\x7C\x7C\x7C",
                              "\xE9\xE4\x05\x42\xBD\xDB\x3E\x9D",
                              "\x7C\x7C\x7C\x7C\x7C\x7C\x7C\x7C", 8),
        add_new_des_test_data("\x7D\x7D\x7D\x7D\x7D\x7D\x7D\x7D",
                              "\x7D\x7D\x7D\x7D\x7D\x7D\x7D\x7D",
                              "\x8A\xD9\x99\x14\xB3\x54\xB9\x11",
                              "\x7D\x7D\x7D\x7D\x7D\x7D\x7D\x7D", 8),
        add_new_des_test_data("\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E",
                              "\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E",
                              "\x6F\x85\xB9\x8D\xD1\x2C\xB1\x3B",
                              "\x7E\x7E\x7E\x7E\x7E\x7E\x7E\x7E", 8),
        add_new_des_test_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                              "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                              "\x10\x13\x0D\xA3\xC3\xA2\x39\x24",
                              "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F", 8),
        add_new_des_test_data("\x80\x80\x80\x80\x80\x80\x80\x80",
                              "\x80\x80\x80\x80\x80\x80\x80\x80",
                              "\xEF\xEC\xF2\x5C\x3C\x5D\xC6\xDB",
                              "\x80\x80\x80\x80\x80\x80\x80\x80", 8),
        add_new_des_test_data("\x81\x81\x81\x81\x81\x81\x81\x81",
                              "\x81\x81\x81\x81\x81\x81\x81\x81",
                              "\x90\x7A\x46\x72\x2E\xD3\x4E\xC4",
                              "\x81\x81\x81\x81\x81\x81\x81\x81", 8),
        add_new_des_test_data("\x82\x82\x82\x82\x82\x82\x82\x82",
                              "\x82\x82\x82\x82\x82\x82\x82\x82",
                              "\x75\x26\x66\xEB\x4C\xAB\x46\xEE",
                              "\x82\x82\x82\x82\x82\x82\x82\x82", 8),
        add_new_des_test_data("\x83\x83\x83\x83\x83\x83\x83\x83",
                              "\x83\x83\x83\x83\x83\x83\x83\x83",
                              "\x16\x1B\xFA\xBD\x42\x24\xC1\x62",
                              "\x83\x83\x83\x83\x83\x83\x83\x83", 8),
        add_new_des_test_data("\x84\x84\x84\x84\x84\x84\x84\x84",
                              "\x84\x84\x84\x84\x84\x84\x84\x84",
                              "\x21\x5F\x48\x69\x9D\xB4\x4A\x45",
                              "\x84\x84\x84\x84\x84\x84\x84\x84", 8),
        add_new_des_test_data("\x85\x85\x85\x85\x85\x85\x85\x85",
                              "\x85\x85\x85\x85\x85\x85\x85\x85",
                              "\x69\xD9\x01\xA8\xA6\x91\xE6\x61",
                              "\x85\x85\x85\x85\x85\x85\x85\x85", 8),
        add_new_des_test_data("\x86\x86\x86\x86\x86\x86\x86\x86",
                              "\x86\x86\x86\x86\x86\x86\x86\x86",
                              "\xCB\xBF\x6E\xEF\xE6\x52\x97\x28",
                              "\x86\x86\x86\x86\x86\x86\x86\x86", 8),
        add_new_des_test_data("\x87\x87\x87\x87\x87\x87\x87\x87",
                              "\x87\x87\x87\x87\x87\x87\x87\x87",
                              "\x7F\x26\xDC\xF4\x25\x14\x98\x23",
                              "\x87\x87\x87\x87\x87\x87\x87\x87", 8),
        add_new_des_test_data("\x88\x88\x88\x88\x88\x88\x88\x88",
                              "\x88\x88\x88\x88\x88\x88\x88\x88",
                              "\x76\x2C\x40\xC8\xFA\xDE\x9D\x16",
                              "\x88\x88\x88\x88\x88\x88\x88\x88", 8),
        add_new_des_test_data("\x89\x89\x89\x89\x89\x89\x89\x89",
                              "\x89\x89\x89\x89\x89\x89\x89\x89",
                              "\x24\x53\xCF\x5D\x5B\xF4\xE4\x63",
                              "\x89\x89\x89\x89\x89\x89\x89\x89", 8),
        add_new_des_test_data("\x8A\x8A\x8A\x8A\x8A\x8A\x8A\x8A",
                              "\x8A\x8A\x8A\x8A\x8A\x8A\x8A\x8A",
                              "\x30\x10\x85\xE3\xFD\xE7\x24\xE1",
                              "\x8A\x8A\x8A\x8A\x8A\x8A\x8A\x8A", 8),
        add_new_des_test_data("\x8B\x8B\x8B\x8B\x8B\x8B\x8B\x8B",
                              "\x8B\x8B\x8B\x8B\x8B\x8B\x8B\x8B",
                              "\xEF\x4E\x3E\x8F\x1C\xC6\x70\x6E",
                              "\x8B\x8B\x8B\x8B\x8B\x8B\x8B\x8B", 8),
        add_new_des_test_data("\x8C\x8C\x8C\x8C\x8C\x8C\x8C\x8C",
                              "\x8C\x8C\x8C\x8C\x8C\x8C\x8C\x8C",
                              "\x72\x04\x79\xB0\x24\xC3\x97\xEE",
                              "\x8C\x8C\x8C\x8C\x8C\x8C\x8C\x8C", 8),
        add_new_des_test_data("\x8D\x8D\x8D\x8D\x8D\x8D\x8D\x8D",
                              "\x8D\x8D\x8D\x8D\x8D\x8D\x8D\x8D",
                              "\xBE\xA2\x7E\x37\x95\x06\x3C\x89",
                              "\x8D\x8D\x8D\x8D\x8D\x8D\x8D\x8D", 8),
        add_new_des_test_data("\x8E\x8E\x8E\x8E\x8E\x8E\x8E\x8E",
                              "\x8E\x8E\x8E\x8E\x8E\x8E\x8E\x8E",
                              "\x46\x8E\x52\x18\xF1\xA3\x76\x11",
                              "\x8E\x8E\x8E\x8E\x8E\x8E\x8E\x8E", 8),
        add_new_des_test_data("\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F",
                              "\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F",
                              "\x50\xAC\xE1\x6A\xDF\x66\xBF\xE8",
                              "\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F", 8),
        add_new_des_test_data("\x90\x90\x90\x90\x90\x90\x90\x90",
                              "\x90\x90\x90\x90\x90\x90\x90\x90",
                              "\xEE\xA2\x43\x69\xA1\x9F\x69\x37",
                              "\x90\x90\x90\x90\x90\x90\x90\x90", 8),
        add_new_des_test_data("\x91\x91\x91\x91\x91\x91\x91\x91",
                              "\x91\x91\x91\x91\x91\x91\x91\x91",
                              "\x60\x50\xD3\x69\x01\x7B\x6E\x62",
                              "\x91\x91\x91\x91\x91\x91\x91\x91", 8),
        add_new_des_test_data("\x92\x92\x92\x92\x92\x92\x92\x92",
                              "\x92\x92\x92\x92\x92\x92\x92\x92",
                              "\x5B\x36\x5F\x2F\xB2\xCD\x7F\x32",
                              "\x92\x92\x92\x92\x92\x92\x92\x92", 8),
        add_new_des_test_data("\x93\x93\x93\x93\x93\x93\x93\x93",
                              "\x93\x93\x93\x93\x93\x93\x93\x93",
                              "\xF0\xB0\x0B\x26\x43\x81\xDD\xBB",
                              "\x93\x93\x93\x93\x93\x93\x93\x93", 8),
        add_new_des_test_data("\x94\x94\x94\x94\x94\x94\x94\x94",
                              "\x94\x94\x94\x94\x94\x94\x94\x94",
                              "\xE1\xD2\x38\x81\xC9\x57\xB9\x6C",
                              "\x94\x94\x94\x94\x94\x94\x94\x94", 8),
        add_new_des_test_data("\x95\x95\x95\x95\x95\x95\x95\x95",
                              "\x95\x95\x95\x95\x95\x95\x95\x95",
                              "\xD9\x36\xBF\x54\xEC\xA8\xBD\xCE",
                              "\x95\x95\x95\x95\x95\x95\x95\x95", 8),
        add_new_des_test_data("\x96\x96\x96\x96\x96\x96\x96\x96",
                              "\x96\x96\x96\x96\x96\x96\x96\x96",
                              "\xA0\x20\x00\x3C\x55\x54\xF3\x4C",
                              "\x96\x96\x96\x96\x96\x96\x96\x96", 8),
        add_new_des_test_data("\x97\x97\x97\x97\x97\x97\x97\x97",
                              "\x97\x97\x97\x97\x97\x97\x97\x97",
                              "\x61\x18\xFC\xEB\xD4\x07\x28\x1D",
                              "\x97\x97\x97\x97\x97\x97\x97\x97", 8),
        add_new_des_test_data("\x98\x98\x98\x98\x98\x98\x98\x98",
                              "\x98\x98\x98\x98\x98\x98\x98\x98",
                              "\x07\x2E\x32\x8C\x98\x4D\xE4\xA2",
                              "\x98\x98\x98\x98\x98\x98\x98\x98", 8),
        add_new_des_test_data("\x99\x99\x99\x99\x99\x99\x99\x99",
                              "\x99\x99\x99\x99\x99\x99\x99\x99",
                              "\x14\x40\xB7\xEF\x9E\x63\xD3\xAA",
                              "\x99\x99\x99\x99\x99\x99\x99\x99", 8),
        add_new_des_test_data("\x9A\x9A\x9A\x9A\x9A\x9A\x9A\x9A",
                              "\x9A\x9A\x9A\x9A\x9A\x9A\x9A\x9A",
                              "\x79\xBF\xA2\x64\xBD\xA5\x73\x73",
                              "\x9A\x9A\x9A\x9A\x9A\x9A\x9A\x9A", 8),
        add_new_des_test_data("\x9B\x9B\x9B\x9B\x9B\x9B\x9B\x9B",
                              "\x9B\x9B\x9B\x9B\x9B\x9B\x9B\x9B",
                              "\xC5\x0E\x8F\xC2\x89\xBB\xD8\x76",
                              "\x9B\x9B\x9B\x9B\x9B\x9B\x9B\x9B", 8),
        add_new_des_test_data("\x9C\x9C\x9C\x9C\x9C\x9C\x9C\x9C",
                              "\x9C\x9C\x9C\x9C\x9C\x9C\x9C\x9C",
                              "\xA3\x99\xD3\xD6\x3E\x16\x9F\xA9",
                              "\x9C\x9C\x9C\x9C\x9C\x9C\x9C\x9C", 8),
        add_new_des_test_data("\x9D\x9D\x9D\x9D\x9D\x9D\x9D\x9D",
                              "\x9D\x9D\x9D\x9D\x9D\x9D\x9D\x9D",
                              "\x4B\x89\x19\xB6\x67\xBD\x53\xAB",
                              "\x9D\x9D\x9D\x9D\x9D\x9D\x9D\x9D", 8),
        add_new_des_test_data("\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E",
                              "\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E",
                              "\xD6\x6C\xDC\xAF\x3F\x67\x24\xA2",
                              "\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E", 8),
        add_new_des_test_data("\x9F\x9F\x9F\x9F\x9F\x9F\x9F\x9F",
                              "\x9F\x9F\x9F\x9F\x9F\x9F\x9F\x9F",
                              "\xE4\x0E\x81\xFF\x3F\x61\x83\x40",
                              "\x9F\x9F\x9F\x9F\x9F\x9F\x9F\x9F", 8),
        add_new_des_test_data("\xA0\xA0\xA0\xA0\xA0\xA0\xA0\xA0",
                              "\xA0\xA0\xA0\xA0\xA0\xA0\xA0\xA0",
                              "\x10\xED\xB8\x97\x7B\x34\x8B\x35",
                              "\xA0\xA0\xA0\xA0\xA0\xA0\xA0\xA0", 8),
        add_new_des_test_data("\xA1\xA1\xA1\xA1\xA1\xA1\xA1\xA1",
                              "\xA1\xA1\xA1\xA1\xA1\xA1\xA1\xA1",
                              "\x64\x46\xC5\x76\x9D\x84\x09\xA0",
                              "\xA1\xA1\xA1\xA1\xA1\xA1\xA1\xA1", 8),
        add_new_des_test_data("\xA2\xA2\xA2\xA2\xA2\xA2\xA2\xA2",
                              "\xA2\xA2\xA2\xA2\xA2\xA2\xA2\xA2",
                              "\x17\xED\x11\x91\xCA\x8D\x67\xA3",
                              "\xA2\xA2\xA2\xA2\xA2\xA2\xA2\xA2", 8),
        add_new_des_test_data("\xA3\xA3\xA3\xA3\xA3\xA3\xA3\xA3",
                              "\xA3\xA3\xA3\xA3\xA3\xA3\xA3\xA3",
                              "\xB6\xD8\x53\x37\x31\xBA\x13\x18",
                              "\xA3\xA3\xA3\xA3\xA3\xA3\xA3\xA3", 8),
        add_new_des_test_data("\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4",
                              "\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4",
                              "\xCA\x43\x90\x07\xC7\x24\x5C\xD0",
                              "\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4", 8),
        add_new_des_test_data("\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5",
                              "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5",
                              "\x06\xFC\x7F\xDE\x1C\x83\x89\xE7",
                              "\xA5\xA5\xA5\xA5\xA5\xA5\xA5\xA5", 8),
        add_new_des_test_data("\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6",
                              "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6",
                              "\x7A\x3C\x1F\x3B\xD6\x0C\xB3\xD8",
                              "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6", 8),
        add_new_des_test_data("\xA7\xA7\xA7\xA7\xA7\xA7\xA7\xA7",
                              "\xA7\xA7\xA7\xA7\xA7\xA7\xA7\xA7",
                              "\xE4\x15\xD8\x00\x48\xDB\xA8\x48",
                              "\xA7\xA7\xA7\xA7\xA7\xA7\xA7\xA7", 8),
        add_new_des_test_data("\xA8\xA8\xA8\xA8\xA8\xA8\xA8\xA8",
                              "\xA8\xA8\xA8\xA8\xA8\xA8\xA8\xA8",
                              "\x26\xF8\x8D\x30\xC0\xFB\x83\x02",
                              "\xA8\xA8\xA8\xA8\xA8\xA8\xA8\xA8", 8),
        add_new_des_test_data("\xA9\xA9\xA9\xA9\xA9\xA9\xA9\xA9",
                              "\xA9\xA9\xA9\xA9\xA9\xA9\xA9\xA9",
                              "\xD4\xE0\x0A\x9E\xF5\xE6\xD8\xF3",
                              "\xA9\xA9\xA9\xA9\xA9\xA9\xA9\xA9", 8),
        add_new_des_test_data("\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
                              "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
                              "\xC4\x32\x2B\xE1\x9E\x9A\x5A\x17",
                              "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 8),
        add_new_des_test_data("\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB",
                              "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB",
                              "\xAC\xE4\x1A\x06\xBF\xA2\x58\xEA",
                              "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB", 8),
        add_new_des_test_data("\xAC\xAC\xAC\xAC\xAC\xAC\xAC\xAC",
                              "\xAC\xAC\xAC\xAC\xAC\xAC\xAC\xAC",
                              "\xEE\xAA\xC6\xD1\x78\x80\xBD\x56",
                              "\xAC\xAC\xAC\xAC\xAC\xAC\xAC\xAC", 8),
        add_new_des_test_data("\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD",
                              "\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD",
                              "\x3C\x9A\x34\xCA\x4C\xB4\x9E\xEB",
                              "\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD", 8),
        add_new_des_test_data("\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE", // uhu!!
                              "\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE",
                              "\x95\x27\xB0\x28\x7B\x75\xF5\xA3",
                              "\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE", 8),
        add_new_des_test_data("\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF",
                              "\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF",
                              "\xF2\xD9\xD1\xBE\x74\x37\x6C\x0C",
                              "\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF", 8),
        add_new_des_test_data("\xB0\xB0\xB0\xB0\xB0\xB0\xB0\xB0",
                              "\xB0\xB0\xB0\xB0\xB0\xB0\xB0\xB0",
                              "\x93\x96\x18\xDF\x0A\xEF\xAA\xE7",
                              "\xB0\xB0\xB0\xB0\xB0\xB0\xB0\xB0", 8),
        add_new_des_test_data("\xB1\xB1\xB1\xB1\xB1\xB1\xB1\xB1",
                              "\xB1\xB1\xB1\xB1\xB1\xB1\xB1\xB1",
                              "\x24\x69\x27\x73\xCB\x9F\x27\xFE",
                              "\xB1\xB1\xB1\xB1\xB1\xB1\xB1\xB1", 8),
        add_new_des_test_data("\xB2\xB2\xB2\xB2\xB2\xB2\xB2\xB2",
                              "\xB2\xB2\xB2\xB2\xB2\xB2\xB2\xB2",
                              "\x38\x70\x3B\xA5\xE2\x31\x5D\x1D",
                              "\xB2\xB2\xB2\xB2\xB2\xB2\xB2\xB2", 8),
        add_new_des_test_data("\xB3\xB3\xB3\xB3\xB3\xB3\xB3\xB3",
                              "\xB3\xB3\xB3\xB3\xB3\xB3\xB3\xB3",
                              "\xFC\xB7\xE4\xB7\xD7\x02\xE2\xFB",
                              "\xB3\xB3\xB3\xB3\xB3\xB3\xB3\xB3", 8),
        add_new_des_test_data("\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4",
                              "\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4",
                              "\x36\xF0\xD0\xB3\x67\x57\x04\xD5",
                              "\xB4\xB4\xB4\xB4\xB4\xB4\xB4\xB4", 8),
        add_new_des_test_data("\xB5\xB5\xB5\xB5\xB5\xB5\xB5\xB5",
                              "\xB5\xB5\xB5\xB5\xB5\xB5\xB5\xB5",
                              "\x62\xD4\x73\xF5\x39\xFA\x0D\x8B",
                              "\xB5\xB5\xB5\xB5\xB5\xB5\xB5\xB5", 8),
        add_new_des_test_data("\xB6\xB6\xB6\xB6\xB6\xB6\xB6\xB6",
                              "\xB6\xB6\xB6\xB6\xB6\xB6\xB6\xB6",
                              "\x15\x33\xF3\xED\x9B\xE8\xEF\x8E",
                              "\xB6\xB6\xB6\xB6\xB6\xB6\xB6\xB6", 8),
        add_new_des_test_data("\xB7\xB7\xB7\xB7\xB7\xB7\xB7\xB7",
                              "\xB7\xB7\xB7\xB7\xB7\xB7\xB7\xB7",
                              "\x9C\x4E\xA3\x52\x59\x97\x31\xED",
                              "\xB7\xB7\xB7\xB7\xB7\xB7\xB7\xB7", 8),
        add_new_des_test_data("\xB8\xB8\xB8\xB8\xB8\xB8\xB8\xB8",
                              "\xB8\xB8\xB8\xB8\xB8\xB8\xB8\xB8",
                              "\xFA\xBB\xF7\xC0\x46\xFD\x27\x3F",
                              "\xB8\xB8\xB8\xB8\xB8\xB8\xB8\xB8", 8),
        add_new_des_test_data("\xB9\xB9\xB9\xB9\xB9\xB9\xB9\xB9",
                              "\xB9\xB9\xB9\xB9\xB9\xB9\xB9\xB9",
                              "\xB7\xFE\x63\xA6\x1C\x64\x6F\x3A",
                              "\xB9\xB9\xB9\xB9\xB9\xB9\xB9\xB9", 8),
        add_new_des_test_data("\xBA\xBA\xBA\xBA\xBA\xBA\xBA\xBA",
                              "\xBA\xBA\xBA\xBA\xBA\xBA\xBA\xBA",
                              "\x10\xAD\xB6\xE2\xAB\x97\x2B\xBE",
                              "\xBA\xBA\xBA\xBA\xBA\xBA\xBA\xBA", 8),
        add_new_des_test_data("\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB",
                              "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB",
                              "\xF9\x1D\xCA\xD9\x12\x33\x2F\x3B",
                              "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB", 8),
        add_new_des_test_data("\xBC\xBC\xBC\xBC\xBC\xBC\xBC\xBC",
                              "\xBC\xBC\xBC\xBC\xBC\xBC\xBC\xBC",
                              "\x46\xE7\xEF\x47\x32\x3A\x70\x1D",
                              "\xBC\xBC\xBC\xBC\xBC\xBC\xBC\xBC", 8),
        add_new_des_test_data("\xBD\xBD\xBD\xBD\xBD\xBD\xBD\xBD",
                              "\xBD\xBD\xBD\xBD\xBD\xBD\xBD\xBD",
                              "\x8D\xB1\x8C\xCD\x96\x92\xF7\x58",
                              "\xBD\xBD\xBD\xBD\xBD\xBD\xBD\xBD", 8),
        add_new_des_test_data("\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE",
                              "\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE",
                              "\xE6\x20\x7B\x53\x6A\xAA\xEF\xFC",
                              "\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE", 8),
        add_new_des_test_data("\xBF\xBF\xBF\xBF\xBF\xBF\xBF\xBF",
                              "\xBF\xBF\xBF\xBF\xBF\xBF\xBF\xBF",
                              "\x92\xAA\x22\x43\x72\x15\x6A\x00",
                              "\xBF\xBF\xBF\xBF\xBF\xBF\xBF\xBF", 8),
        add_new_des_test_data("\xC0\xC0\xC0\xC0\xC0\xC0\xC0\xC0",
                              "\xC0\xC0\xC0\xC0\xC0\xC0\xC0\xC0",
                              "\xA3\xB3\x57\x88\x5B\x1E\x16\xD2",
                              "\xC0\xC0\xC0\xC0\xC0\xC0\xC0\xC0", 8),
        add_new_des_test_data("\xC1\xC1\xC1\xC1\xC1\xC1\xC1\xC1",
                              "\xC1\xC1\xC1\xC1\xC1\xC1\xC1\xC1",
                              "\x16\x9F\x76\x29\xC9\x70\xC1\xE5",
                              "\xC1\xC1\xC1\xC1\xC1\xC1\xC1\xC1", 8),
        add_new_des_test_data("\xC2\xC2\xC2\xC2\xC2\xC2\xC2\xC2",
                              "\xC2\xC2\xC2\xC2\xC2\xC2\xC2\xC2",
                              "\x62\xF4\x4B\x24\x7C\xF1\x34\x8C",
                              "\xC2\xC2\xC2\xC2\xC2\xC2\xC2\xC2", 8),
        add_new_des_test_data("\xC3\xC3\xC3\xC3\xC3\xC3\xC3\xC3",
                              "\xC3\xC3\xC3\xC3\xC3\xC3\xC3\xC3",
                              "\xAE\x0F\xEE\xB0\x49\x59\x32\xC8",
                              "\xC3\xC3\xC3\xC3\xC3\xC3\xC3\xC3", 8),
        add_new_des_test_data("\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4",
                              "\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4",
                              "\x72\xDA\xF2\xA7\xC9\xEA\x68\x03",
                              "\xC4\xC4\xC4\xC4\xC4\xC4\xC4\xC4", 8),
        add_new_des_test_data("\xC5\xC5\xC5\xC5\xC5\xC5\xC5\xC5",
                              "\xC5\xC5\xC5\xC5\xC5\xC5\xC5\xC5",
                              "\x4F\xB5\xD5\x53\x6D\xA5\x44\xF4",
                              "\xC5\xC5\xC5\xC5\xC5\xC5\xC5\xC5", 8),
        add_new_des_test_data("\xC6\xC6\xC6\xC6\xC6\xC6\xC6\xC6",
                              "\xC6\xC6\xC6\xC6\xC6\xC6\xC6\xC6",
                              "\x1D\xD4\xE6\x5A\xAF\x79\x88\xB4",
                              "\xC6\xC6\xC6\xC6\xC6\xC6\xC6\xC6", 8),
        add_new_des_test_data("\xC7\xC7\xC7\xC7\xC7\xC7\xC7\xC7",
                              "\xC7\xC7\xC7\xC7\xC7\xC7\xC7\xC7",
                              "\x76\xBF\x08\x4C\x15\x35\xA6\xC6",
                              "\xC7\xC7\xC7\xC7\xC7\xC7\xC7\xC7", 8),
        add_new_des_test_data("\xC8\xC8\xC8\xC8\xC8\xC8\xC8\xC8",
                              "\xC8\xC8\xC8\xC8\xC8\xC8\xC8\xC8",
                              "\xAF\xEC\x35\xB0\x9D\x36\x31\x5F",
                              "\xC8\xC8\xC8\xC8\xC8\xC8\xC8\xC8", 8),
        add_new_des_test_data("\xC9\xC9\xC9\xC9\xC9\xC9\xC9\xC9",
                              "\xC9\xC9\xC9\xC9\xC9\xC9\xC9\xC9",
                              "\xC8\x07\x8A\x61\x48\x81\x84\x03",
                              "\xC9\xC9\xC9\xC9\xC9\xC9\xC9\xC9", 8),
        add_new_des_test_data("\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA",
                              "\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA",
                              "\x4D\xA9\x1C\xB4\x12\x4B\x67\xFE",
                              "\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA", 8),
        add_new_des_test_data("\xCB\xCB\xCB\xCB\xCB\xCB\xCB\xCB",
                              "\xCB\xCB\xCB\xCB\xCB\xCB\xCB\xCB",
                              "\x2D\xAB\xFE\xB3\x46\x79\x4C\x3D",
                              "\xCB\xCB\xCB\xCB\xCB\xCB\xCB\xCB", 8),
        add_new_des_test_data("\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                              "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                              "\xFB\xCD\x12\xC7\x90\xD2\x1C\xD7",
                              "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", 8),
        add_new_des_test_data("\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD",
                              "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD",
                              "\x53\x68\x73\xDB\x87\x9C\xC7\x70",
                              "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD", 8),
        add_new_des_test_data("\xCE\xCE\xCE\xCE\xCE\xCE\xCE\xCE",
                              "\xCE\xCE\xCE\xCE\xCE\xCE\xCE\xCE",
                              "\x9A\xA1\x59\xD7\x30\x9D\xA7\xA0",
                              "\xCE\xCE\xCE\xCE\xCE\xCE\xCE\xCE", 8),
        add_new_des_test_data("\xCF\xCF\xCF\xCF\xCF\xCF\xCF\xCF",
                              "\xCF\xCF\xCF\xCF\xCF\xCF\xCF\xCF",
                              "\x0B\x84\x4B\x9D\x8C\x4E\xA1\x4A",
                              "\xCF\xCF\xCF\xCF\xCF\xCF\xCF\xCF", 8),
        add_new_des_test_data("\xD0\xD0\xD0\xD0\xD0\xD0\xD0\xD0",
                              "\xD0\xD0\xD0\xD0\xD0\xD0\xD0\xD0",
                              "\x3B\xBD\x84\xCE\x53\x9E\x68\xC4",
                              "\xD0\xD0\xD0\xD0\xD0\xD0\xD0\xD0", 8),
        add_new_des_test_data("\xD1\xD1\xD1\xD1\xD1\xD1\xD1\xD1",
                              "\xD1\xD1\xD1\xD1\xD1\xD1\xD1\xD1",
                              "\xCF\x3E\x4F\x3E\x02\x6E\x2C\x8E",
                              "\xD1\xD1\xD1\xD1\xD1\xD1\xD1\xD1", 8),
        add_new_des_test_data("\xD2\xD2\xD2\xD2\xD2\xD2\xD2\xD2",
                              "\xD2\xD2\xD2\xD2\xD2\xD2\xD2\xD2",
                              "\x82\xF8\x58\x85\xD5\x42\xAF\x58",
                              "\xD2\xD2\xD2\xD2\xD2\xD2\xD2\xD2", 8),
        add_new_des_test_data("\xD3\xD3\xD3\xD3\xD3\xD3\xD3\xD3",
                              "\xD3\xD3\xD3\xD3\xD3\xD3\xD3\xD3",
                              "\x22\xD3\x34\xD6\x49\x3B\x3C\xB6",
                              "\xD3\xD3\xD3\xD3\xD3\xD3\xD3\xD3", 8),
        add_new_des_test_data("\xD4\xD4\xD4\xD4\xD4\xD4\xD4\xD4",
                              "\xD4\xD4\xD4\xD4\xD4\xD4\xD4\xD4",
                              "\x47\xE9\xCB\x3E\x31\x54\xD6\x73",
                              "\xD4\xD4\xD4\xD4\xD4\xD4\xD4\xD4", 8),
        add_new_des_test_data("\xD5\xD5\xD5\xD5\xD5\xD5\xD5\xD5",
                              "\xD5\xD5\xD5\xD5\xD5\xD5\xD5\xD5",
                              "\x23\x52\xBC\xC7\x08\xAD\xC7\xE9",
                              "\xD5\xD5\xD5\xD5\xD5\xD5\xD5\xD5", 8),
        add_new_des_test_data("\xD6\xD6\xD6\xD6\xD6\xD6\xD6\xD6",
                              "\xD6\xD6\xD6\xD6\xD6\xD6\xD6\xD6",
                              "\x8C\x0F\x3B\xA0\xC8\x60\x19\x80",
                              "\xD6\xD6\xD6\xD6\xD6\xD6\xD6\xD6", 8),
        add_new_des_test_data("\xD7\xD7\xD7\xD7\xD7\xD7\xD7\xD7",
                              "\xD7\xD7\xD7\xD7\xD7\xD7\xD7\xD7",
                              "\xEE\x5E\x9F\xD7\x0C\xEF\x00\xE9",
                              "\xD7\xD7\xD7\xD7\xD7\xD7\xD7\xD7", 8),
        add_new_des_test_data("\xD8\xD8\xD8\xD8\xD8\xD8\xD8\xD8",
                              "\xD8\xD8\xD8\xD8\xD8\xD8\xD8\xD8",
                              "\xDE\xF6\xBD\xA6\xCA\xBF\x95\x47",
                              "\xD8\xD8\xD8\xD8\xD8\xD8\xD8\xD8", 8),
        add_new_des_test_data("\xD9\xD9\xD9\xD9\xD9\xD9\xD9\xD9",
                              "\xD9\xD9\xD9\xD9\xD9\xD9\xD9\xD9",
                              "\x4D\xAD\xD0\x4A\x0E\xA7\x0F\x20",
                              "\xD9\xD9\xD9\xD9\xD9\xD9\xD9\xD9", 8),
        add_new_des_test_data("\xDA\xDA\xDA\xDA\xDA\xDA\xDA\xDA",
                              "\xDA\xDA\xDA\xDA\xDA\xDA\xDA\xDA",
                              "\xC1\xAA\x16\x68\x9E\xE1\xB4\x82",
                              "\xDA\xDA\xDA\xDA\xDA\xDA\xDA\xDA", 8),
        add_new_des_test_data("\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xDB",
                              "\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xDB",
                              "\xF4\x5F\xC2\x61\x93\xE6\x9A\xEE",
                              "\xDB\xDB\xDB\xDB\xDB\xDB\xDB\xDB", 8),
        add_new_des_test_data("\xDC\xDC\xDC\xDC\xDC\xDC\xDC\xDC",
                              "\xDC\xDC\xDC\xDC\xDC\xDC\xDC\xDC",
                              "\xD0\xCF\xBB\x93\x7C\xED\xBF\xB5",
                              "\xDC\xDC\xDC\xDC\xDC\xDC\xDC\xDC", 8),
        add_new_des_test_data("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD",
                              "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD",
                              "\xF0\x75\x20\x04\xEE\x23\xD8\x7B",
                              "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD", 8),
        add_new_des_test_data("\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE",
                              "\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE",
                              "\x77\xA7\x91\xE2\x8A\xA4\x64\xA5",
                              "\xDE\xDE\xDE\xDE\xDE\xDE\xDE\xDE", 8),
        add_new_des_test_data("\xDF\xDF\xDF\xDF\xDF\xDF\xDF\xDF",
                              "\xDF\xDF\xDF\xDF\xDF\xDF\xDF\xDF",
                              "\xE7\x56\x2A\x7F\x56\xFF\x49\x66",
                              "\xDF\xDF\xDF\xDF\xDF\xDF\xDF\xDF", 8),
        add_new_des_test_data("\xE0\xE0\xE0\xE0\xE0\xE0\xE0\xE0",
                              "\xE0\xE0\xE0\xE0\xE0\xE0\xE0\xE0",
                              "\xB0\x26\x91\x3F\x2C\xCF\xB1\x09",
                              "\xE0\xE0\xE0\xE0\xE0\xE0\xE0\xE0", 8),
        add_new_des_test_data("\xE1\xE1\xE1\xE1\xE1\xE1\xE1\xE1",
                              "\xE1\xE1\xE1\xE1\xE1\xE1\xE1\xE1",
                              "\x0D\xB5\x72\xDD\xCE\x38\x8A\xC7",
                              "\xE1\xE1\xE1\xE1\xE1\xE1\xE1\xE1", 8),
        add_new_des_test_data("\xE2\xE2\xE2\xE2\xE2\xE2\xE2\xE2",
                              "\xE2\xE2\xE2\xE2\xE2\xE2\xE2\xE2",
                              "\xD9\xFA\x65\x95\xF0\xC0\x94\xCA",
                              "\xE2\xE2\xE2\xE2\xE2\xE2\xE2\xE2", 8),
        add_new_des_test_data("\xE3\xE3\xE3\xE3\xE3\xE3\xE3\xE3",
                              "\xE3\xE3\xE3\xE3\xE3\xE3\xE3\xE3",
                              "\xAD\xE4\x80\x4C\x4B\xE4\x48\x6E",
                              "\xE3\xE3\xE3\xE3\xE3\xE3\xE3\xE3", 8),
        add_new_des_test_data("\xE4\xE4\xE4\xE4\xE4\xE4\xE4\xE4",
                              "\xE4\xE4\xE4\xE4\xE4\xE4\xE4\xE4",
                              "\x00\x7B\x81\xF5\x20\xE6\xD7\xDA",
                              "\xE4\xE4\xE4\xE4\xE4\xE4\xE4\xE4", 8),
        add_new_des_test_data("\xE5\xE5\xE5\xE5\xE5\xE5\xE5\xE5",
                              "\xE5\xE5\xE5\xE5\xE5\xE5\xE5\xE5",
                              "\x96\x1A\xEB\x77\xBF\xC1\x0B\x3C",
                              "\xE5\xE5\xE5\xE5\xE5\xE5\xE5\xE5", 8),
        add_new_des_test_data("\xE6\xE6\xE6\xE6\xE6\xE6\xE6\xE6",
                              "\xE6\xE6\xE6\xE6\xE6\xE6\xE6\xE6",
                              "\x8A\x8D\xD8\x70\xC9\xB1\x4A\xF2",
                              "\xE6\xE6\xE6\xE6\xE6\xE6\xE6\xE6", 8),
        add_new_des_test_data("\xE7\xE7\xE7\xE7\xE7\xE7\xE7\xE7",
                              "\xE7\xE7\xE7\xE7\xE7\xE7\xE7\xE7",
                              "\x3C\xC0\x2E\x14\xB6\x34\x9B\x25",
                              "\xE7\xE7\xE7\xE7\xE7\xE7\xE7\xE7", 8),
        add_new_des_test_data("\xE8\xE8\xE8\xE8\xE8\xE8\xE8\xE8",
                              "\xE8\xE8\xE8\xE8\xE8\xE8\xE8\xE8",
                              "\xBA\xD3\xEE\x68\xBD\xDB\x96\x07",
                              "\xE8\xE8\xE8\xE8\xE8\xE8\xE8\xE8", 8),
        add_new_des_test_data("\xE9\xE9\xE9\xE9\xE9\xE9\xE9\xE9",
                              "\xE9\xE9\xE9\xE9\xE9\xE9\xE9\xE9",
                              "\xDF\xF9\x18\xE9\x3B\xDA\xD2\x92",
                              "\xE9\xE9\xE9\xE9\xE9\xE9\xE9\xE9", 8),
        add_new_des_test_data("\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA",
                              "\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA",
                              "\x8F\xE5\x59\xC7\xCD\x6F\xA5\x6D",
                              "\xEA\xEA\xEA\xEA\xEA\xEA\xEA\xEA", 8),
        add_new_des_test_data("\xEB\xEB\xEB\xEB\xEB\xEB\xEB\xEB",
                              "\xEB\xEB\xEB\xEB\xEB\xEB\xEB\xEB",
                              "\xC8\x84\x80\x83\x5C\x1A\x44\x4C",
                              "\xEB\xEB\xEB\xEB\xEB\xEB\xEB\xEB", 8),
        add_new_des_test_data("\xEC\xEC\xEC\xEC\xEC\xEC\xEC\xEC",
                              "\xEC\xEC\xEC\xEC\xEC\xEC\xEC\xEC",
                              "\xD6\xEE\x30\xA1\x6B\x2C\xC0\x1E",
                              "\xEC\xEC\xEC\xEC\xEC\xEC\xEC\xEC", 8),
        add_new_des_test_data("\xED\xED\xED\xED\xED\xED\xED\xED",
                              "\xED\xED\xED\xED\xED\xED\xED\xED",
                              "\x69\x32\xD8\x87\xB2\xEA\x9C\x1A",
                              "\xED\xED\xED\xED\xED\xED\xED\xED", 8),
        add_new_des_test_data("\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE",
                              "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE",
                              "\x0B\xFC\x86\x54\x61\xF1\x3A\xCC",
                              "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE", 8),
        add_new_des_test_data("\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF",
                              "\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF",
                              "\x22\x8A\xEA\x0D\x40\x3E\x80\x7A",
                              "\xEF\xEF\xEF\xEF\xEF\xEF\xEF\xEF", 8),
        add_new_des_test_data("\xF0\xF0\xF0\xF0\xF0\xF0\xF0\xF0",
                              "\xF0\xF0\xF0\xF0\xF0\xF0\xF0\xF0",
                              "\x2A\x28\x91\xF6\x5B\xB8\x17\x3C",
                              "\xF0\xF0\xF0\xF0\xF0\xF0\xF0\xF0", 8),
        add_new_des_test_data("\xF1\xF1\xF1\xF1\xF1\xF1\xF1\xF1",
                              "\xF1\xF1\xF1\xF1\xF1\xF1\xF1\xF1",
                              "\x5D\x1B\x8F\xAF\x78\x39\x49\x4B",
                              "\xF1\xF1\xF1\xF1\xF1\xF1\xF1\xF1", 8),
        add_new_des_test_data("\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2",
                              "\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2",
                              "\x1C\x0A\x92\x80\xEE\xCF\x5D\x48",
                              "\xF2\xF2\xF2\xF2\xF2\xF2\xF2\xF2", 8),
        add_new_des_test_data("\xF3\xF3\xF3\xF3\xF3\xF3\xF3\xF3",
                              "\xF3\xF3\xF3\xF3\xF3\xF3\xF3\xF3",
                              "\x6C\xBC\xE9\x51\xBB\xC3\x0F\x74",
                              "\xF3\xF3\xF3\xF3\xF3\xF3\xF3\xF3", 8),
        add_new_des_test_data("\xF4\xF4\xF4\xF4\xF4\xF4\xF4\xF4",
                              "\xF4\xF4\xF4\xF4\xF4\xF4\xF4\xF4",
                              "\x9C\xA6\x6E\x96\xBD\x08\xBC\x70",
                              "\xF4\xF4\xF4\xF4\xF4\xF4\xF4\xF4", 8),
        add_new_des_test_data("\xF5\xF5\xF5\xF5\xF5\xF5\xF5\xF5",
                              "\xF5\xF5\xF5\xF5\xF5\xF5\xF5\xF5",
                              "\xF5\xD7\x79\xFC\xFB\xB2\x8B\xF3",
                              "\xF5\xF5\xF5\xF5\xF5\xF5\xF5\xF5", 8),
        add_new_des_test_data("\xF6\xF6\xF6\xF6\xF6\xF6\xF6\xF6",
                              "\xF6\xF6\xF6\xF6\xF6\xF6\xF6\xF6",
                              "\x0F\xEC\x6B\xBF\x9B\x85\x91\x84",
                              "\xF6\xF6\xF6\xF6\xF6\xF6\xF6\xF6", 8),
        add_new_des_test_data("\xF7\xF7\xF7\xF7\xF7\xF7\xF7\xF7",
                              "\xF7\xF7\xF7\xF7\xF7\xF7\xF7\xF7",
                              "\xEF\x88\xD2\xBF\x05\x2D\xBD\xA8",
                              "\xF7\xF7\xF7\xF7\xF7\xF7\xF7\xF7", 8),
        add_new_des_test_data("\xF8\xF8\xF8\xF8\xF8\xF8\xF8\xF8",
                              "\xF8\xF8\xF8\xF8\xF8\xF8\xF8\xF8",
                              "\x39\xAD\xBD\xDB\x73\x63\x09\x0D",
                              "\xF8\xF8\xF8\xF8\xF8\xF8\xF8\xF8", 8),
        add_new_des_test_data("\xF9\xF9\xF9\xF9\xF9\xF9\xF9\xF9",
                              "\xF9\xF9\xF9\xF9\xF9\xF9\xF9\xF9",
                              "\xC0\xAE\xAF\x44\x5F\x7E\x2A\x7A",
                              "\xF9\xF9\xF9\xF9\xF9\xF9\xF9\xF9", 8),
        add_new_des_test_data("\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA",
                              "\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA",
                              "\xC6\x6F\x54\x06\x72\x98\xD4\xE9",
                              "\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA", 8),
        add_new_des_test_data("\xFB\xFB\xFB\xFB\xFB\xFB\xFB\xFB",
                              "\xFB\xFB\xFB\xFB\xFB\xFB\xFB\xFB",
                              "\xE0\xBA\x8F\x44\x88\xAA\xF9\x7C",
                              "\xFB\xFB\xFB\xFB\xFB\xFB\xFB\xFB", 8),
        add_new_des_test_data("\xFC\xFC\xFC\xFC\xFC\xFC\xFC\xFC",
                              "\xFC\xFC\xFC\xFC\xFC\xFC\xFC\xFC",
                              "\x67\xB3\x6E\x28\x75\xD9\x63\x1C",
                              "\xFC\xFC\xFC\xFC\xFC\xFC\xFC\xFC", 8),
        add_new_des_test_data("\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD",
                              "\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD",
                              "\x1E\xD8\x3D\x49\xE2\x67\x19\x1D",
                              "\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD", 8),
        add_new_des_test_data("\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
                              "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
                              "\x66\xB2\xB2\x3E\xA8\x46\x93\xAD",
                              "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE", 8),
        add_new_des_test_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                              "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                              "\x73\x59\xB2\x16\x3E\x4E\xDC\x58",
                              "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8),
         // TODO(Rafael): Fill it up with the remaining test data from NESSIE.
/*        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),
        add_new_des_test_data("",
                              "",
                              "",
                              "", 8),*/
    };
#undef add_new_des_test_data
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), tv;

    // INFO(Rafael): ECB mode tests.

    kryptos_task_init_as_null(&t);

    for (tv = 0; tv < test_vector_nr; tv++) {

        kryptos_des_setup(&t, test_vector[tv].key, test_vector[tv].block_size, kKryptosECB);

        t.in = test_vector[tv].plain;
        t.in_size = 8;
        kryptos_task_set_encrypt_action(&t);

        kryptos_des_cipher(&ktask);

        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == (t.in_size << 1)); // INFO(Rafael): We always pad.
        //printf("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n", *(t.out), *(t.out+1), *(t.out+2), *(t.out+3), *(t.out+4), *(t.out+5), *(t.out+6), *(t.out+7));
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].cipher, test_vector[tv].block_size) == 0);

        t.in = t.out;
        t.in_size = t.out_size;
        kryptos_task_set_decrypt_action(&t);

        kryptos_des_cipher(&ktask);

        CUTE_ASSERT(t.out != NULL);
        CUTE_ASSERT(t.out_size == 8);
        CUTE_ASSERT(memcmp(t.out, test_vector[tv].decrypted, test_vector[tv].block_size) == 0);

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
    }

    // INFO(Rafael): CBC mode tests.
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_apply_iv_tests)
    kryptos_u8_t *iv = "rofginkoolerautahtsdiordeht";
    kryptos_u8_t *block = "thedroidsthatuarelookingfor";
    size_t s = 27;
    CUTE_ASSERT(kryptos_apply_iv(block, iv, s) == block);
    CUTE_ASSERT(kryptos_apply_iv(block, iv, s) == block);
    CUTE_ASSERT(memcmp(block, "thedroidsthatuarelookingfor", 27) == 0);
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

CUTE_TEST_CASE(kryptos_test_monkey)
    // CLUE(Rafael): Before adding a new test try to find out the best place for putting it here.
    //               At first glance you should consider the utility that it implements into the library.

    // INFO(Rafael): Generic/shared stuff.
    CUTE_RUN_TEST(kryptos_padding_tests);
    CUTE_RUN_TEST(kryptos_get_random_block_tests);
    CUTE_RUN_TEST(kryptos_block_parser_tests);
    CUTE_RUN_TEST(kryptos_endianess_utils_tests);
    CUTE_RUN_TEST(kryptos_apply_iv_tests);
    CUTE_RUN_TEST(kryptos_iv_data_flush_tests);
    CUTE_RUN_TEST(kryptos_task_check_tests);

    // INFO(Rafael): Cipher validation using official test vectors.
    CUTE_RUN_TEST(kryptos_arc4_tests);
    CUTE_RUN_TEST(kryptos_seal_tests);
    CUTE_RUN_TEST(kryptos_des_tests);

    //  -=-=-=-=- If you have just added a new cipher take a look in "kryptos_dsl_tests" case, there is some work to
    //                                               be done there too! -=-=-=-=-=-=-

    // INFO(Rafael): Internal DSL stuff.
    CUTE_RUN_TEST(kryptos_dsl_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(kryptos_test_monkey);
