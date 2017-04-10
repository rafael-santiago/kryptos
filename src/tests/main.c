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
         // TODO(Rafael): Fill it up with the remaining test data from NESSIE.
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
        /*add_new_des_test_data("",
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
