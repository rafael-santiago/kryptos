/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "symmetric_ciphers_tests.h"
#include "test_vectors.h"
#include <kryptos.h>
#include <string.h>

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
        kryptos_freeseg(t.in, t.in_size);
        kryptos_freeseg(t.out, t.out_size);
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

    kryptos_freeseg(t.out, t.out_size);
    kryptos_freeseg(t.in, t.in_size);

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

    kryptos_freeseg(t.out, t.out_size);
    kryptos_freeseg(t.in, t.in_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_des_tests)
    // INFO(Rafael): Running the ECB, CBC and OFB tests. Once defined the ECB test vector related with the cipher,
    //               the following incantation is all that you should implement inside a test case dedicated to block cipher.
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
                                                                        &feal_rounds[tv % feal_rounds_nr].rounds),
                                                     kryptos_feal_setup(&t,
                                                                        feal_test_vector[tv % feal_rounds_nr].key,
                                                                        feal_test_vector[tv % feal_rounds_nr].key_size,
                                                                        kKryptosCTR,
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
        {   63 }, {   64 }, {   64 }, {   64 }, {   64 }, {   64 }, {  128 }, {  129 },
        {  128 }, {  128 }, {  128 }, {  128 }, {  128 }, {  128 }, {  128 }, {  128 },
        {  128 }, {  128 }, {  128 }, {  128 }, {  128 }, {  128 }, {  128 }, {  128 },
        {  128 }, { 1024 }, { 1024 }, { 1024 }, { 1024 }
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
                                                                       &rc2_key_bits[tv % rc2_key_bits_nr].T1),
                                                     kryptos_rc2_setup(&t,
                                                                       rc2_test_vector[tv % rc2_key_bits_nr].key,
                                                                       rc2_test_vector[tv % rc2_key_bits_nr].key_size,
                                                                       kKryptosCTR,
                                                                       &rc2_key_bits[tv % rc2_key_bits_nr].T1));

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia128_tests)
    kryptos_run_block_cipher_tests(camellia128, KRYPTOS_CAMELLIA_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia192_tests)
    kryptos_run_block_cipher_tests(camellia192, KRYPTOS_CAMELLIA_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia256_tests)
    kryptos_run_block_cipher_tests(camellia256, KRYPTOS_CAMELLIA_BLOCKSIZE);
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
                                                                            &rounds[tv % rounds_nr].n),
                                                     kryptos_saferk64_setup(&t,
                                                                            saferk64_test_vector[tv % rounds_nr].key,
                                                                            saferk64_test_vector[tv % rounds_nr].key_size,
                                                                            kKryptosCTR,
                                                                            &rounds[tv % rounds_nr].n));

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes128_tests)
    kryptos_run_block_cipher_tests(aes128, KRYPTOS_AES_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes192_tests)
    kryptos_run_block_cipher_tests(aes192, KRYPTOS_AES_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes256_tests)
    kryptos_run_block_cipher_tests(aes256, KRYPTOS_AES_BLOCKSIZE);
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
                                                                              &addkeys[tv % addkeys_nr].key3_size),
                                                     kryptos_triple_des_setup(&t,
                                                                              triple_des_test_vector[tv % addkeys_nr].key,
                                                                              triple_des_test_vector[tv % addkeys_nr].key_size,
                                                                              kKryptosCTR,
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
                                                                          &addkeys[tv % addkeys_nr].key3_size),
                                                     kryptos_triple_des_ede_setup(&t,
                                                                          triple_des_ede_test_vector[tv % addkeys_nr].key,
                                                                          triple_des_ede_test_vector[tv % addkeys_nr].key_size,
                                                                          kKryptosCTR,
                                                                          addkeys[tv % addkeys_nr].key2,
                                                                          &addkeys[tv % addkeys_nr].key2_size,
                                                                          addkeys[tv % addkeys_nr].key3,
                                                                          &addkeys[tv % addkeys_nr].key3_size));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tea_tests)
    kryptos_run_block_cipher_tests(tea, KRYPTOS_TEA_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_xtea_tests)
    struct xtea_rounds_ctx {
        int rounds;
    };
    struct xtea_rounds_ctx xtea_rounds[] = {
        { 32 }, { 32 }, { 32 }, { 32 }, { 32 }, { 32 },
        { 32 }, { 32 }, { 32 }, { 32 }, { 32 }, { 32 },
        { 32 }, { 32 }, { 32 }, { 32 }, { 32 }, { 32 },
        { 32 }, { 32 }, { 32 }, { 32 }, { 32 }, { 32 },
        { 32 }, { 32 }, { 32 }, { 32 }, { 32 }, { 32 },
        { 32 }, { 32 }, { 32 }, { 32 }, { 32 }, { 32 },
        { 32 }, { 32 }
    };
    size_t xtea_rounds_nr = sizeof(xtea_rounds) / sizeof(xtea_rounds[0]);
    kryptos_task_ctx t;
    size_t tv;

    kryptos_run_block_cipher_tests_with_custom_setup(xtea,
                                                     KRYPTOS_XTEA_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     xtea_rounds, xtea_rounds_nr,
                                                     kryptos_xtea_setup(&t,
                                                                        xtea_test_vector[tv % xtea_rounds_nr].key,
                                                                        xtea_test_vector[tv % xtea_rounds_nr].key_size,
                                                                        kKryptosECB,
                                                                        &xtea_rounds[tv % xtea_rounds_nr].rounds),
                                                     kryptos_xtea_setup(&t,
                                                                        xtea_test_vector[tv % xtea_rounds_nr].key,
                                                                        xtea_test_vector[tv % xtea_rounds_nr].key_size,
                                                                        kKryptosCBC,
                                                                        &xtea_rounds[tv % xtea_rounds_nr].rounds),
                                                     kryptos_xtea_setup(&t,
                                                                        xtea_test_vector[tv % xtea_rounds_nr].key,
                                                                        xtea_test_vector[tv % xtea_rounds_nr].key_size,
                                                                        kKryptosOFB,
                                                                        &xtea_rounds[tv % xtea_rounds_nr].rounds),
                                                     kryptos_xtea_setup(&t,
                                                                        xtea_test_vector[tv % xtea_rounds_nr].key,
                                                                        xtea_test_vector[tv % xtea_rounds_nr].key_size,
                                                                        kKryptosCTR,
                                                                        &xtea_rounds[tv % xtea_rounds_nr].rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_misty1_tests)
    kryptos_run_block_cipher_tests(misty1, KRYPTOS_MISTY1_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc5_tests)
    struct rc5_rounds_ctx {
        int rounds;
    };
    struct rc5_rounds_ctx rc5_rounds[] = {
        { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 },
        { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 },
        { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 },
        { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 }, { 12 },
        { 12 }, { 12 }
    };
    size_t rc5_rounds_nr = sizeof(rc5_rounds) / sizeof(rc5_rounds[0]);
    kryptos_task_ctx t;
    size_t tv;

    kryptos_run_block_cipher_tests_with_custom_setup(rc5,
                                                     KRYPTOS_RC5_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     rc5_rounds, rc5_rounds_nr,
                                                     kryptos_rc5_setup(&t,
                                                                        rc5_test_vector[tv % rc5_rounds_nr].key,
                                                                        rc5_test_vector[tv % rc5_rounds_nr].key_size,
                                                                        kKryptosECB,
                                                                        &rc5_rounds[tv % rc5_rounds_nr].rounds),
                                                     kryptos_rc5_setup(&t,
                                                                        rc5_test_vector[tv % rc5_rounds_nr].key,
                                                                        rc5_test_vector[tv % rc5_rounds_nr].key_size,
                                                                        kKryptosCBC,
                                                                        &rc5_rounds[tv % rc5_rounds_nr].rounds),
                                                     kryptos_rc5_setup(&t,
                                                                        rc5_test_vector[tv % rc5_rounds_nr].key,
                                                                        rc5_test_vector[tv % rc5_rounds_nr].key_size,
                                                                        kKryptosOFB,
                                                                        &rc5_rounds[tv % rc5_rounds_nr].rounds),
                                                     kryptos_rc5_setup(&t,
                                                                        rc5_test_vector[tv % rc5_rounds_nr].key,
                                                                        rc5_test_vector[tv % rc5_rounds_nr].key_size,
                                                                        kKryptosCTR,
                                                                        &rc5_rounds[tv % rc5_rounds_nr].rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_128_tests)
    struct rc6_rounds_ctx {
        int rounds;
    };
    struct rc6_rounds_ctx rc6_rounds[] = {
        { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 }, { 20 }
    };
    size_t rc6_rounds_nr = sizeof(rc6_rounds) / sizeof(rc6_rounds[0]);
    kryptos_task_ctx t;
    size_t tv;

    kryptos_run_block_cipher_tests_with_custom_setup(rc6_128,
                                                     KRYPTOS_RC6_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     rc6_rounds, rc6_rounds_nr,
                                                     kryptos_rc6_128_setup(&t,
                                                                           rc6_128_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_128_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosECB,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_128_setup(&t,
                                                                           rc6_128_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_128_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosCBC,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_128_setup(&t,
                                                                           rc6_128_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_128_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosOFB,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_128_setup(&t,
                                                                           rc6_128_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_128_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosCTR,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_192_tests)
    struct rc6_rounds_ctx {
        int rounds;
    };
    struct rc6_rounds_ctx rc6_rounds[] = {
        { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 }
    };
    size_t rc6_rounds_nr = sizeof(rc6_rounds) / sizeof(rc6_rounds[0]);
    kryptos_task_ctx t;
    size_t tv;

    kryptos_run_block_cipher_tests_with_custom_setup(rc6_192,
                                                     KRYPTOS_RC6_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     rc6_rounds, rc6_rounds_nr,
                                                     kryptos_rc6_192_setup(&t,
                                                                           rc6_192_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_192_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosECB,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_192_setup(&t,
                                                                           rc6_192_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_192_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosCBC,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_192_setup(&t,
                                                                           rc6_192_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_192_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosOFB,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_192_setup(&t,
                                                                           rc6_192_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_192_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosCTR,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_256_tests)
    struct rc6_rounds_ctx {
        int rounds;
    };
    struct rc6_rounds_ctx rc6_rounds[] = {
        { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 },
        { 20 }, { 20 }, { 20 }, { 20 }
    };
    size_t rc6_rounds_nr = sizeof(rc6_rounds) / sizeof(rc6_rounds[0]);
    kryptos_task_ctx t;
    size_t tv;

    kryptos_run_block_cipher_tests_with_custom_setup(rc6_256,
                                                     KRYPTOS_RC6_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     rc6_rounds, rc6_rounds_nr,
                                                     kryptos_rc6_256_setup(&t,
                                                                           rc6_256_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_256_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosECB,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_256_setup(&t,
                                                                           rc6_256_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_256_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosCBC,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_256_setup(&t,
                                                                           rc6_256_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_256_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosOFB,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds),
                                                     kryptos_rc6_256_setup(&t,
                                                                           rc6_256_test_vector[tv % rc6_rounds_nr].key,
                                                                           rc6_256_test_vector[tv % rc6_rounds_nr].key_size,
                                                                           kKryptosCTR,
                                                                           &rc6_rounds[tv % rc6_rounds_nr].rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars128_tests)
    kryptos_run_block_cipher_tests(mars128, KRYPTOS_MARS_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars192_tests)
    kryptos_run_block_cipher_tests(mars192, KRYPTOS_MARS_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars256_tests)
    kryptos_run_block_cipher_tests(mars256, KRYPTOS_MARS_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present80_tests)
    kryptos_run_block_cipher_tests(present80, KRYPTOS_PRESENT_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present128_tests)
    kryptos_run_block_cipher_tests(present128, KRYPTOS_PRESENT_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rabbit_tests)
    size_t test_vector_nr = sizeof(kryptos_rabbit_test_vector) / sizeof(kryptos_rabbit_test_vector[0]), t;
    kryptos_task_ctx ktsk, *ktask = &ktsk;
    int s;
    for (t = 0; t < test_vector_nr; t++) {
        kryptos_rabbit_setup(ktask,
                             kryptos_rabbit_test_vector[t].key, kryptos_rabbit_test_vector[t].key_size,
                             kryptos_rabbit_test_vector[t].iv);
        ktask->in = kryptos_rabbit_test_vector[t].in;
        ktask->in_size = kryptos_rabbit_test_vector[t].in_size;
        kryptos_rabbit_cipher(&ktask);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out_size == kryptos_rabbit_test_vector[t].out_size);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(memcmp(ktask->out, kryptos_rabbit_test_vector[t].out, ktask->out_size) == 0);
        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size; // WARN(Rafael): It must be the same but let's do it for correctness issues.
        kryptos_rabbit_cipher(&ktask);
        CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == kryptos_rabbit_test_vector[t].exp_size);
        CUTE_ASSERT(memcmp(ktask->out, kryptos_rabbit_test_vector[t].exp, ktask->out_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ctr_mode_sequencing_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u32_t ctr = 10;
    kryptos_u8_t *data = "ISLEEPTHROUGHTHEWAR";
    size_t data_size = 19;

    kryptos_task_init_as_null(ktask);

    kryptos_task_set_in(ktask, data, data_size);

    kryptos_task_set_encrypt_action(ktask);

    kryptos_task_set_ctr_mode(ktask, &ctr);
    kryptos_misty1_setup(ktask, "bulls", 5, kKryptosCTR);
    kryptos_misty1_cipher(&ktask);

    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    CUTE_ASSERT(ktask->out != NULL);

    CUTE_ASSERT(ctr == 13);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);

    kryptos_task_set_decrypt_action(ktask);

    kryptos_misty1_setup(ktask, "bulls", 5, kKryptosCTR);
    kryptos_misty1_cipher(&ktask);

    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(ktask->out_size == data_size);

    CUTE_ASSERT(memcmp(ktask->out, data, data_size) == 0);

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal1_tests)
    kryptos_run_block_cipher_tests(shacal1, KRYPTOS_SHACAL1_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal2_tests)
    kryptos_run_block_cipher_tests(shacal2, KRYPTOS_SHACAL2_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_tests)
    kryptos_run_block_cipher_tests(noekeon, KRYPTOS_NOEKEON_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_d_tests)
    kryptos_run_block_cipher_tests(noekeon_d, KRYPTOS_NOEKEON_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_ds_tests)
    kryptos_run_block_cipher_tests(gost_ds, KRYPTOS_GOST_BLOCKSIZE);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_tests)
    struct gost_sboxes_ctx {
        kryptos_u8_t *s1, *s2, *s3, *s4, *s5, *s6, *s7, *s8;
    };
    kryptos_u8_t s1[16] = {
         4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3
    };
    kryptos_u8_t s2[16] = {
        14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9
    };
    kryptos_u8_t s3[16] = {
        5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11
    };
    kryptos_u8_t s4[16] = {
        7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3
    };
    kryptos_u8_t s5[16] = {
        6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2
    };
    kryptos_u8_t s6[16] = {
        4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14
    };
    kryptos_u8_t s7[16] = {
        13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12
    };
    kryptos_u8_t s8[16] = {
         1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12
    };
    struct gost_sboxes_ctx gost_sboxes[] = {
        { s1, s2, s3, s4, s5, s6, s7, s8 },
        { s1, s2, s3, s4, s5, s6, s7, s8 }
    };
    size_t gost_sboxes_nr = sizeof(gost_sboxes) / sizeof(gost_sboxes[0]);
    kryptos_task_ctx t;
    size_t tv;

    kryptos_run_block_cipher_tests_with_custom_setup(gost,
                                                     KRYPTOS_GOST_BLOCKSIZE,
                                                     t,
                                                     tv,
                                                     gost_sboxes, gost_sboxes_nr,
                                                     kryptos_gost_setup(&t,
                                                                        gost_test_vector[tv % gost_sboxes_nr].key,
                                                                        gost_test_vector[tv % gost_sboxes_nr].key_size,
                                                                        kKryptosECB,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s1,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s2,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s3,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s4,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s5,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s6,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s7,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s8),
                                                    kryptos_gost_setup(&t,
                                                                        gost_test_vector[tv % gost_sboxes_nr].key,
                                                                        gost_test_vector[tv % gost_sboxes_nr].key_size,
                                                                        kKryptosCBC,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s1,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s2,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s3,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s4,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s5,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s6,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s7,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s8),
                                                    kryptos_gost_setup(&t,
                                                                        gost_test_vector[tv % gost_sboxes_nr].key,
                                                                        gost_test_vector[tv % gost_sboxes_nr].key_size,
                                                                        kKryptosOFB,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s1,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s2,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s3,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s4,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s5,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s6,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s7,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s8),
                                                    kryptos_gost_setup(&t,
                                                                        gost_test_vector[tv % gost_sboxes_nr].key,
                                                                        gost_test_vector[tv % gost_sboxes_nr].key_size,
                                                                        kKryptosCTR,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s1,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s2,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s3,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s4,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s5,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s6,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s7,
                                                                        gost_sboxes[tv % gost_sboxes_nr].s8));
CUTE_TEST_CASE_END


CUTE_TEST_CASE(kryptos_des_weak_keys_detection_tests)
#define REGISTER_DES_WEAK_KEY(k) (k)
    static kryptos_u8_t *wkey[] = {
        // WARN(Rafael): DES' weak keys.
        REGISTER_DES_WEAK_KEY("\x01\x01\x01\x01\x01\x01\x01\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1"), REGISTER_DES_WEAK_KEY("\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE"),
        // WARN(Rafael): DES' semiweak keys.
        REGISTER_DES_WEAK_KEY("\x01\xFE\x01\xFE\x01\xFE\x01\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x01\xFE\x01\xFE\x01\xFE\x01"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1"), REGISTER_DES_WEAK_KEY("\xE0\xF1\xE0\xF1\xF1\x0E\xF1\x0E"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\x01\xE0\x01\xF1\x01\xF1"), REGISTER_DES_WEAK_KEY("\xE0\x01\xE0\x01\xF1\x01\xF1\x01"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E"),
        REGISTER_DES_WEAK_KEY("\x01\xF1\x01\xF1\x01\x0E\x01\x0E"), REGISTER_DES_WEAK_KEY("\x1F\x01\x1F\x01\x0E\x01\x0E\x01"),
        REGISTER_DES_WEAK_KEY("\x0E\xFE\x0E\xFE\xF1\xFE\xF1\xFE"), REGISTER_DES_WEAK_KEY("\xFE\x0E\xFE\x0E\xFE\xF1\xFE\xF1"),
        // WARN(Rafael): DES' possibly weak keys.
        REGISTER_DES_WEAK_KEY("\x1F\x1F\x01\x01\x0E\x0E\x01\x01"), REGISTER_DES_WEAK_KEY("\x0E\x01\x0E\xF1\xF1\x01\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\x1F\x1F\x01\x01\x0E\x0E\x01"), REGISTER_DES_WEAK_KEY("\xFE\xF1\x01\xE0\xFE\x0E\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\x1F\x01\x01\x1F\x0E\x01\x01\x0E"), REGISTER_DES_WEAK_KEY("\xFE\x01\x1F\xE0\xFE\x01\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\x01\x1F\x1F\x01\x01\x0E\x0E"), REGISTER_DES_WEAK_KEY("\xE0\x1F\x1F\xE0\xF1\x0E\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\x01\x01\xF1\xF1\x01\x01"), REGISTER_DES_WEAK_KEY("\xFE\x01\x01\xFE\xFE\x01\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xFE\x01\x01\xFE\xFE\x01\x01"), REGISTER_DES_WEAK_KEY("\xE0\x1F\x01\xFE\xF1\x0E\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xE0\x1F\x01\xFE\xF1\x0E\x01"), REGISTER_DES_WEAK_KEY("\xE0\x01\x1F\xFE\xF1\x01\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xE0\xFE\x1F\x01\xF1\xFE\x0E\x01"), REGISTER_DES_WEAK_KEY("\xFE\x1F\x1F\xFE\xFE\x0E\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xE0\x01\x1F\xFE\xF1\x01\x0E"), REGISTER_DES_WEAK_KEY("\x1F\xFE\x01\xE0\x0E\xFE\x01\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xFE\x01\x1F\xF1\xFE\x01\x0E"), REGISTER_DES_WEAK_KEY("\x01\xFE\x1F\xE0\x01\xFE\x0E\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\xE0\x1F\x1F\xF1\xF1\x0E\x0E"), REGISTER_DES_WEAK_KEY("\x1F\xE0\x01\xFE\x0E\xF1\x01\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\xFE\x1F\x1F\xFE\xFE\x0E\x0E"), REGISTER_DES_WEAK_KEY("\x01\xE0\x1F\xFE\x01\xF1\x0E\xFE"),
        REGISTER_DES_WEAK_KEY("\xFE\x1F\xE0\x01\xFE\x0E\xF1\x01"), REGISTER_DES_WEAK_KEY("\x01\x01\xE0\xE0\x01\x01\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\x1F\xFE\x01\xF1\x0E\xFE\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\xE0\xE0\x0E\x0E\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\xFE\x01\xE0\x1F\xFE\x01\xF1\x0E"), REGISTER_DES_WEAK_KEY("\x1F\x01\xFE\xE0\x0E\x01\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\xE0\x01\xFE\x1F\xF1\x01\xFE\x0E"), REGISTER_DES_WEAK_KEY("\x01\x1F\xFE\xE0\x01\x0E\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\xE0\x01\x01\xF1\xF1\x01"), REGISTER_DES_WEAK_KEY("\x1F\x01\xE0\xFE\x0E\x01\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\xE0\x01\x0E\xFE\xF0\x01"), REGISTER_DES_WEAK_KEY("\x01\x1F\xE0\xFE\x01\x0E\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\xFE\x01\x0E\xF1\xFE\x01"), REGISTER_DES_WEAK_KEY("\x01\x01\xFE\xFE\x01\x01\xFE\xFE"),
        REGISTER_DES_WEAK_KEY("\x01\xFE\xFE\x01\x01\xFE\xFE\x01"), REGISTER_DES_WEAK_KEY("\x1F\x1F\xFE\xFE\x0E\x0E\xFE\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xE0\xE0\x1F\x0E\xF1\xF1\x0E"), REGISTER_DES_WEAK_KEY("\xFE\xFE\xE0\xE0\xFE\xFE\xF1\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xFE\xE0\x1F\x01\xFE\xF1\x0E"), REGISTER_DES_WEAK_KEY("\xE0\xFE\xFE\xE0\xF1\xFE\xFE\xF1"),
        REGISTER_DES_WEAK_KEY("\x01\xE0\xFE\x1F\x01\xF1\xFE\x0E"), REGISTER_DES_WEAK_KEY("\xFE\xE0\xE0\xFE\xFE\xF1\xF1\xFE"),
        REGISTER_DES_WEAK_KEY("\x1F\xFE\xFE\x1F\x0E\xFE\xFE\x0E"), REGISTER_DES_WEAK_KEY("\xE0\xE0\xFE\xFE\xF1\xF1\xFE\xFE")
    };
#undef REGISTER_DES_WEAK_KEY
    size_t wkey_nr = sizeof(wkey) / sizeof(wkey[0]), w, wkeys_size = 8;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *k1 = "101", *k2 = "255";
    size_t k1_size = 3, k2_size = 3;

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_des_setup(ktask, wkey[w], wkeys_size, kKryptosECB);
        kryptos_des_cipher(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);
    }

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_triple_des_setup(ktask, wkey[w], wkeys_size, kKryptosECB, k1, &k1_size, k2, &k2_size);
        kryptos_triple_des_cipher(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_setup(ktask, k1, k1_size, kKryptosECB, wkey[w], &wkeys_size, k2, &k2_size);
        kryptos_triple_des_cipher(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_setup(ktask, k1, k1_size, kKryptosECB, k2, &k2_size, wkey[w], &wkeys_size);
        kryptos_triple_des_cipher(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);
    }

    for (w = 0; w < wkey_nr; w++) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_in(ktask, "Skeletons", 9);
        kryptos_task_set_encrypt_action(ktask);
        kryptos_triple_des_ede_setup(ktask, wkey[w], wkeys_size, kKryptosECB, k1, &k1_size, k2, &k2_size);
        kryptos_triple_des_ede_cipher(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_ede_setup(ktask, k1, k1_size, kKryptosECB, wkey[w], &wkeys_size, k2, &k2_size);
        kryptos_triple_des_ede_cipher(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);
        kryptos_triple_des_ede_setup(ktask, k1, k1_size, kKryptosECB, k2, &k2_size, wkey[w], &wkeys_size);
        kryptos_triple_des_ede_cipher(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosKeyError);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_bcrypt_tests)
    struct bcrypt_test {
        const kryptos_u8_t *password;
        const size_t password_size;
        const int cost;
        const kryptos_u8_t *salt;
        const size_t salt_size;
        const kryptos_u8_t *hash;
        const size_t hash_size;
    };
#define add_test_step(p, p_sz, c, s, s_sz, h, h_sz) { p, p_sz, c, s, s_sz, h, h_sz }
    struct bcrypt_test test_vector[] = {
        add_test_step("", 0,
                       4, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$04$zVHmKQtGGQob.b/Nc7l9NO8UlrYcW05FiuCj/SxsFO/ZtiN9.mNzy", 60),
        add_test_step("", 0,
                       5, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$05$zVHmKQtGGQob.b/Nc7l9NOWES.1hkVBgy5IWImh9DOjKNU8atY4Iy", 60),
        add_test_step("", 0,
                       6, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$06$zVHmKQtGGQob.b/Nc7l9NOjOl7l4oz3WSh5fJ6414Uw8IXRAUoiaO", 60),
        add_test_step("", 0,
                       7, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$07$zVHmKQtGGQob.b/Nc7l9NOBsj1dQpBA1HYNGpIETIByoNX9jc.hOi", 60),
        add_test_step("", 0,
                       8, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$08$zVHmKQtGGQob.b/Nc7l9NOiLTUh/9MDpX86/DLyEzyiFjqjBFePgO", 60),
        add_test_step("messycrypt", 10,
                       4, "\xD5\x72\x68\x31\x2B\xC8\x21\x2A\x9D\x01\xD0\x4F\x7B\xD9\xFF\x3D", 16,
                      "$2a$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC", 60)
    };
#undef add_test_step
    size_t t, test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t *hash;
    size_t hash_size;

    for (t = 0; t < test_vector_nr; t++) {
        hash = kryptos_bcrypt(test_vector[t].cost,
                              test_vector[t].salt, test_vector[t].salt_size,
                              test_vector[t].password, test_vector[t].password_size, &hash_size);
        CUTE_ASSERT(hash != NULL);
        CUTE_ASSERT(hash_size == test_vector[t].hash_size);
        CUTE_ASSERT(memcmp(hash, test_vector[t].hash, hash_size) == 0);
        kryptos_freeseg(hash, hash_size);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_bcrypt_verify_tests)
    kryptos_u8_t *password[] = {
        "messycrypt", "No Good, Mr. Holden", "Bad idea.", "Nothing Ventured"
    };
    size_t password_nr = sizeof(password) / sizeof(password[0]), p;
    kryptos_u8_t *hash;
    size_t hash_size;
    kryptos_u8_t *salt;

    // INFO(Rafael): Malformed or unsupported hashes.

    hash = "$3a$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "2x$04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2a04$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$0a$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$a4$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$32$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$00$zVHmKQtGGQob.b/Nc7l9NOW2pAwmViS9PCMB6D5D0ehLM6L7H3OGC";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    hash = "$2x$04$zVHmKQtGGQo";
    CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, strlen(hash)) == 0);

    for (p = 0; p < password_nr; p++) {
        salt = kryptos_get_random_block(16);
        CUTE_ASSERT(salt != NULL);
        hash = kryptos_bcrypt(4 + p, salt, 16, password[p], strlen(password[p]), &hash_size);
        CUTE_ASSERT(hash != NULL);
        CUTE_ASSERT(kryptos_bcrypt_verify("Wrong", 5, hash, hash_size) == 0);
        CUTE_ASSERT(kryptos_bcrypt_verify(password[p], strlen(password[p]), hash, hash_size) == 1);
        kryptos_freeseg(hash, hash_size);
        kryptos_freeseg(salt, 16);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_des_gcm_tests)
    kryptos_run_gcm_tests_no_support(des);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_idea_gcm_tests)
    kryptos_run_gcm_tests_no_support(idea);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blowfish_gcm_tests)
    kryptos_run_gcm_tests_no_support(blowfish);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_feal_gcm_tests)
    int rounds = 1;
    kryptos_run_gcm_tests_no_support_with_custom_setup(feal, ktask, kryptos_feal_setup(ktask, "feal", 4,
                                                                                       kKryptosGCM, &rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc2_gcm_tests)
    int T1 = 32;
    kryptos_run_gcm_tests_no_support_with_custom_setup(rc2, ktask, kryptos_rc2_setup(ktask, "rc2", 3, kKryptosGCM,
                                                                                     &T1));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia128_gcm_tests)
    kryptos_run_gcm_tests(camellia128);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia192_gcm_tests)
    kryptos_run_gcm_tests(camellia192);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia256_gcm_tests)
    kryptos_run_gcm_tests(camellia256);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_cast5_gcm_tests)
    kryptos_run_gcm_tests_no_support(cast5);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_saferk64_gcm_tests)
    int rounds = 67;
    kryptos_run_gcm_tests_no_support_with_custom_setup(saferk64, ktask, kryptos_saferk64_setup(ktask, "saferk64", 8,
                                                                                               kKryptosGCM, &rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes128_gcm_tests)
    kryptos_run_gcm_tests(aes128);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes192_gcm_tests)
    kryptos_run_gcm_tests(aes192);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes256_gcm_tests)
    kryptos_run_gcm_tests(aes256);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_serpent_gcm_tests)
    kryptos_run_gcm_tests(serpent);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_gcm_tests)
    kryptos_u8_t *k2 = "3des'", *k3 = "3des''";
    size_t k2_size = 5, k3_size = 6;
    kryptos_run_gcm_tests_no_support_with_custom_setup(triple_des, ktask, kryptos_triple_des_setup(ktask, "3des", 4,
                                                                                                   kKryptosGCM,
                                                                                                   k2, &k2_size,
                                                                                                   k3, &k3_size));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_ede_gcm_tests)
    kryptos_u8_t *k2 = "3des'", *k3 = "3des''";
    size_t k2_size = 5, k3_size = 6;
    kryptos_run_gcm_tests_no_support_with_custom_setup(triple_des_ede, ktask, kryptos_triple_des_ede_setup(ktask, "3des", 4,
                                                                                                           kKryptosGCM,
                                                                                                           k2, &k2_size,
                                                                                                           k3, &k3_size));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tea_gcm_tests)
    kryptos_run_gcm_tests_no_support_with_custom_setup(tea, ktask, kryptos_tea_setup(ktask,
                                                                                     "teateateateateat", 16, kKryptosGCM));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_xtea_gcm_tests)
    int rounds = 17;
    kryptos_run_gcm_tests_no_support_with_custom_setup(xtea, ktask, kryptos_xtea_setup(ktask, "teateateateateat", 16,
                                                                                       kKryptosGCM, &rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_misty1_gcm_tests)
    kryptos_run_gcm_tests_no_support(misty1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc5_gcm_tests)
    int rounds = 60;
    kryptos_run_gcm_tests_no_support_with_custom_setup(rc5, ktask, kryptos_rc5_setup(ktask, "rc5", 3, kKryptosGCM, &rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_128_gcm_tests)
    int rounds = 48;
    kryptos_run_gcm_tests_with_custom_setup(rc6_128, ktask, kryptos_rc6_128_setup(ktask, "rc6", 3, kKryptosGCM, &rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_192_gcm_tests)
    int rounds = 48;
    kryptos_run_gcm_tests_with_custom_setup(rc6_192, ktask, kryptos_rc6_192_setup(ktask, "rc6", 3, kKryptosGCM, &rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_256_gcm_tests)
    int rounds = 48;
    kryptos_run_gcm_tests_with_custom_setup(rc6_256, ktask, kryptos_rc6_256_setup(ktask, "rc6", 3, kKryptosGCM, &rounds));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars128_gcm_tests)
    kryptos_run_gcm_tests(mars128);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars192_gcm_tests)
    kryptos_run_gcm_tests(mars192);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars256_gcm_tests)
    kryptos_run_gcm_tests(mars256);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present80_gcm_tests)
    kryptos_run_gcm_tests_no_support(present80);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present128_gcm_tests)
    kryptos_run_gcm_tests_no_support(present128);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal1_gcm_tests)
    kryptos_run_gcm_tests_no_support(shacal1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal2_gcm_tests)
    kryptos_run_gcm_tests_no_support(shacal2);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_gcm_tests)
    kryptos_run_gcm_tests(noekeon);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_d_gcm_tests)
    kryptos_run_gcm_tests(noekeon_d);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_ds_gcm_tests)
    kryptos_run_gcm_tests_no_support(gost_ds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_gcm_tests)
    struct gost_sboxes_ctx {
        kryptos_u8_t *s1, *s2, *s3, *s4, *s5, *s6, *s7, *s8;
    };
    kryptos_u8_t s1[16] = {
         4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3
    };
    kryptos_u8_t s2[16] = {
        14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9
    };
    kryptos_u8_t s3[16] = {
        5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11
    };
    kryptos_u8_t s4[16] = {
        7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3
    };
    kryptos_u8_t s5[16] = {
        6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2
    };
    kryptos_u8_t s6[16] = {
        4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14
    };
    kryptos_u8_t s7[16] = {
        13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12
    };
    kryptos_u8_t s8[16] = {
         1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12
    };
    kryptos_run_gcm_tests_no_support_with_custom_setup(gost, ktask, kryptos_gost_setup(ktask, "gost", 4, kKryptosGCM,
                                                       s1, s2, s3, s4, s5, s6, s7, s8));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_salsa20_tests)
    struct test_vector_ctx {
        kryptos_u8_t *key;
        size_t key_size;
        size_t input_size;
        kryptos_u8_t *iv;
        kryptos_u8_t *expected_chunk0;
        size_t expected_chunk0_start;
        kryptos_u8_t *expected_chunk1;
        size_t expected_chunk1_start;
        kryptos_u8_t *expected_chunk2;
        size_t expected_chunk2_start;
        kryptos_u8_t *expected_chunk3;
        size_t expected_chunk3_start;
    } test_vector[] = {
        {
            "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            32,
            512,
            "\x00\x00\x00\x00\x00\x00\x00\x00",
            "\xE3\xBE\x8F\xDD\x8B\xEC\xA2\xE3\xEA\x8E\xF9\x47\x5B\x29\xA6\xE7"
            "\x00\x39\x51\xE1\x09\x7A\x5C\x38\xD2\x3B\x7A\x5F\xAD\x9F\x68\x44"
            "\xB2\x2C\x97\x55\x9E\x27\x23\xC7\xCB\xBD\x3F\xE4\xFC\x8D\x9A\x07"
            "\x44\x65\x2A\x83\xE7\x2A\x9C\x46\x18\x76\xAF\x4D\x7E\xF1\xA1\x17",
            0,
            "\x57\xBE\x81\xF4\x7B\x17\xD9\xAE\x7C\x4F\xF1\x54\x29\xA7\x3E\x10"
            "\xAC\xF2\x50\xED\x3A\x90\xA9\x3C\x71\x13\x08\xA7\x4C\x62\x16\xA9"
            "\xED\x84\xCD\x12\x6D\xA7\xF2\x8E\x8A\xBF\x8B\xB6\x35\x17\xE1\xCA"
            "\x98\xE7\x12\xF4\xFB\x2E\x1A\x6A\xED\x9F\xDC\x73\x29\x1F\xAA\x17",
            192,
            "\x95\x82\x11\xC4\xBA\x2E\xBD\x58\x38\xC6\x35\xED\xB8\x1F\x51\x3A"
            "\x91\xA2\x94\xE1\x94\xF1\xC0\x39\xAE\xEC\x65\x7D\xCE\x40\xAA\x7E"
            "\x7C\x0A\xF5\x7C\xAC\xEF\xA4\x0C\x9F\x14\xB7\x1A\x4B\x34\x56\xA6"
            "\x3E\x16\x2E\xC7\xD8\xD1\x0B\x8F\xFB\x18\x10\xD7\x10\x01\xB6\x18",
            256,
            "\x69\x6A\xFC\xFD\x0C\xDD\xCC\x83\xC7\xE7\x7F\x11\xA6\x49\xD7\x9A"
            "\xCD\xC3\x35\x4E\x96\x35\xFF\x13\x7E\x92\x99\x33\xA0\xBD\x6F\x53"
            "\x77\xEF\xA1\x05\xA3\xA4\x26\x6B\x7C\x0D\x08\x9D\x08\xF1\xE8\x55"
            "\xCC\x32\xB1\x5B\x93\x78\x4A\x36\xE5\x6A\x76\xCC\x64\xBC\x84\x77",
            448
        },
        {
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            32,
            512,
            "\x00\x00\x00\x00\x00\x00\x00\x01",
            "\xB4\x7F\x96\xAA\x96\x78\x61\x35\x29\x7A\x3C\x4E\xC5\x6A\x61\x3D"
            "\x0B\x80\x09\x53\x24\xFF\x43\x23\x9D\x68\x4C\x57\xFF\xE4\x2E\x1C"
            "\x44\xF3\xCC\x01\x16\x13\xDB\x6C\xDC\x88\x09\x99\xA1\xE6\x5A\xED"
            "\x12\x87\xFC\xB1\x1C\x83\x9C\x37\x12\x07\x65\xAF\xA7\x3E\x50\x75",
            0,
            "\x97\x12\x8B\xD6\x99\xDD\xC1\xB4\xB1\x35\xD9\x48\x11\xB5\xD2\xD6"
            "\xB2\xAD\xCB\xDC\x1E\xD8\xD3\xCF\x86\xEC\xF6\x5A\x17\x50\xDE\x66"
            "\xCA\x5F\x1C\x2E\xD3\x50\xDC\x2F\x49\x73\x96\xE0\x29\xDB\xD4\xA0"
            "\x6F\xDD\xA6\x23\x8B\xE7\xD1\x20\xDD\x41\xE9\xF1\x9E\x6D\xEE\xA2",
            192,
            "\xFF\x80\x65\xAD\x90\x1A\x2D\xFC\x5C\x01\x64\x2A\x84\x0F\x75\x93"
            "\xAE\x03\x29\x46\x05\x8E\x54\xEA\x67\x30\x0F\xBF\x7B\x92\x8C\x20"
            "\x32\x44\xEF\x54\x67\x62\xBA\x64\x00\x32\xB6\xA2\x51\x41\x22\xDE"
            "\x0C\xA9\x69\x28\x3F\x70\xCE\x21\xF9\x81\xA5\xD6\x68\x27\x4F\x0D",
            256,
            "\x13\x09\x26\x8B\xE5\x48\xEF\xEC\x38\xD7\x9D\xF4\x33\x4C\xA9\x49"
            "\xAB\x15\xA2\xA1\x00\x3E\x2B\x97\x96\x9F\xE0\xCD\x74\xA1\x6A\x06"
            "\x5F\xE8\x69\x1F\x03\xCB\xD0\xEC\xFC\xF6\x31\x2F\x2E\xE0\x69\x7F"
            "\x44\xBD\x3B\xF3\xE6\x03\x20\xB2\x89\xCB\xF2\x1B\x42\x8C\x89\x22",
            448
        },
        {
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            32,
            512,
            "\x00\x00\x00\x00\x00\x00\x02\x00",
            "\x98\x95\x19\x56\xF4\xBD\x5E\x2E\x9D\xC6\x24\xCC\xD2\xD7\x9E\x60"
            "\x6D\x24\xA4\xDB\x51\xD4\x13\xFD\xAF\x9A\x97\x41\xA6\xF0\x79\xB4"
            "\x21\x40\x0F\xDA\x0B\x4D\x87\x85\x57\x8B\xB3\x18\xBD\xAD\x4A\xBC"
            "\xA8\xC2\xD1\xBA\x3B\xA4\xE1\x8C\x2F\x55\x72\x49\x9F\x34\x5B\xC1",
            0,
            "\xC3\xA2\x67\xF0\xEB\x87\xED\x71\x4E\x09\xCA\xBC\x27\x80\xFE\xF6"
            "\xE5\xF6\x65\xBB\xBB\xB4\x4C\x84\x48\xD8\xEB\x42\xD8\x82\x75\xCD"
            "\x62\xAD\x75\x9A\xAC\x9F\x40\x80\xF7\x39\x93\xDE\x50\xFF\x94\xE8"
            "\x34\xE2\xCF\x7B\x74\xA9\x1E\x68\xB3\x8E\xAC\xE9\xC1\x29\x22\xC2",
            192,
            "\x78\xBD\x0B\xB3\x2A\x69\xE6\x23\x62\xEE\x7E\x31\xF1\xDD\x9E\x96"
            "\xCA\x6E\x19\x68\x44\xEF\xD9\x45\x9F\x27\x0D\x61\x21\x19\xDF\xA4"
            "\x5D\xD1\x52\x29\x67\x62\x91\x43\xCE\xCD\x58\x5C\xFE\x62\xB7\xFD"
            "\x9D\x15\x03\xA6\x2A\x23\x8C\x35\xA6\x65\x95\xC4\x9D\xD7\x15\x75",
            256,
            "\xC1\x7F\x94\x6C\x14\xA4\x92\x39\x2A\x1C\x55\x49\x93\xF4\x06\xB2"
            "\xEA\x80\x6E\x41\x86\xD9\x7F\xCB\x42\x0C\x21\xFB\x42\x45\xA3\xDB"
            "\x4E\xBA\x2B\xCB\x59\xD2\xC3\x3C\xE2\xCD\x50\x44\xA7\x9A\x96\xF9"
            "\x51\x82\x11\x2D\x97\x24\xE1\x6A\xD9\xE9\x65\x04\x7D\xA7\x1F\x05",
            448
        },

        {
            "\x00\x53\xA6\xF9\x4C\x9F\xF2\x45\x98\xEB\x3E\x91\xE4\x37\x8A\xDD"
            "\x30\x83\xD6\x29\x7C\xCF\x22\x75\xC8\x1B\x6E\xC1\x14\x67\xBA\x0D",
            32,
            131072,
            "\x0D\x74\xDB\x42\xA9\x10\x77\xDE",
            "\xF5\xFA\xD5\x3F\x79\xF9\xDF\x58\xC4\xAE\xA0\xD0\xED\x9A\x96\x01"
            "\xF2\x78\x11\x2C\xA7\x18\x0D\x56\x5B\x42\x0A\x48\x01\x96\x70\xEA"
            "\xF2\x4C\xE4\x93\xA8\x62\x63\xF6\x77\xB4\x6A\xCE\x19\x24\x77\x3D"
            "\x2B\xB2\x55\x71\xE1\xAA\x85\x93\x75\x8F\xC3\x82\xB1\x28\x0B\x71",
            0,
            "\xB7\x0C\x50\x13\x9C\x63\x33\x2E\xF6\xE7\x7A\xC5\x43\x38\xA4\x07"
            "\x9B\x82\xBE\xC9\xF9\xA4\x03\xDF\xEA\x82\x1B\x83\xF7\x86\x07\x91"
            "\x65\x0E\xF1\xB2\x48\x9D\x05\x90\xB1\xDE\x77\x2E\xED\xA4\xE3\xBC"
            "\xD6\x0F\xA7\xCE\x9C\xD6\x23\xD9\xD2\xFD\x57\x58\xB8\x65\x3E\x70",
            65472,
            "\x81\x58\x2C\x65\xD7\x56\x2B\x80\xAE\xC2\xF1\xA6\x73\xA9\xD0\x1C"
            "\x9F\x89\x2A\x23\xD4\x91\x9F\x6A\xB4\x7B\x91\x54\xE0\x8E\x69\x9B"
            "\x41\x17\xD7\xC6\x66\x47\x7B\x60\xF8\x39\x14\x81\x68\x2F\x5D\x95"
            "\xD9\x66\x23\xDB\xC4\x89\xD8\x8D\xAA\x69\x56\xB9\xF0\x64\x6B\x6E",
            65536,
            "\xA1\x3F\xFA\x12\x08\xF8\xBF\x50\x90\x08\x86\xFA\xAB\x40\xFD\x10"
            "\xE8\xCA\xA3\x06\xE6\x3D\xF3\x95\x36\xA1\x56\x4F\xB7\x60\xB2\x42"
            "\xA9\xD6\xA4\x62\x8C\xDC\x87\x87\x62\x83\x4E\x27\xA5\x41\xDA\x2A"
            "\x5E\x3B\x34\x45\x98\x9C\x76\xF6\x11\xE0\xFE\xC6\xD9\x1A\xCA\xCC",
            131008
        },
        // TODO(Rafael): Add more NESSIE test vectors.
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_task_ctx t, *ktask = &t;

    memset(&t, 0, sizeof(t));

    t.cipher = kKryptosCipherSALSA20;

    while (test != test_end) {
        t.in_size = test->input_size;
        t.in = (kryptos_u8_t *) kryptos_newseg(t.in_size);
        CUTE_ASSERT(t.in != NULL);
        memset(t.in, 0, t.in_size);
        kryptos_salsa20_setup(ktask, test->key, test->key_size, test->iv);
        kryptos_salsa20_cipher(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosSuccess);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(ktask->out_size == test->input_size);
        CUTE_ASSERT(memcmp(&ktask->out[test->expected_chunk0_start], test->expected_chunk0, 64) == 0);
        CUTE_ASSERT(memcmp(&ktask->out[test->expected_chunk1_start], test->expected_chunk1, 64) == 0);
        CUTE_ASSERT(memcmp(&ktask->out[test->expected_chunk2_start], test->expected_chunk2, 64) == 0);
        CUTE_ASSERT(memcmp(&ktask->out[test->expected_chunk3_start], test->expected_chunk3, 64) == 0);

        kryptos_freeseg(ktask->out, ktask->out_size);
        kryptos_freeseg(ktask->in, ktask->in_size);
        test++;
    }
CUTE_TEST_CASE_END

