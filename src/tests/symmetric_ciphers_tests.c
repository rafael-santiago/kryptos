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
