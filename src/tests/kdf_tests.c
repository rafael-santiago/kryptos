/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "kdf_tests.h"
#include <kryptos.h>

CUTE_TEST_CASE(kryptos_do_hkdf_tests)
    struct test_step {
        kryptos_hash_func h;
        kryptos_hash_size_func h_input_size;
        kryptos_hash_size_func h_size;
        kryptos_u8_t *ikm;
        size_t ikm_size;
        kryptos_u8_t *salt;
        size_t salt_size;
        kryptos_u8_t *info;
        size_t info_size;
        size_t L;
        kryptos_u8_t *okm;
    };
#define add_hkdf_test_case(h, ikm, ikm_size, salt, salt_size, info, info_size, L, okm)\
    { kryptos_ ## h ## _hash, kryptos_ ## h ## _hash_input_size, kryptos_ ## h ## _hash_size,\
      ikm, ikm_size, salt, salt_size, info, info_size, L, okm }
    // INFO(Rafael): Test cases from RFC-5869.
    struct test_step test_vector[] = {
        // INFO(Rafael): Test case 1.
        add_hkdf_test_case(sha256,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 22,
                           "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c", 13,
                           "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9", 10,
                           42, "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a"
                               "\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf"
                               "\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65"),
        // INFO(Rafael): Test case 2.
        add_hkdf_test_case(sha256,
                           "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                           "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
                           "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
                           "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
                           "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f", 80,
                           "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
                           "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
                           "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
                           "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
                           "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf", 80,
                           "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
                           "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
                           "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
                           "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
                           "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff", 80,
                           82, "\xb1\x1e\x39\x8d\xc8\x03\x27\xa1\xc8\xe7\xf7\x8c\x59\x6a\x49\x34"
                               "\x4f\x01\x2e\xda\x2d\x4e\xfa\xd8\xa0\x50\xcc\x4c\x19\xaf\xa9\x7c"
                               "\x59\x04\x5a\x99\xca\xc7\x82\x72\x71\xcb\x41\xc6\x5e\x59\x0e\x09"
                               "\xda\x32\x75\x60\x0c\x2f\x09\xb8\x36\x77\x93\xa9\xac\xa3\xdb\x71"
                               "\xcc\x30\xc5\x81\x79\xec\x3e\x87\xc1\x4c\x01\xd5\xc1\xf3\x43\x4f"
                               "\x1d\x87"),
        // INFO(Rafael): Test case 3.
        add_hkdf_test_case(sha256,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 22,
                           "", 0,
                           "", 0,
                           42, "\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f\x71\x5f\x80\x2a\x06\x3c\x5a\x31"
                               "\xb8\xa1\x1f\x5c\x5e\xe1\x87\x9e\xc3\x45\x4e\x5f\x3c\x73\x8d\x2d"
                               "\x9d\x20\x13\x95\xfa\xa4\xb6\x1a\x96\xc8"),
        add_hkdf_test_case(sha256,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 22,
                           "",   0,
                           NULL, 0,
                           42, "\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f\x71\x5f\x80\x2a\x06\x3c\x5a\x31"
                               "\xb8\xa1\x1f\x5c\x5e\xe1\x87\x9e\xc3\x45\x4e\x5f\x3c\x73\x8d\x2d"
                               "\x9d\x20\x13\x95\xfa\xa4\xb6\x1a\x96\xc8"),
        // INFO(Rafael): Test case 4.
        add_hkdf_test_case(sha1,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 11,
                           "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c", 13,
                           "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9", 10,
                           42, "\x08\x5a\x01\xea\x1b\x10\xf3\x69\x33\x06\x8b\x56\xef\xa5\xad\x81"
                               "\xa4\xf1\x4b\x82\x2f\x5b\x09\x15\x68\xa9\xcd\xd4\xf1\x55\xfd\xa2"
                               "\xc2\x2e\x42\x24\x78\xd3\x05\xf3\xf8\x96"),
        // INFO(Rafael): Test case 5.
        add_hkdf_test_case(sha1,
                           "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                           "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
                           "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
                           "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
                           "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f", 80,
                           "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
                           "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
                           "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
                           "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
                           "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf", 80,
                           "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
                           "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
                           "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
                           "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
                           "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff", 80,
                           82, "\x0b\xd7\x70\xa7\x4d\x11\x60\xf7\xc9\xf1\x2c\xd5\x91\x2a\x06\xeb"
                               "\xff\x6a\xdc\xae\x89\x9d\x92\x19\x1f\xe4\x30\x56\x73\xba\x2f\xfe"
                               "\x8f\xa3\xf1\xa4\xe5\xad\x79\xf3\xf3\x34\xb3\xb2\x02\xb2\x17\x3c"
                               "\x48\x6e\xa3\x7c\xe3\xd3\x97\xed\x03\x4c\x7f\x9d\xfe\xb1\x5c\x5e"
                               "\x92\x73\x36\xd0\x44\x1f\x4c\x43\x00\xe2\xcf\xf0\xd0\x90\x0b\x52"
                               "\xd3\xb4"),
        // INFO(Rafael): Test case 6.
        add_hkdf_test_case(sha1,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 22,
                           "", 0,
                           "", 0,
                           42, "\x0a\xc1\xaf\x70\x02\xb3\xd7\x61\xd1\xe5\x52\x98\xda\x9d\x05\x06"
                               "\xb9\xae\x52\x05\x72\x20\xa3\x06\xe0\x7b\x6b\x87\xe8\xdf\x21\xd0"
                               "\xea\x00\x03\x3d\xe0\x39\x84\xd3\x49\x18"),
        add_hkdf_test_case(sha1,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 22,
                           "",   0,
                           NULL, 0,
                           42, "\x0a\xc1\xaf\x70\x02\xb3\xd7\x61\xd1\xe5\x52\x98\xda\x9d\x05\x06"
                               "\xb9\xae\x52\x05\x72\x20\xa3\x06\xe0\x7b\x6b\x87\xe8\xdf\x21\xd0"
                               "\xea\x00\x03\x3d\xe0\x39\x84\xd3\x49\x18"),
        // INFO(Rafael): Test case 7.
        add_hkdf_test_case(sha1,
                           "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
                           "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 22,
                           NULL, 0,
                           "",   0,
                           42, "\x2c\x91\x11\x72\x04\xd7\x45\xf3\x50\x0d\x63\x6a\x62\xf6\x4f\x0a"
                               "\xb3\xba\xe5\x48\xaa\x53\xd4\x23\xb0\xd1\xf2\x7e\xbb\xa6\xf5\xe5"
                               "\x67\x3a\x08\x1d\x70\xcc\xe7\xac\xfc\x48")

    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_u8_t *okm;
    for (t = 0; t < test_vector_nr; t++) {
        okm = kryptos_do_hkdf(test_vector[t].ikm,
                              test_vector[t].ikm_size,
                              test_vector[t].h, test_vector[t].h_input_size, test_vector[t].h_size,
                              test_vector[t].salt,
                              test_vector[t].salt_size,
                              test_vector[t].info,
                              test_vector[t].info_size,
                              test_vector[t].L);
        CUTE_ASSERT(okm != NULL);
        CUTE_ASSERT(memcmp(okm, test_vector[t].okm, test_vector[t].L) == 0);
        kryptos_freeseg(okm, test_vector[t].L);
    }
#undef add_hkdf_test_case
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hkdf_macro_tests)
    // WARN(Rafael): Keep the prints. It is trying to access n expected bytes.
    //               If n bytes were not returned this test will explode and we will know that something went wrong here.
    kryptos_u8_t *okm, *op, *op_end;
    okm = kryptos_hkdf("Gardenia", 8, sha3_512, "", 0, "", 0, 18);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 18;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 18);

    okm = kryptos_hkdf("Slow Cheetah", 12, whirlpool, "RHCP", 4, "Stadium Arcadium", 16, 22);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 22;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 22);

    okm = kryptos_hkdf("Joe Cool", 8, tiger, "", 0, "", 0, 113);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 113;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 113);

    okm = kryptos_hkdf("HKDF", 4, tiger, "FDKH", 4, "", 0, 256);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 256;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 256);

    okm = kryptos_hkdf("Dulcimer Stomp", 14, md5, "Pump", 4, "The Other Side", 14, 1024);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 1024;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 1024);

    okm = kryptos_hkdf("Ahhhhh", 6, md4, "", 0, "", 0, 2048);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 2048;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 2048);

    okm = kryptos_hkdf("boo!", 4, sha3_256, "ahh!", 4, "duh!", 4, 8);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 8;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 8);
CUTE_TEST_CASE_END
