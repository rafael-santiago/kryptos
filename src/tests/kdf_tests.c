/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "kdf_tests.h"
#include <kryptos.h>

CUTE_TEST_CASE(kryptos_do_argon2_tests)
    struct test_step {
        kryptos_argon2_hash_type_t htype;
        kryptos_u32_t memory_size_kb;
        kryptos_u32_t iterations;
        kryptos_u32_t parallelism;
        kryptos_u32_t tag_size;
        kryptos_u8_t *password;
        kryptos_u32_t password_size;
        kryptos_u8_t *salt;
        kryptos_u32_t salt_size;
        kryptos_u8_t *key;
        kryptos_u32_t key_size;
        kryptos_u8_t *associated_data;
        kryptos_u32_t associated_data_size;
        kryptos_u8_t *expected;
        kryptos_u32_t expected_size;
    };
#define add_argon2_test_case(t, m, i, pl, ts, p, ps, s, s_sz, k, ks, a, as, e, es)\
    { t, m, i, pl, ts, p, ps, s, s_sz, k, ks, a, as, e, es }
    // INFO(Rafael): This following test vector is picked from the Argon2's reference implementation.
    struct test_step test_vector[] = {
        add_argon2_test_case(kArgon2d, 32, 3, 4, 32,
                             "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                             "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", 32,
                             "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02", 16,
                             "\x03\x03\x03\x03\x03\x03\x03\x03", 8,
                             "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04", 12,
                             "\x51\x2B\x39\x1B\x6F\x11\x62\x97\x53\x71\xD3\x09\x19\x73\x42\x94"
                             "\xF8\x68\xE3\xBE\x39\x84\xF3\xC1\xA1\x3A\x4D\xB9\xFA\xBE\x4A\xCB", 32),
        add_argon2_test_case(kArgon2i, 32, 3, 4, 32,
                             "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                             "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", 32,
                             "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02", 16,
                             "\x03\x03\x03\x03\x03\x03\x03\x03", 8,
                             "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04", 12,
                             "\xC8\x14\xD9\xD1\xDC\x7F\x37\xAA\x13\xF0\xD7\x7F\x24\x94\xBD\xA1"
                             "\xC8\xDE\x6B\x01\x6D\xD3\x88\xD2\x99\x52\xA4\xC4\x67\x2B\x6C\xE8", 32),
        add_argon2_test_case(kArgon2id, 32, 3, 4, 32,
                             "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                             "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01", 32,
                             "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02", 16,
                             "\x03\x03\x03\x03\x03\x03\x03\x03", 8,
                             "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04", 12,
                             "\x0D\x64\x0D\xF5\x8D\x78\x76\x6C\x08\xC0\x37\xA3\x4A\x8B\x53\xC9"
                             "\xD0\x1E\xF0\x45\x2D\x75\xB6\x5E\xB5\x25\x20\xE9\x6B\x01\xE6\x59", 32)
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t *tag;
    for (t = 0; t < tv_nr; t++) {
        tag = kryptos_do_argon2(test_vector[t].password, test_vector[t].password_size,
                                test_vector[t].salt, test_vector[t].salt_size,
                                test_vector[t].parallelism,
                                test_vector[t].tag_size,
                                test_vector[t].memory_size_kb, test_vector[t].iterations,
                                test_vector[t].key, test_vector[t].key_size,
                                test_vector[t].associated_data, test_vector[t].associated_data_size,
                                test_vector[t].htype);
        CUTE_ASSERT(tag != NULL);
        CUTE_ASSERT(memcmp(tag, test_vector[t].expected, test_vector[t].expected_size) == 0);
        kryptos_freeseg(tag, test_vector[t].tag_size);
    }
#undef add_argon2_test_case
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_argon2_macro_tests)
    // WARN(Rafael): Keep the prints. It is trying to access n expected bytes.
    //               If n bytes were not returned this test will explode and we will know that something went wrong here.
    kryptos_u8_t *okm, *op, *op_end;
    okm = kryptos_argon2d("Gardenia", 8, "", 0, 5, 128, 64, 20, "slow", 4, "", 0);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 128;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 128);

    okm = kryptos_argon2i("Gardenia", 8, "", 0, 5, 128, 64, 20, "slow", 4, "", 0);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 128;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 128);

    okm = kryptos_argon2id("Gardenia", 8, "", 0, 5, 128, 64, 20, "slow", 4, "", 0);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 128;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 128);

    okm = kryptos_argon2d("Ash Gray Sunday", 15, "Revelator", 9, 5, 16, 64, 20, "Black Rose Way", 14, "Anita Grey", 10);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 16;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 16);

    okm = kryptos_argon2i("Ash Gray Sunday", 15, "Revelator", 9, 5, 16, 64, 20, "Black Rose Way", 14, "Anita Grey", 10);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 16;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 16);

    okm = kryptos_argon2id("Ash Gray Sunday", 15, "Revelator", 9, 5, 16, 64, 20, "Black Rose Way", 14, "Anita Grey", 10);
    CUTE_ASSERT(okm != NULL);
    op = okm;
    op_end = op + 16;
    printf("\t OKM = ");
    while (op != op_end) {
        printf("%.2X", *op);
        op++;
    }
    printf("\n");
    kryptos_freeseg(okm, 16);

    okm = kryptos_argon2d("Ash Gray Sunday", 15, "Revelator", 9, 5, 1024, 64, 20, "Black Rose Way", 14, "Anita Grey", 10);
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

    okm = kryptos_argon2i("Ash Gray Sunday", 15, "Revelator", 9, 5, 1024, 64, 20, "Black Rose Way", 14, "Anita Grey", 10);
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

    okm = kryptos_argon2id("Ash Gray Sunday", 15, "Revelator", 9, 5, 1024, 64, 20, "Black Rose Way", 14, "Anita Grey", 10);
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
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_do_argon2_bounds_tests)
    kryptos_u32_t memory_size_kb = (0xFFFFFFFF >> 3) + 1;
    kryptos_u32_t iterations = (0xFFFFFFFF >> 3) + 1;
    kryptos_u32_t parallelism = 0x00FFFFFF + 1;
    kryptos_u32_t tag_size = (0xFFFFFFFF >> 3) + 1;
    size_t password_size = (0xFFFFFFFF >> 3) + 1;
    size_t salt_size = (0xFFFFFFFF >> 3) + 1;
    size_t key_size = (0xFFFFFFFF >> 3) + 1;
    size_t associated_data_size = (0xFFFFFFFF >> 3) + 1;
    kryptos_u8_t *tag;

    CUTE_ASSERT(kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                  iterations, NULL, key_size, NULL, associated_data_size, kArgon2d) == NULL);

    password_size = 0;

    CUTE_ASSERT(kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                  iterations, NULL, key_size, NULL, associated_data_size, kArgon2d) == NULL);

    salt_size = 0;

    CUTE_ASSERT(kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                  iterations, NULL, key_size, NULL, associated_data_size, kArgon2d) == NULL);

    parallelism = 3;

    CUTE_ASSERT(kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                  iterations, NULL, key_size, NULL, associated_data_size, kArgon2d) == NULL);

    tag_size = 32;

    CUTE_ASSERT(kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                  iterations, NULL, key_size, NULL, associated_data_size, kArgon2d) == NULL);

    memory_size_kb = 32;

    CUTE_ASSERT(kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                  iterations, NULL, key_size, NULL, associated_data_size, kArgon2d) == NULL);

    iterations = 3;

    CUTE_ASSERT(kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                  iterations, NULL, key_size, NULL, associated_data_size, kArgon2d) == NULL);

    key_size = 0;

    CUTE_ASSERT(kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                  iterations, NULL, key_size, NULL, associated_data_size, kArgon2d) == NULL);

    associated_data_size = 0;

    CUTE_ASSERT((tag = kryptos_do_argon2(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                         iterations, NULL, key_size, NULL, associated_data_size, kArgon2d)) != NULL);

    kryptos_freeseg(tag, tag_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_argon2_macro_bounds_tests)
    kryptos_u32_t memory_size_kb = (0xFFFFFFFF >> 3) + 1;
    kryptos_u32_t iterations = (0xFFFFFFFF >> 3) + 1;
    kryptos_u32_t parallelism = 0x00FFFFFF + 1;
    kryptos_u32_t tag_size = (0xFFFFFFFF >> 3) + 1;
    size_t password_size = (0xFFFFFFFF >> 3) + 1;
    size_t salt_size = (0xFFFFFFFF >> 3) + 1;
    size_t key_size = (0xFFFFFFFF >> 3) + 1;
    size_t associated_data_size = (0xFFFFFFFF >> 3) + 1;
    kryptos_u8_t *tag;

    CUTE_ASSERT(kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    password_size = 0;

    CUTE_ASSERT(kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    salt_size = 0;

    CUTE_ASSERT(kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    parallelism = 3;

    CUTE_ASSERT(kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    tag_size = 32;

    CUTE_ASSERT(kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    memory_size_kb = 32;

    CUTE_ASSERT(kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    iterations = 3;

    CUTE_ASSERT(kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    key_size = 0;

    CUTE_ASSERT(kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    associated_data_size = 0;

    CUTE_ASSERT((tag = kryptos_argon2d(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                       iterations, NULL, key_size, NULL, associated_data_size)) != NULL);

    kryptos_freeseg(tag, tag_size);

    memory_size_kb = (0xFFFFFFFF >> 3) + 1;
    iterations = (0xFFFFFFFF >> 3) + 1;
    parallelism = 0x00FFFFFF + 1;
    tag_size = (0xFFFFFFFF >> 3) + 1;
    password_size = (0xFFFFFFFF >> 3) + 1;
    salt_size = (0xFFFFFFFF >> 3) + 1;
    key_size = (0xFFFFFFFF >> 3) + 1;
    associated_data_size = (0xFFFFFFFF >> 3) + 1;

    CUTE_ASSERT(kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    password_size = 0;

    CUTE_ASSERT(kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    salt_size = 0;

    CUTE_ASSERT(kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    parallelism = 3;

    CUTE_ASSERT(kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    tag_size = 32;

    CUTE_ASSERT(kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    memory_size_kb = 32;

    CUTE_ASSERT(kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    iterations = 3;

    CUTE_ASSERT(kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    key_size = 0;

    CUTE_ASSERT(kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    associated_data_size = 0;

    CUTE_ASSERT((tag = kryptos_argon2i(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                       iterations, NULL, key_size, NULL, associated_data_size)) != NULL);

    kryptos_freeseg(tag, tag_size);

    memory_size_kb = (0xFFFFFFFF >> 3) + 1;
    iterations = (0xFFFFFFFF >> 3) + 1;
    parallelism = 0x00FFFFFF + 1;
    tag_size = (0xFFFFFFFF >> 3) + 1;
    password_size = (0xFFFFFFFF >> 3) + 1;
    salt_size = (0xFFFFFFFF >> 3) + 1;
    key_size = (0xFFFFFFFF >> 3) + 1;
    associated_data_size = (0xFFFFFFFF >> 3) + 1;

    CUTE_ASSERT(kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                 iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    password_size = 0;

    CUTE_ASSERT(kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                 iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    salt_size = 0;

    CUTE_ASSERT(kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                 iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    parallelism = 3;

    CUTE_ASSERT(kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                 iterations, NULL, key_size, NULL, associated_data_size) == NULL);

    tag_size = 32;

    CUTE_ASSERT(kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                 iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    memory_size_kb = 32;

    CUTE_ASSERT(kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                 iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    iterations = 3;

    CUTE_ASSERT(kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                 iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    key_size = 0;

    CUTE_ASSERT(kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                 iterations, NULL, key_size, NULL, associated_data_size) == NULL);
    associated_data_size = 0;

    CUTE_ASSERT((tag = kryptos_argon2id(NULL, password_size, NULL, salt_size, parallelism, tag_size, memory_size_kb,
                                        iterations, NULL, key_size, NULL, associated_data_size)) != NULL);

    kryptos_freeseg(tag, tag_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_do_pbkdf2_tests)
    struct test_step {
        kryptos_hash_func prf;
        kryptos_hash_size_func prf_input_size;
        kryptos_hash_size_func prf_size;
        kryptos_u8_t *password;
        size_t password_size;
        kryptos_u8_t *salt;
        size_t salt_size;
        size_t count;
        size_t dklen;
        kryptos_u8_t *expected;
    };
#define add_pbkdf2_test_case(h, p, p_size, s, s_size, c, d, e)\
    { kryptos_ ## h ## _hash, kryptos_ ## h ## _hash_input_size, kryptos_ ## h ## _hash_size, p, p_size, s, s_size, c, d, e }
    // INFO(Rafael): Test vectors from RFC-6070.
    struct test_step test_vector[] = {
        add_pbkdf2_test_case(sha1,
                             "password",
                             8,
                             "salt",
                             4,
                             1,
                             20,
                             "\x0C\x60\xC8\x0F\x96\x1F\x0E\x71\xF3\xA9"
                             "\xB5\x24\xAF\x60\x12\x06\x2F\xE0\x37\xA6"),
        add_pbkdf2_test_case(sha1,
                             "password",
                             8,
                             "salt",
                             4,
                             2,
                             20,
                             "\xEA\x6C\x01\x4D\xC7\x2D\x6F\x8C\xCD\x1E"
                             "\xD9\x2A\xCE\x1D\x41\xF0\xD8\xDE\x89\x57"),
        add_pbkdf2_test_case(sha1,
                             "password",
                             8,
                             "salt",
                             4,
                             4096,
                             20,
                             "\x4B\x00\x79\x01\xB7\x65\x48\x9A\xBE\xAD"
                             "\x49\xD9\x26\xF7\x21\xD0\x65\xA4\x29\xC1"),
        /*add_pbkdf2_test_case(sha1,
                             "password",
                             8,
                             "salt",
                             4,
                             16777216,
                             20,
                             "\xEE\xFE\x3D\x61\xCD\x4D\xA4\xE4\xE9\x94"
                             "\x5B\x3D\x6B\xA2\x15\x8C\x26\x34\xE9\x84"),*/ // INFO(Rafael): Too slow! But passing.
        add_pbkdf2_test_case(sha1,
                             "passwordPASSWORDpassword",
                             24,
                             "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                             36,
                             4096,
                             25,
                             "\x3D\x2E\xEC\x4F\xE4\x1C\x84\x9B\x80\xC8"
                             "\xD8\x36\x62\xC0\xE4\x4A\x8B\x29\x1A\x96"
                             "\x4C\xF2\xF0\x70\x38"),
        add_pbkdf2_test_case(sha1,
                             "pass\x00word",
                             9,
                             "sa\x00lt",
                             5,
                             4096,
                             16,
                             "\x56\xFA\x6A\xA7\x55\x48\x09\x9D\xCC\x37\xD7\xF0\x34\x25\xE0\xC3"),
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_u8_t *dk;
    for (t = 0; t < test_vector_nr; t++) {
        dk = kryptos_do_pbkdf2(test_vector[t].password, test_vector[t].password_size,
                               test_vector[t].prf, test_vector[t].prf_input_size, test_vector[t].prf_size,
                               test_vector[t].salt, test_vector[t].salt_size,
                               test_vector[t].count, test_vector[t].dklen);
        CUTE_ASSERT(dk != NULL);
        CUTE_ASSERT(memcmp(dk, test_vector[t].expected, test_vector[t].dklen) == 0);
        kryptos_freeseg(dk, test_vector[t].dklen);
    }
#undef add_pbkdkf2_test_case
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_pbkdf2_macro_tests)
    // WARN(Rafael): Keep the prints. It is trying to access n expected bytes.
    //               If n bytes were not returned this test will explode and we will know that something went wrong here.
    kryptos_u8_t *dk, *dk_p, *dk_p_end;
    dk = kryptos_pbkdf2("Gardenia", 8, sha3_512, "", 0, 188, 18);
    CUTE_ASSERT(dk != NULL);
    dk_p = dk;
    dk_p_end = dk_p + 18;
    printf("\t DK = ");
    while (dk_p != dk_p_end) {
        printf("%.2X", *dk_p);
        dk_p++;
    }
    printf("\n");
    kryptos_freeseg(dk, 18);

    dk = kryptos_pbkdf2("Slow Cheetah", 12, whirlpool, "RHCP", 4, 16, 22);
    CUTE_ASSERT(dk != NULL);
    dk_p = dk;
    dk_p_end = dk_p + 22;
    printf("\t DK = ");
    while (dk_p != dk_p_end) {
        printf("%.2X", *dk_p);
        dk_p++;
    }
    printf("\n");
    kryptos_freeseg(dk, 22);

    dk = kryptos_pbkdf2("Joe Cool", 8, tiger, "", 0, 27, 113);
    CUTE_ASSERT(dk != NULL);
    dk_p = dk;
    dk_p_end = dk_p + 113;
    printf("\t DK = ");
    while (dk_p != dk_p_end) {
        printf("%.2X", *dk_p);
        dk_p++;
    }
    printf("\n");
    kryptos_freeseg(dk, 113);

    dk = kryptos_pbkdf2("PBKDF2", 6, tiger, "2FDKBP", 6, 5, 256);
    CUTE_ASSERT(dk != NULL);
    dk_p = dk;
    dk_p_end = dk_p + 256;
    printf("\t DK = ");
    while (dk_p != dk_p_end) {
        printf("%.2X", *dk_p);
        dk_p++;
    }
    printf("\n");
    kryptos_freeseg(dk, 256);

    dk = kryptos_pbkdf2("Dulcimer Stomp", 14, md5, "Pump", 4, 14, 1024);
    CUTE_ASSERT(dk != NULL);
    dk_p = dk;
    dk_p_end = dk_p + 1024;
    printf("\t DK = ");
    while (dk_p != dk_p_end) {
        printf("%.2X", *dk_p);
        dk_p++;
    }
    printf("\n");
    kryptos_freeseg(dk, 1024);

    dk = kryptos_pbkdf2("Ahhhhh", 6, md4, "", 0, 32, 2048);
    CUTE_ASSERT(dk != NULL);
    dk_p = dk;
    dk_p_end = dk_p + 2048;
    printf("\t DK = ");
    while (dk_p != dk_p_end) {
        printf("%.2X", *dk_p);
        dk_p++;
    }
    printf("\n");
    kryptos_freeseg(dk, 2048);

    dk = kryptos_pbkdf2("boo!", 4, sha3_256, "ahh!", 4, 4, 8);
    CUTE_ASSERT(dk != NULL);
    dk_p = dk;
    dk_p_end = dk_p + 8;
    printf("\t DK = ");
    while (dk_p != dk_p_end) {
        printf("%.2X", *dk_p);
        dk_p++;
    }
    printf("\n");
    kryptos_freeseg(dk, 8);
CUTE_TEST_CASE_END

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
