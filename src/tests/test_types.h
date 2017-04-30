/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_TEST_TYPES_H
#define KRYPTOS_TESTS_TEST_TYPES_H 1

#include <kryptos_types.h>

struct block_cipher_test_vector_ctx {
    kryptos_u8_t *key;
    size_t key_size;
    kryptos_u8_t *plain;
    kryptos_u8_t *cipher;
    kryptos_u8_t *decrypted;
    size_t block_size;
};

struct hash_test_vector_ctx {
    kryptos_u8_t *message;
    size_t message_size;
    kryptos_u8_t *hex_hash;
    size_t hex_hash_size;
    kryptos_u8_t *raw_hash;
    size_t raw_hash_size;
};

#define test_vector(cipher, type) static struct type ## _test_vector_ctx cipher ##_test_vector[]

#define add_test_vector_data(k, s, p, c, d, b) { (k), (s), (p), (c), (d), (b) }

#endif // KRYPTOS_TESTS_TEST_TYPES_H
