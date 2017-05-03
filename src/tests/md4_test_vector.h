/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_MD4_TEST_VECTOR_H
#define KRYPTOS_TESTS_MD4_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(md4, hash) = {
    add_test_vector_data("", 0,
                         "31D6CFE0D16AE931B73C59D7E0C089C0", 32,
                         "\x31\xD6\xCF\xE0\xD1\x6A\xE9\x31\xB7\x3C\x59\xD7\xE0\xC0\x89\xC0", 16),
    add_test_vector_data("a", 1,
                         "BDE52CB31DE33E46245E05FBDBD6FB24", 32,
                         "\xBD\xE5\x2C\xB3\x1D\xE3\x3E\x46\x24\x5E\x05\xFB\xDB\xD6\xFB\x24", 16),
    add_test_vector_data("abc", 3,
                         "A448017AAF21D8525FC10AE87AA6729D", 32,
                         "\xA4\x48\x01\x7A\xAF\x21\xD8\x52\x5F\xC1\x0A\xE8\x7A\xA6\x72\x9D", 16),
    add_test_vector_data("message digest", 14,
                         "D9130A8164549FE818874806E1C7014B", 32,
                         "\xD9\x13\x0A\x81\x64\x54\x9F\xE8\x18\x87\x48\x06\xE1\xC7\x01\x4B", 16),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "D79E1C308AA5BBCDEEA8ED63DF412DA9", 32,
                         "\xD7\x9E\x1C\x30\x8A\xA5\xBB\xCD\xEE\xA8\xED\x63\xDF\x41\x2D\xA9", 16),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "4691A9EC81B1A6BD1AB8557240B245C5", 32,
                         "\x46\x91\xA9\xEC\x81\xB1\xA6\xBD\x1A\xB8\x55\x72\x40\xB2\x45\xC5", 16)
};

#endif
