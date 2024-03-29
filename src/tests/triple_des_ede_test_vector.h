/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_TRIPLE_DES_EDE_TEST_VECTOR_H
#define KRYPTOS_TESTS_TRIPLE_DES_EDE_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(triple_des_ede, block_cipher) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x95\xA8\xD7\x28\x13\xDA\xA9\x4D",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x0E\xEC\x14\x87\xDD\x8C\x26\xD5",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x7A\xD1\x6F\xFB\x79\xC4\x59\x26",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xD3\x74\x62\x94\xCA\x6A\x6C\xF3",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x8C\xCF\xCD\x24\x18\xE8\x57\x50",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xE7\x4C\xA1\x18\x08\xED\x17\xA3",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x0A\x63\x4C\x7A\x69\x89\x7F\x35",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x6C\x2C\x0F\x27\xE9\x73\xCE\x29",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x08",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x5A\x59\x45\x28\xBE\xBE\xF1\xCC",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x04",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xFC\xDB\x32\x91\xDE\x21\xF0\xC0",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x02",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x86\x9E\xFD\x7F\x9F\x26\x5A\x09",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x01",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x8C\xA6\x4D\xE9\xC1\xB1\x23\xA7",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07",
                         8,
                         "\x98\x26\x62\x60\x55\x53\x24\x4D",
                         "\x00\x11\x22\x33\x44\x55\x66\x77",
                         "\x98\x26\x62\x60\x55\x53\x24\x4D",
                         8),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00",
                         8,
                         "\x85\x98\x53\x8A\x8E\xCF\x11\x7D",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x85\x98\x53\x8A\x8E\xCF\x11\x7D",
                         8)
};

#endif // KRYPTOS_TESTS_TRIPLE_DES_EDE_TEST_VECTOR_H
