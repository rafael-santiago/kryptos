/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_PRESENT_TEST_VECTOR_H
#define KRYPTOS_TESTS_PRESENT_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(present80, block_cipher) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         10,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x55\x79\xC1\x38\x7B\x22\x84\x45",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         10,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\xA1\x12\xFF\xC7\x2F\x68\x41\x7B",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         10,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xE7\x2C\x46\xC0\xF5\x94\x50\x49",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         10,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x33\x33\xDC\xD3\x21\x32\x10\xD2",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8)
};

test_vector(present128, block_cipher) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x96\xDB\x70\x2A\x2E\x69\x00\xAF",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x3C\x60\x19\xE5\xE5\xED\xD5\x63",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x13\x23\x8C\x71\x02\x72\xA5\xD8",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x62\x8D\x9F\xBD\x42\x18\xE5\xB4 ",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8)
};

#endif
