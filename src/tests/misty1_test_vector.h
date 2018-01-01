/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_MISTY1_TEST_VECTOR_H
#define KRYPTOS_TESTS_MISTY1_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(misty1, block_cipher) = {
    add_test_vector_data("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         16,
                         "\x01\x23\x45\x67\x89\xAB\xCD\xEF",
                         "\x8B\x1D\xA5\xF5\x6A\xB3\xD0\x7C",
                         "\x01\x23\x45\x67\x89\xAB\xCD\xEF",
                         8),
    add_test_vector_data("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         16,
                         "\xFE\xDC\xBA\x98\x76\x54\x32\x10",
                         "\x04\xB6\x82\x40\xB1\x3B\xE9\x5D",
                         "\xFE\xDC\xBA\x98\x76\x54\x32\x10",
                         8)
};

#endif
