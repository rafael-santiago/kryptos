/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_GOST_TEST_VECTOR_H
#define KRYPTOS_TESTS_GOST_TEST_VECTOR_H 1

#include "test_types.h"

// WARN(Rafael): GOST 28147-89 is hard to test because it does not includes official test vectors.
//               I extracted the following data from the sample implementation included in Applied Cryptography.
//               The GOST implementation here also uses the DES s-boxes.

test_vector(gost_ds, block_cipher) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xE7\x2B\x17\xD7\x02\xF1\x22\xC0",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x75\x71\x31\x34\xB6\x0F\xEC\x45\xA6\x07\xBB\x83\xAA\x37\x46\xAF"
                         "\x4F\xF9\x9D\xA6\xD1\xB5\x3B\x5B\x1B\x40\x2A\x1B\xAA\x03\x0D\x1B",
                         32,
                         "\x11\x22\x33\x44\x55\x66\x77\x88",
                         "\x1F\xDB\x93\x71\x38\xA4\x7D\x12",
                         "\x11\x22\x33\x44\x55\x66\x77\x88",
                         8)
};

test_vector(gost, block_cipher) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xA6\xC2\xFD\xC9\x12\x61\x0B\xE2",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x75\x71\x31\x34\xB6\x0F\xEC\x45\xA6\x07\xBB\x83\xAA\x37\x46\xAF"
                         "\x4F\xF9\x9D\xA6\xD1\xB5\x3B\x5B\x1B\x40\x2A\x1B\xAA\x03\x0D\x1B",
                         32,
                         "\x11\x22\x33\x44\x55\x66\x77\x88",
                         "\x4D\xB4\xC6\x80\xD7\xF7\x50\x5C",
                         "\x11\x22\x33\x44\x55\x66\x77\x88",
                         8)
};

#endif
