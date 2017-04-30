/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_FEAL_TEST_VECTOR_H
#define KRYPTOS_TESTS_FEAL_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(feal, block_cipher) = {
    add_test_vector_data("\x01\x23\x45\x67\x89\xab\xcd\xef",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xCE\xEF\x2C\x86\xF2\x49\x07\x52",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming 8 rounds.
    add_test_vector_data("\x01\x23\x45\x67\x89\xab\xcd\xef",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x3A\xDE\x0D\x2A\xD8\x4D\x0B\x6F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming 16 rounds.
    add_test_vector_data("\x01\x23\x45\x67\x89\xab\xcd\xef",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x69\xB0\xFA\xE6\xDD\xED\x6B\x0B",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8) // INFO(Rafael): Assuming 32 rounds.
};

#endif
