/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_TRIPLE_DES_TEST_VECTOR_H
#define KRYPTOS_TESTS_TRIPLE_DES_TEST_VECTOR_H 1

#include "test_types.h"

//  WARN(Rafael): I picked it from NESSIE's 3DES test vector but the 3DES used by NESSIE was EDE instead of EEE, so I only
//                chose specific data that maps to the same result on both modes (EDE, EEE).

test_vector(triple_des, block_cipher) = {
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
                         8)
};

#endif // KRYPTOS_TESTS_TRIPLE_DES_TEST_VECTOR_H
