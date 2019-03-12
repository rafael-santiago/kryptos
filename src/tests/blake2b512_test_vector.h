/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_BLAKE2B512_TEST_VECTOR_H
#define KRYPTOS_TESTS_BLAKE2B512_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(blake2b512, hash) = {
    // INFO(Rafael): Test vector from RFC-7693.
    add_test_vector_data("abc", 3,
                         "BA80A53F981C4D0D6A2797B69F12F6E9"
                         "4C212F14685AC4B74B12BB6FDBFFA2D1"
                         "7D87C5392AAB792DC252D5DE4533CC95"
                         "18D38AA8DBF1925AB92386EDD4009923", 128,
                         "\xBA\x80\xA5\x3F\x98\x1C\x4D\x0D\x6A\x27\x97\xB6\x9F\x12\xF6\xE9"
                         "\x4C\x21\x2F\x14\x68\x5A\xC4\xB7\x4B\x12\xBB\x6F\xDB\xFF\xA2\xD1"
                         "\x7D\x87\xC5\x39\x2A\xAB\x79\x2D\xC2\x52\xD5\xDE\x45\x33\xCC\x95"
                         "\x18\xD3\x8A\xA8\xDB\xF1\x92\x5A\xB9\x23\x86\xED\xD4\x00\x99\x23", 64)
};

#endif
