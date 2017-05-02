/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA224_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA224_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha224, hash) = {
    add_test_vector_data("abc", 3,
                         "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7", 56,
                         "\x23\x09\x7D\x22\x34\x05\xD8\x22\x86\x42\xA4\x77\xBD\xA2"
                         "\x55\xB3\x2A\xAD\xBC\xE4\xBD\xA0\xB3\xF7\xE3\x6C\x9D\xA7", 28),
    add_test_vector_data("", 0,
                         "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F", 56,
                         "\xD1\x4A\x02\x8C\x2A\x3A\x2B\xC9\x47\x61\x02\xBB\x28\x82"
                         "\x34\xC4\x15\xA2\xB0\x1F\x82\x8E\xA6\x2A\xC5\xB3\xE4\x2F", 28),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525", 56,
                         "\x75\x38\x8B\x16\x51\x27\x76\xCC\x5D\xBA\x5D\xA1\xFD\x89"
                         "\x01\x50\xB0\xC6\x45\x5C\xB4\xF5\x8B\x19\x52\x52\x25\x25", 28),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "C97CA9A559850CE97A04A96DEF6D99A9E0E0E2AB14E6B8DF265FC0B3", 56,
                         "\xC9\x7C\xA9\xA5\x59\x85\x0C\xE9\x7A\x04\xA9\x6D\xEF\x6D"
                         "\x99\xA9\xE0\xE0\xE2\xAB\x14\xE6\xB8\xDF\x26\x5F\xC0\xB3", 28)
};

#endif
