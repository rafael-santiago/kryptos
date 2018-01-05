/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA3_224_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA3_224_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha3_224, hash) = {
    add_test_vector_data("abc", 3,
                         "E642824C3F8CF24AD09234EE7D3C766FC9A3A5168D0C94AD73B46FDF", 56,
                         "\xE6\x42\x82\x4C\x3F\x8C\xF2\x4A\xD0\x92\x34\xEE\x7D\x3C"
                         "\x76\x6F\xC9\xA3\xA5\x16\x8D\x0C\x94\xAD\x73\xB4\x6F\xDF", 28),
    add_test_vector_data("", 0,
                         "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7", 56,
                         "\x6B\x4E\x03\x42\x36\x67\xDB\xB7\x3B\x6E\x15\x45\x4F\x0E"
                         "\xB1\xAB\xD4\x59\x7F\x9A\x1B\x07\x8E\x3F\x5B\x5A\x6B\xC7", 28),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "8A24108B154ADA21C9FD5574494479BA5C7E7AB76EF264EAD0FCCE33", 56,
                         "\x8A\x24\x10\x8B\x15\x4A\xDA\x21\xC9\xFD\x55\x74\x49\x44"
                         "\x79\xBA\x5C\x7E\x7A\xB7\x6E\xF2\x64\xEA\xD0\xFC\xCE\x33", 28),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "543E6868E1666C1A643630DF77367AE5A62A85070A51C14CBF665CBC",  56,
                         "\x54\x3E\x68\x68\xE1\x66\x6C\x1A\x64\x36\x30\xDF\x77\x36"
                         "\x7A\xE5\xA6\x2A\x85\x07\x0A\x51\xC1\x4C\xBF\x66\x5C\xBC",  28)
};

#endif
