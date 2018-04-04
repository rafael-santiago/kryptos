/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_RIPEMD160_TEST_VECTOR_H
#define KRYPTOS_TESTS_RIPEMD160_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(ripemd160, hash) = {
    add_test_vector_data("", 0,
                         "9C1185A5C5E9FC54612808977EE8F548B2258D31", 40,
                         "\x9C\x11\x85\xA5\xC5\xE9\xFC\x54\x61\x28\x08\x97\x7E\xE8\xF5\x48\xB2\x25\x8D\x31", 20),
    add_test_vector_data("a", 1,
                         "0BDC9D2D256B3EE9DAAE347BE6F4DC835A467FFE", 40,
                         "\x0B\xDC\x9D\x2D\x25\x6B\x3E\xE9\xDA\xAE\x34\x7B\xE6\xF4\xDC\x83\x5A\x46\x7F\xFE", 20),
    add_test_vector_data("abc", 3,
                         "8EB208F7E05D987A9B044A8E98C6B087F15A0BFC", 40,
                         "\x8E\xB2\x08\xF7\xE0\x5D\x98\x7A\x9B\x04\x4A\x8E\x98\xC6\xB0\x87\xF1\x5A\x0B\xFC", 20),
    add_test_vector_data("message digest", 14,
                         "5D0689EF49D2FAE572B881B123A85FFA21595F36", 40,
                         "\x5D\x06\x89\xEF\x49\xD2\xFA\xE5\x72\xB8\x81\xB1\x23\xA8\x5F\xFA\x21\x59\x5F\x36", 20),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "F71C27109C692C1B56BBDCEB5B9D2865B3708DBC", 40,
                         "\xF7\x1C\x27\x10\x9C\x69\x2C\x1B\x56\xBB\xDC\xEB\x5B\x9D\x28\x65\xB3\x70\x8D\xBC", 20),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "12A053384A9C0C88E405A06C27DCF49ADA62EB2B", 40,
                         "\x12\xA0\x53\x38\x4A\x9C\x0C\x88\xE4\x05\xA0\x6C\x27\xDC\xF4\x9A\xDA\x62\xEB\x2B", 20),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijk", 32,
                         "94C264115404E633790DFCC87B587D3677067D9F", 40,
                         "\x94\xC2\x64\x11\x54\x04\xE6\x33\x79\x0D\xFC\xC8\x7B\x58\x7D\x36\x77\x06\x7D\x9F", 20)
};

#endif
