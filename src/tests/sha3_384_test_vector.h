/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA3_384_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA3_384_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha3_384, hash) = {
    add_test_vector_data("abc", 3,
                         "EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B2"
                         "98D88CEA927AC7F539F1EDF228376D25", 96,
                         "\xEC\x01\x49\x82\x88\x51\x6F\xC9\x26\x45\x9F\x58\xE2\xC6\xAD\x8D"
                         "\xF9\xB4\x73\xCB\x0F\xC0\x8C\x25\x96\xDA\x7C\xF0\xE4\x9B\xE4\xB2"
                         "\x98\xD8\x8C\xEA\x92\x7A\xC7\xF5\x39\xF1\xED\xF2\x28\x37\x6D\x25", 48),
    add_test_vector_data("", 0,
                         "0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2A"
                         "C3713831264ADB47FB6BD1E058D5F004", 96,
                         "\x0C\x63\xA7\x5B\x84\x5E\x4F\x7D\x01\x10\x7D\x85\x2E\x4C\x24\x85"
                         "\xC5\x1A\x50\xAA\xAA\x94\xFC\x61\x99\x5E\x71\xBB\xEE\x98\x3A\x2A"
                         "\xC3\x71\x38\x31\x26\x4A\xDB\x47\xFB\x6B\xD1\xE0\x58\xD5\xF0\x04", 48),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "991C665755EB3A4B6BBDFB75C78A492E8C56A22C5C4D7E429BFDBC32B9D4AD5A"
                         "A04A1F076E62FEA19EEF51ACD0657C22", 96,
                         "\x99\x1C\x66\x57\x55\xEB\x3A\x4B\x6B\xBD\xFB\x75\xC7\x8A\x49\x2E"
                         "\x8C\x56\xA2\x2C\x5C\x4D\x7E\x42\x9B\xFD\xBC\x32\xB9\xD4\xAD\x5A"
                         "\xA0\x4A\x1F\x07\x6E\x62\xFE\xA1\x9E\xEF\x51\xAC\xD0\x65\x7C\x22", 48),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                         "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "79407D3B5916B59C3E30B09822974791C313FB9ECC849E406F23592D04F625DC"
                         "8C709B98B43B3852B337216179AA7FC7", 96,
                         "\x79\x40\x7D\x3B\x59\x16\xB5\x9C\x3E\x30\xB0\x98\x22\x97\x47\x91"
                         "\xC3\x13\xFB\x9E\xCC\x84\x9E\x40\x6F\x23\x59\x2D\x04\xF6\x25\xDC"
                         "\x8C\x70\x9B\x98\xB4\x3B\x38\x52\xB3\x37\x21\x61\x79\xAA\x7F\xC7", 48)
};

#endif
