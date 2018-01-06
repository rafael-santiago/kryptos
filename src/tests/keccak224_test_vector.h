/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_KECCAK224_TEST_VECTOR_H
#define KRYPTOS_TESTS_KECCAK224_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(keccak224, hash) = {
    add_test_vector_data("abc", 3,
                         "C30411768506EBE1C2871B1EE2E87D38DF342317300A9B97A95EC6A8", 56,
                         "\xC3\x04\x11\x76\x85\x06\xEB\xE1\xC2\x87\x1B\x1E\xE2\xE8"
                         "\x7D\x38\xDF\x34\x23\x17\x30\x0A\x9B\x97\xA9\x5E\xC6\xA8", 28),
    add_test_vector_data("", 0,
                         "F71837502BA8E10837BDD8D365ADB85591895602FC552B48B7390ABD", 56,
                         "\xF7\x18\x37\x50\x2B\xA8\xE1\x08\x37\xBD\xD8\xD3\x65\xAD"
                         "\xB8\x55\x91\x89\x56\x02\xFC\x55\x2B\x48\xB7\x39\x0A\xBD", 28),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "E51FAA2B4655150B931EE8D700DC202F763CA5F962C529EAE55012B6", 56,
                         "\xE5\x1F\xAA\x2B\x46\x55\x15\x0B\x93\x1E\xE8\xD7\x00\xDC"
                         "\x20\x2F\x76\x3C\xA5\xF9\x62\xC5\x29\xEA\xE5\x50\x12\xB6", 28),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "344298994B1B06873EAE2CE739C425C47291A2E24189E01B524F88DC",  56,
                         "\x34\x42\x98\x99\x4B\x1B\x06\x87\x3E\xAE\x2C\xE7\x39\xC4"
                         "\x25\xC4\x72\x91\xA2\xE2\x41\x89\xE0\x1B\x52\x4F\x88\xDC",  28)
};

#endif
