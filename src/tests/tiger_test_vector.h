/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_TIGER_TEST_VECTOR_H
#define KRYPTOS_TESTS_TIGER_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(tiger, hash) = {
    add_test_vector_data("", 0,
                         "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3", 48,
                         "\x32\x93\xAC\x63\x0C\x13\xF0\x24\x5F\x92\xBB\xB1"
                         "\x76\x6E\x16\x16\x7A\x4E\x58\x49\x2D\xDE\x73\xF3", 24),
    add_test_vector_data("a", 1,
                         "77BEFBEF2E7EF8AB2EC8F93BF587A7FC613E247F5F247809", 48,
                         "\x77\xBE\xFB\xEF\x2E\x7E\xF8\xAB\x2E\xC8\xF9\x3B"
                         "\xF5\x87\xA7\xFC\x61\x3E\x24\x7F\x5F\x24\x78\x09", 24),
    add_test_vector_data("abc", 3,
                         "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93", 48,
                         "\x2A\xAB\x14\x84\xE8\xC1\x58\xF2\xBF\xB8\xC5\xFF"
                         "\x41\xB5\x7A\x52\x51\x29\x13\x1C\x95\x7B\x5F\x93", 24),
    add_test_vector_data("message digest", 14,
                         "D981F8CB78201A950DCF3048751E441C517FCA1AA55A29F6", 48,
                         "\xD9\x81\xF8\xCB\x78\x20\x1A\x95\x0D\xCF\x30\x48"
                         "\x75\x1E\x44\x1C\x51\x7F\xCA\x1A\xA5\x5A\x29\xF6", 24),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "1714A472EEE57D30040412BFCC55032A0B11602FF37BEEE9", 48,
                         "\x17\x14\xA4\x72\xEE\xE5\x7D\x30\x04\x04\x12\xBF"
                         "\xCC\x55\x03\x2A\x0B\x11\x60\x2F\xF3\x7B\xEE\xE9", 24),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmno"
                         "mnopnopq", 56,
                         "0F7BF9A19B9C58F2B7610DF7E84F0AC3A71C631E7B53F78E", 48,
                         "\x0F\x7B\xF9\xA1\x9B\x9C\x58\xF2\xB7\x61\x0D\xF7"
                         "\xE8\x4F\x0A\xC3\xA7\x1C\x63\x1E\x7B\x53\xF7\x8E", 24),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijk", 32,
                         "24DA7C949CCDDEFA0A2AAB697D6AE0CCE491B12BBF2EFD25", 48,
                         "\x24\xDA\x7C\x94\x9C\xCD\xDE\xFA\x0A\x2A\xAB\x69"
                         "\x7D\x6A\xE0\xCC\xE4\x91\xB1\x2B\xBF\x2E\xFD\x25", 24)
};

#endif
