/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA1_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA1_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha1, hash) = {
    add_test_vector_data("", 0,
                         "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", 40,
                         "\xDA\x39\xA3\xEE\x5E\x6B\x4B\x0D\x32\x55\xBF\xEF\x95\x60\x18\x90\xAF\xD8\x07\x09", 20),
    add_test_vector_data("a", 1,
                         "86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8", 40,
                         "\x86\xF7\xE4\x37\xFA\xA5\xA7\xFC\xE1\x5D\x1D\xDC\xB9\xEA\xEA\xEA\x37\x76\x67\xB8", 20),
    add_test_vector_data("abc", 0,
                         "A9993E364706816ABA3E25717850C26C9CD0D89D", 40,
                         "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D", 20),
    add_test_vector_data("message digest", 14,
                         "C12252CEDA8BE8994D5FA0290A47231C1D16AAE3", 40,
                         "\xC1\x22\x52\xCE\xDA\x8B\xE8\x99\x4D\x5F\xA0\x29\x0A\x47\x23\x1C\x1D\x16\xAA\xE3", 20),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "32D10C7B8CF96570CA04CE37F2A19D84240D3A89", 40,
                         "\x32\xD1\x0C\x7B\x8C\xF9\x65\x70\xCA\x04\xCE\x37\xF2\xA1\x9D\x84\x24\x0D\x3A\x89", 20),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "84983E441C3BD26EBAAE4AA1F95129E5E54670F1", 40,
                         "\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1", 20)
}

#endif
