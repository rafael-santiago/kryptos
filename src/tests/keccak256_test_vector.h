/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_KECCAK256_TEST_VECTOR_H
#define KRYPTOS_TESTS_KECCAK256_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(keccak256, hash) = {
    add_test_vector_data("abc", 3,
                         "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45", 64,
                         "\x4E\x03\x65\x7A\xEA\x45\xA9\x4F\xC7\xD4\x7B\xA8\x26\xC8\xD6\x67"
                         "\xC0\xD1\xE6\xE3\x3A\x64\xA0\x36\xEC\x44\xF5\x8F\xA1\x2D\x6C\x45", 32),
    add_test_vector_data("", 0,
                         "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470", 64,
                         "\xC5\xD2\x46\x01\x86\xF7\x23\x3C\x92\x7E\x7D\xB2\xDC\xC7\x03\xC0"
                         "\xE5\x00\xB6\x53\xCA\x82\x27\x3B\x7B\xFA\xD8\x04\x5D\x85\xA4\x70", 32),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "45D3B367A6904E6E8D502EE04999A7C27647F91FA845D456525FD352AE3D7371", 64,
                         "\x45\xD3\xB3\x67\xA6\x90\x4E\x6E\x8D\x50\x2E\xE0\x49\x99\xA7\xC2"
                         "\x76\x47\xF9\x1F\xA8\x45\xD4\x56\x52\x5F\xD3\x52\xAE\x3D\x73\x71", 32),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                         "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "F519747ED599024F3882238E5AB43960132572B7345FBEB9A90769DAFD21AD67", 64,
                         "\xF5\x19\x74\x7E\xD5\x99\x02\x4F\x38\x82\x23\x8E\x5A\xB4\x39\x60"
                         "\x13\x25\x72\xB7\x34\x5F\xBE\xB9\xA9\x07\x69\xDA\xFD\x21\xAD\x67", 32)

};

#endif
