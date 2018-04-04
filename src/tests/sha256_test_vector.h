/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA256_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA256_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha256, hash) = {
    add_test_vector_data("", 0,
                         "E3B0C44298FC1C149AFBF4C8996FB924"
                         "27AE41E4649B934CA495991B7852B855", 64,
                         "\xE3\xB0\xC4\x42\x98\xFC\x1C\x14\x9A\xFB\xF4\xC8\x99\x6F\xB9\x24"
                         "\x27\xAE\x41\xE4\x64\x9B\x93\x4C\xA4\x95\x99\x1B\x78\x52\xB8\x55", 32),
    add_test_vector_data("a", 1,
                         "CA978112CA1BBDCAFAC231B39A23DC4D"
                         "A786EFF8147C4E72B9807785AFEE48BB", 64,
                         "\xCA\x97\x81\x12\xCA\x1B\xBD\xCA\xFA\xC2\x31\xB3\x9A\x23\xDC\x4D"
                         "\xA7\x86\xEF\xF8\x14\x7C\x4E\x72\xB9\x80\x77\x85\xAF\xEE\x48\xBB", 32),
    add_test_vector_data("abc", 3,
                         "BA7816BF8F01CFEA414140DE5DAE2223"
                         "B00361A396177A9CB410FF61F20015AD", 64,
                         "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22\x23"
                         "\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00\x15\xAD", 32),
    add_test_vector_data("message digest", 14,
                         "F7846F55CF23E14EEBEAB5B4E1550CAD"
                         "5B509E3348FBC4EFA3A1413D393CB650", 64,
                         "\xF7\x84\x6F\x55\xCF\x23\xE1\x4E\xEB\xEA\xB5\xB4\xE1\x55\x0C\xAD"
                         "\x5B\x50\x9E\x33\x48\xFB\xC4\xEF\xA3\xA1\x41\x3D\x39\x3C\xB6\x50", 32),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "71C480DF93D6AE2F1EFAD1447C66C952"
                         "5E316218CF51FC8D9ED832F2DAF18B73", 64,
                         "\x71\xC4\x80\xDF\x93\xD6\xAE\x2F\x1E\xFA\xD1\x44\x7C\x66\xC9\x52"
                         "\x5E\x31\x62\x18\xCF\x51\xFC\x8D\x9E\xD8\x32\xF2\xDA\xF1\x8B\x73", 32),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "248D6A61D20638B8E5C026930C3E6039"
                         "A33CE45964FF2167F6ECEDD419DB06C1", 64,
                         "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60\x39"
                         "\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB\x06\xC1", 32),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijk", 32,
                         "B09CBD263B043F000C5BEFCAA40BC2F55A4785E024E5DEB749B56061EAFB65E9", 64,
                         "\xB0\x9C\xBD\x26\x3B\x04\x3F\x00\x0C\x5B\xEF\xCA\xA4\x0B\xC2\xF5"
                         "\x5A\x47\x85\xE0\x24\xE5\xDE\xB7\x49\xB5\x60\x61\xEA\xFB\x65\xE9", 32)
};

#endif
