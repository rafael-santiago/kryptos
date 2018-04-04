/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_MD5_TEST_VECTOR_H
#define KRYPTOS_TESTS_MD5_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(md5, hash) = {
    add_test_vector_data("", 0,
                         "D41D8CD98F00B204E9800998ECF8427E", 32,
                         "\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\x09\x98\xEC\xF8\x42\x7E", 16),
    add_test_vector_data("a", 1,
                         "0CC175B9C0F1B6A831C399E269772661", 32,
                         "\x0C\xC1\x75\xB9\xC0\xF1\xB6\xA8\x31\xC3\x99\xE2\x69\x77\x26\x61", 16),
    add_test_vector_data("abc", 3,
                         "900150983CD24FB0D6963F7D28E17F72", 32,
                         "\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72", 16),
    add_test_vector_data("message digest", 14,
                         "F96B697D7CB7938D525A2F31AAF161D0", 32,
                         "\xF9\x6B\x69\x7D\x7C\xB7\x93\x8D\x52\x5A\x2F\x31\xAA\xF1\x61\xD0", 16),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "C3FCD3D76192E4007DFB496CCA67E13B", 32,
                         "\xC3\xFC\xD3\xD7\x61\x92\xE4\x00\x7D\xFB\x49\x6C\xCA\x67\xE1\x3B", 16),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "8215EF0796A20BCAAAE116D3876C664A", 32,
                         "\x82\x15\xEF\x07\x96\xA2\x0B\xCA\xAA\xE1\x16\xD3\x87\x6C\x66\x4A", 16),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijk", 32,
                         "8F52322928B91BF06561EA38DDF1752E", 32,
                         "\x8F\x52\x32\x29\x28\xB9\x1B\xF0\x65\x61\xEA\x38\xDD\xF1\x75\x2E", 16)
};

#endif
