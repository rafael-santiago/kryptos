/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA3_256_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA3_256_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha3_256, hash) = {
    add_test_vector_data("abc", 3,
                         "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532", 64,
                         "\x3A\x98\x5D\xA7\x4F\xE2\x25\xB2\x04\x5C\x17\x2D\x6B\xD3\x90\xBD"
                         "\x85\x5F\x08\x6E\x3E\x9D\x52\x5B\x46\xBF\xE2\x45\x11\x43\x15\x32", 32),
    add_test_vector_data("", 0,
                         "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A", 64,
                         "\xA7\xFF\xC6\xF8\xBF\x1E\xD7\x66\x51\xC1\x47\x56\xA0\x61\xD6\x62"
                         "\xF5\x80\xFF\x4D\xE4\x3B\x49\xFA\x82\xD8\x0A\x4B\x80\xF8\x43\x4A", 32),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "41C0DBA2A9D6240849100376A8235E2C82E1B9998A999E21DB32DD97496D3376", 64,
                         "\x41\xC0\xDB\xA2\xA9\xD6\x24\x08\x49\x10\x03\x76\xA8\x23\x5E\x2C"
                         "\x82\xE1\xB9\x99\x8A\x99\x9E\x21\xDB\x32\xDD\x97\x49\x6D\x33\x76", 32),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                         "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "916F6061FE879741CA6469B43971DFDB28B1A32DC36CB3254E812BE27AAD1D18", 64,
                         "\x91\x6F\x60\x61\xFE\x87\x97\x41\xCA\x64\x69\xB4\x39\x71\xDF\xDB"
                         "\x28\xB1\xA3\x2D\xC3\x6C\xB3\x25\x4E\x81\x2B\xE2\x7A\xAD\x1D\x18", 32)

};

#endif
