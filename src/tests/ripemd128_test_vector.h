/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_RIPEMD128_TEST_VECTOR_H
#define KRYPTOS_TESTS_RIPEMD128_TEST_VECTOR_H 1

#include "test_types.h"

// WARN(Rafael): I have not found any official test vector for RIPEMD-128, excepting the first entry extracted from
//               the IETF Tools man page. Based on this, I generated the additional entries, not with my own implementation,
//               of course... :)

test_vector(ripemd128, hash) = {
    add_test_vector_data("Tcl does RIPEMD-128", 19,
                         "3CAB177BAE65205D81E7978F63556C63", 32,
                         "\x3C\xAB\x17\x7B\xAE\x65\x20\x5D\x81\xE7\x97\x8F\x63\x55\x6C\x63", 16), // From IETF Tools [tcllib]
    add_test_vector_data("a", 1,
                         "86BE7AFA339D0FC7CFC785E72F578D33", 32,
                         "\x86\xBE\x7A\xFA\x33\x9D\x0F\xC7\xCF\xC7\x85\xE7\x2F\x57\x8D\x33", 16),
    add_test_vector_data("abc", 3,
                         "C14A12199C66E4BA84636B0F69144C77", 32,
                         "\xC1\x4A\x12\x19\x9C\x66\xE4\xBA\x84\x63\x6B\x0F\x69\x14\x4C\x77", 16),
    add_test_vector_data("message digest", 14,
                         "9E327B3D6E523062AFC1132D7DF9D1B8", 32,
                         "\x9E\x32\x7B\x3D\x6E\x52\x30\x62\xAF\xC1\x13\x2D\x7D\xF9\xD1\xB8", 16),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "FD2AA607F71DC8F510714922B371834E", 32,
                         "\xFD\x2A\xA6\x07\xF7\x1D\xC8\xF5\x10\x71\x49\x22\xB3\x71\x83\x4E", 16),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "A1AA0689D0FAFA2DDC22E88B49133A06", 32,
                         "\xA1\xAA\x06\x89\xD0\xFA\xFA\x2D\xDC\x22\xE8\x8B\x49\x13\x3A\x06", 16)
};

#endif
