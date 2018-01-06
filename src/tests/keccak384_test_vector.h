/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_KECCAK384_TEST_VECTOR_H
#define KRYPTOS_TESTS_KECCAK384_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(keccak384, hash) = {
    add_test_vector_data("abc", 3,
                         "F7DF1165F033337BE098E7D288AD6A2F74409D7A60B49C36642218DE161B1F99"
                         "F8C681E4AFAF31A34DB29FB763E3C28E", 96,
                         "\xF7\xDF\x11\x65\xF0\x33\x33\x7B\xE0\x98\xE7\xD2\x88\xAD\x6A\x2F"
                         "\x74\x40\x9D\x7A\x60\xB4\x9C\x36\x64\x22\x18\xDE\x16\x1B\x1F\x99"
                         "\xF8\xC6\x81\xE4\xAF\xAF\x31\xA3\x4D\xB2\x9F\xB7\x63\xE3\xC2\x8E", 48),
    add_test_vector_data("", 0,
                         "2C23146A63A29ACF99E73B88F8C24EAA7DC60AA771780CCC006AFBFA8FE2479B"
                         "2DD2B21362337441AC12B515911957FF", 96,
                         "\x2C\x23\x14\x6A\x63\xA2\x9A\xCF\x99\xE7\x3B\x88\xF8\xC2\x4E\xAA"
                         "\x7D\xC6\x0A\xA7\x71\x78\x0C\xCC\x00\x6A\xFB\xFA\x8F\xE2\x47\x9B"
                         "\x2D\xD2\xB2\x13\x62\x33\x74\x41\xAC\x12\xB5\x15\x91\x19\x57\xFF", 48),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "B41E8896428F1BCBB51E17ABD6ACC98052A3502E0D5BF7FA1AF949B4D3C855E7"
                         "C4DC2C390326B3F3E74C7B1E2B9A3657", 96,
                         "\xB4\x1E\x88\x96\x42\x8F\x1B\xCB\xB5\x1E\x17\xAB\xD6\xAC\xC9\x80"
                         "\x52\xA3\x50\x2E\x0D\x5B\xF7\xFA\x1A\xF9\x49\xB4\xD3\xC8\x55\xE7"
                         "\xC4\xDC\x2C\x39\x03\x26\xB3\xF3\xE7\x4C\x7B\x1E\x2B\x9A\x36\x57", 48),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                         "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "CC063F34685135368B34F7449108F6D10FA727B09D696EC5331771DA46A923B6"
                         "C34DBD1D4F77E595689C1F3800681C28", 96,
                         "\xCC\x06\x3F\x34\x68\x51\x35\x36\x8B\x34\xF7\x44\x91\x08\xF6\xD1"
                         "\x0F\xA7\x27\xB0\x9D\x69\x6E\xC5\x33\x17\x71\xDA\x46\xA9\x23\xB6"
                         "\xC3\x4D\xBD\x1D\x4F\x77\xE5\x95\x68\x9C\x1F\x38\x00\x68\x1C\x28", 48)
};

#endif
