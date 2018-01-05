/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA3_512_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA3_512_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha3_512, hash) = {
    add_test_vector_data("abc", 3,
                         "B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E1"
                         "16E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0", 128,
                         "\xB7\x51\x85\x0B\x1A\x57\x16\x8A\x56\x93\xCD\x92\x4B\x6B\x09\x6E\x08"
                         "\xF6\x21\x82\x74\x44\xF7\x0D\x88\x4F\x5D\x02\x40\xD2\x71\x2E\x10\xE1"
                         "\x16\xE9\x19\x2A\xF3\xC9\x1A\x7E\xC5\x76\x47\xE3\x93\x40\x57\x34\x0B"
                         "\x4C\xF4\x08\xD5\xA5\x65\x92\xF8\x27\x4E\xEC\x53\xF0", 64),
    add_test_vector_data("", 0,
                         "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2"
                         "123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26", 128,
                         "\xA6\x9F\x73\xCC\xA2\x3A\x9A\xC5\xC8\xB5\x67\xDC\x18\x5A\x75\x6E\x97"
                         "\xC9\x82\x16\x4F\xE2\x58\x59\xE0\xD1\xDC\xC1\x47\x5C\x80\xA6\x15\xB2"
                         "\x12\x3A\xF1\xF5\xF9\x4C\x11\xE3\xE9\x40\x2C\x3A\xC5\x58\xF5\x00\x19"
                         "\x9D\x95\xB6\xD3\xE3\x01\x75\x85\x86\x28\x1D\xCD\x26", 64),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "04A371E84ECFB5B8B77CB48610FCA8182DD457CE6F326A0FD3D7EC2F1E91636DEE69"
                         "1FBE0C985302BA1B0D8DC78C086346B533B49C030D99A27DAF1139D6E75E", 128,
                         "\x04\xA3\x71\xE8\x4E\xCF\xB5\xB8\xB7\x7C\xB4\x86\x10\xFC\xA8\x18\x2D"
                         "\xD4\x57\xCE\x6F\x32\x6A\x0F\xD3\xD7\xEC\x2F\x1E\x91\x63\x6D\xEE\x69"
                         "\x1F\xBE\x0C\x98\x53\x02\xBA\x1B\x0D\x8D\xC7\x8C\x08\x63\x46\xB5\x33"
                         "\xB4\x9C\x03\x0D\x99\xA2\x7D\xAF\x11\x39\xD6\xE7\x5E", 64),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                         "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "AFEBB2EF542E6579C50CAD06D2E578F9F8DD6881D7DC824D26360FEEBF18A4FA73E3"
                         "261122948EFCFD492E74E82E2189ED0FB440D187F382270CB455F21DD185", 128,
                         "\xAF\xEB\xB2\xEF\x54\x2E\x65\x79\xC5\x0C\xAD\x06\xD2\xE5\x78\xF9\xF8"
                         "\xDD\x68\x81\xD7\xDC\x82\x4D\x26\x36\x0F\xEE\xBF\x18\xA4\xFA\x73\xE3"
                         "\x26\x11\x22\x94\x8E\xFC\xFD\x49\x2E\x74\xE8\x2E\x21\x89\xED\x0F\xB4"
                         "\x40\xD1\x87\xF3\x82\x27\x0C\xB4\x55\xF2\x1D\xD1\x85", 64)
};

#endif
