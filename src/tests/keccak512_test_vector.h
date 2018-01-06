/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_KECCAK512_TEST_VECTOR_H
#define KRYPTOS_TESTS_KECCAK512_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(keccak512, hash) = {
    add_test_vector_data("abc", 3,
                         "18587DC2EA106B9A1563E32B3312421CA164C7F1F07BC922A9C83D77CEA3A1E5D0C6"
                         "9910739025372DC14AC9642629379540C17E2A65B19D77AA511A9D00BB96", 128,
                         "\x18\x58\x7D\xC2\xEA\x10\x6B\x9A\x15\x63\xE3\x2B\x33\x12\x42\x1C\xA1"
                         "\x64\xC7\xF1\xF0\x7B\xC9\x22\xA9\xC8\x3D\x77\xCE\xA3\xA1\xE5\xD0\xC6"
                         "\x99\x10\x73\x90\x25\x37\x2D\xC1\x4A\xC9\x64\x26\x29\x37\x95\x40\xC1"
                         "\x7E\x2A\x65\xB1\x9D\x77\xAA\x51\x1A\x9D\x00\xBB\x96", 64),
    add_test_vector_data("", 0,
                         "0EAB42DE4C3CEB9235FC91ACFFE746B29C29A8C366B7C60E4E67C466F36A4304C00F"
                         "A9CAF9D87976BA469BCBE06713B435F091EF2769FB160CDAB33D3670680E", 128,
                         "\x0E\xAB\x42\xDE\x4C\x3C\xEB\x92\x35\xFC\x91\xAC\xFF\xE7\x46\xB2\x9C"
                         "\x29\xA8\xC3\x66\xB7\xC6\x0E\x4E\x67\xC4\x66\xF3\x6A\x43\x04\xC0\x0F"
                         "\xA9\xCA\xF9\xD8\x79\x76\xBA\x46\x9B\xCB\xE0\x67\x13\xB4\x35\xF0\x91"
                         "\xEF\x27\x69\xFB\x16\x0C\xDA\xB3\x3D\x36\x70\x68\x0E", 64),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "6AA6D3669597DF6D5A007B00D09C20795B5C4218234E1698A944757A488ECDC09965"
                         "435D97CA32C3CFED7201FF30E070CD947F1FC12B9D9214C467D342BCBA5D", 128,
                         "\x6A\xA6\xD3\x66\x95\x97\xDF\x6D\x5A\x00\x7B\x00\xD0\x9C\x20\x79\x5B"
                         "\x5C\x42\x18\x23\x4E\x16\x98\xA9\x44\x75\x7A\x48\x8E\xCD\xC0\x99\x65"
                         "\x43\x5D\x97\xCA\x32\xC3\xCF\xED\x72\x01\xFF\x30\xE0\x70\xCD\x94\x7F"
                         "\x1F\xC1\x2B\x9D\x92\x14\xC4\x67\xD3\x42\xBC\xBA\x5D", 64),
    add_test_vector_data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                         "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
                         "AC2FB35251825D3AA48468A9948C0A91B8256F6D97D8FA4160FAFF2DD9DFCC24F3F1"
                         "DB7A983DAD13D53439CCAC0B37E24037E7B95F80F59F37A2F683C4BA4682", 128,
                         "\xAC\x2F\xB3\x52\x51\x82\x5D\x3A\xA4\x84\x68\xA9\x94\x8C\x0A\x91\xB8"
                         "\x25\x6F\x6D\x97\xD8\xFA\x41\x60\xFA\xFF\x2D\xD9\xDF\xCC\x24\xF3\xF1"
                         "\xDB\x7A\x98\x3D\xAD\x13\xD5\x34\x39\xCC\xAC\x0B\x37\xE2\x40\x37\xE7"
                         "\xB9\x5F\x80\xF5\x9F\x37\xA2\xF6\x83\xC4\xBA\x46\x82", 64)
};

#endif
