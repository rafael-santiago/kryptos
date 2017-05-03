/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA512_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA512_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha512, hash) = {
    add_test_vector_data("", 0,
                         "CF83E1357EEFB8BDF1542850D66D8007"
                         "D620E4050B5715DC83F4A921D36CE9CE"
                         "47D0D13C5D85F2B0FF8318D2877EEC2F"
                         "63B931BD47417A81A538327AF927DA3E", 128,
                         "\xCF\x83\xE1\x35\x7E\xEF\xB8\xBD\xF1\x54\x28\x50\xD6\x6D\x80\x07"
                         "\xD6\x20\xE4\x05\x0B\x57\x15\xDC\x83\xF4\xA9\x21\xD3\x6C\xE9\xCE"
                         "\x47\xD0\xD1\x3C\x5D\x85\xF2\xB0\xFF\x83\x18\xD2\x87\x7E\xEC\x2F"
                         "\x63\xB9\x31\xBD\x47\x41\x7A\x81\xA5\x38\x32\x7A\xF9\x27\xDA\x3E", 64),
    add_test_vector_data("a", 1,
                         "1F40FC92DA241694750979EE6CF582F2"
                         "D5D7D28E18335DE05ABC54D0560E0F53"
                         "02860C652BF08D560252AA5E74210546"
                         "F369FBBBCE8C12CFC7957B2652FE9A75", 128,
                         "\x1F\x40\xFC\x92\xDA\x24\x16\x94\x75\x09\x79\xEE\x6C\xF5\x82\xF2"
                         "\xD5\xD7\xD2\x8E\x18\x33\x5D\xE0\x5A\xBC\x54\xD0\x56\x0E\x0F\x53"
                         "\x02\x86\x0C\x65\x2B\xF0\x8D\x56\x02\x52\xAA\x5E\x74\x21\x05\x46"
                         "\xF3\x69\xFB\xBB\xCE\x8C\x12\xCF\xC7\x95\x7B\x26\x52\xFE\x9A\x75", 64),
    add_test_vector_data("abc", 3,
                         "DDAF35A193617ABACC417349AE204131"
                         "12E6FA4E89A97EA20A9EEEE64B55D39A"
                         "2192992A274FC1A836BA3C23A3FEEBBD"
                         "454D4423643CE80E2A9AC94FA54CA49F", 128,
                         "\xDD\xAF\x35\xA1\x93\x61\x7A\xBA\xCC\x41\x73\x49\xAE\x20\x41\x31"
                         "\x12\xE6\xFA\x4E\x89\xA9\x7E\xA2\x0A\x9E\xEE\xE6\x4B\x55\xD3\x9A"
                         "\x21\x92\x99\x2A\x27\x4F\xC1\xA8\x36\xBA\x3C\x23\xA3\xFE\xEB\xBD"
                         "\x45\x4D\x44\x23\x64\x3C\xE8\x0E\x2A\x9A\xC9\x4F\xA5\x4C\xA4\x9F", 64),
    add_test_vector_data("message digest", 14,
                         "107DBF389D9E9F71A3A95F6C055B9251"
                         "BC5268C2BE16D6C13492EA45B0199F33"
                         "09E16455AB1E96118E8A905D5597B720"
                         "38DDB372A89826046DE66687BB420E7C", 128,
                         "\x10\x7D\xBF\x38\x9D\x9E\x9F\x71\xA3\xA9\x5F\x6C\x05\x5B\x92\x51"
                         "\xBC\x52\x68\xC2\xBE\x16\xD6\xC1\x34\x92\xEA\x45\xB0\x19\x9F\x33"
                         "\x09\xE1\x64\x55\xAB\x1E\x96\x11\x8E\x8A\x90\x5D\x55\x97\xB7\x20"
                         "\x38\xDD\xB3\x72\xA8\x98\x26\x04\x6D\xE6\x66\x87\xBB\x42\x0E\x7C", 64),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "4DBFF86CC2CA1BAE1E16468A05CB9881"
                         "C97F1753BCE3619034898FAA1AABE429"
                         "955A1BF8EC483D7421FE3C1646613A59"
                         "ED5441FB0F321389F77F48A879C7B1F1", 128,
                         "\x4D\xBF\xF8\x6C\xC2\xCA\x1B\xAE\x1E\x16\x46\x8A\x05\xCB\x98\x81"
                         "\xC9\x7F\x17\x53\xBC\xE3\x61\x90\x34\x89\x8F\xAA\x1A\xAB\xE4\x29"
                         "\x95\x5A\x1B\xF8\xEC\x48\x3D\x74\x21\xFE\x3C\x16\x46\x61\x3A\x59"
                         "\xED\x54\x41\xFB\x0F\x32\x13\x89\xF7\x7F\x48\xA8\x79\xC7\xB1\xF1", 64),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "204A8FC6DDA82F0A0CED7BEB8E08A416"
                         "57C16EF468B228A8279BE331A703C335"
                         "96FD15C13B1B07F9AA1D3BEA57789CA0"
                         "31AD85C7A71DD70354EC631238CA3445", 128,
                         "\x20\x4A\x8F\xC6\xDD\xA8\x2F\x0A\x0C\xED\x7B\xEB\x8E\x08\xA4\x16"
                         "\x57\xC1\x6E\xF4\x68\xB2\x28\xA8\x27\x9B\xE3\x31\xA7\x03\xC3\x35"
                         "\x96\xFD\x15\xC1\x3B\x1B\x07\xF9\xAA\x1D\x3B\xEA\x57\x78\x9C\xA0"
                         "\x31\xAD\x85\xC7\xA7\x1D\xD7\x03\x54\xEC\x63\x12\x38\xCA\x34\x45", 64)
};

#endif
