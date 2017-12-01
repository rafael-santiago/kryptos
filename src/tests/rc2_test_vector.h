/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_RC2_TEST_VECTOR_H
#define KRYPTOS_TESTS_RC2_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(rc2, block_cipher) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xEB\xB7\x73\xF9\x93\x27\x8E\xFF",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=63.
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x27\x8B\x27\xE4\x2E\x2F\x0D\x49",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x30\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x10\x00\x00\x00\x00\x00\x00\x01",
                         "\x30\x64\x9E\xDF\x9B\xE7\xD2\xC2",
                         "\x10\x00\x00\x00\x00\x00\x00\x01",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x88",
                         1,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x61\xA8\xA2\x44\xAD\xAC\xCC\xF0",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x88\xBC\xA9\x0E\x90\x87\x5A",
                         7,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x6C\xCF\x43\x08\x97\x4C\x26\x7F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x88\xBC\xA9\x0E\x90\x87\x5A\x7F\x0F\x79\xC3\x84\x62\x7B\xAF\xB2",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x1A\x80\x7D\x27\x2B\xBE\x5D\xB1",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x88\xBC\xA9\x0E\x90\x87\x5A\x7F\x0F\x79\xC3\x84\x62\x7B\xAF\xB2",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x22\x69\x55\x2A\xB0\xF8\x5C\xA6",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x88\xBC\xA9\x0E\x90\x87\x5A\x7F\x0F\x79\xC3\x84\x62\x7B\xAF\xB2"
                         "\x16\xF8\x0A\x6F\x85\x92\x05\x84\xC4\x2F\xCE\xB0\xBE\x25\x5D\xAF"
                         "\x1E",
                         33,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x5B\x78\xD3\xA4\x3D\xFF\xF1\xF1",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=129.
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x4E\x0C\xB9\x3D\x71\xC2\x58\x3E",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x92\xF8\x21\x09\x8A\xB9\x05\xFB",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x5B\xA3\x7C\x7D\x87\x73\xB9\x55",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x76\x08\x2F\x0A\x05\x98\xC7\xBF",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xC3\xF5\x91\xB4\xC7\xAD\x16\x3B",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x61\x0D\x02\xC6\xD6\xD8\xFD\x2E",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xE8\x5E\x65\x40\x09\x00\x3A\x33",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xB8\xD5\xBD\x80\x57\xDB\x16\x34",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x60\x60\x60\x60\x60\x60\x60\x60\x60\x60\x60\x60\x60\x60\x60\x60",
                         16,
                         "\x60\x60\x60\x60\x60\x60\x60\x60",
                         "\xCA\x0E\xCF\x6A\x92\x08\xD7\xE2",
                         "\x60\x60\x60\x60\x60\x60\x60\x60",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16,
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\x7A\x1F\xB2\x58\x9B\x24\xB2\x27",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         16,
                         "\x82\x82\x82\x82\x82\x82\x82\x82",
                         "\xBA\x99\x37\x23\x54\xCE\x02\xFD",
                         "\x82\x82\x82\x82\x82\x82\x82\x82",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94",
                         16,
                         "\x94\x94\x94\x94\x94\x94\x94\x94",
                         "\x96\x39\xF3\x37\xAC\xD7\xB0\x95",
                         "\x94\x94\x94\x94\x94\x94\x94\x94",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99",
                         16,
                         "\x99\x99\x99\x99\x99\x99\x99\x99",
                         "\xBF\x17\x4C\x7F\xF8\xF2\xA9\x08",
                         "\x99\x99\x99\x99\x99\x99\x99\x99",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         16,
                         "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         "\x79\x49\x8E\xB8\x93\x36\x64\x38",
                         "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\xB0\xC2\x1A\x0D\xBE\x0A\x2A\xA6",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                         16,
                         "\x00\x11\x22\x33\x44\x55\x66\x77",
                         "\x5A\xB3\x33\x7C\x2C\x72\xB6\x9F",
                         "\x00\x11\x22\x33\x44\x55\x66\x77",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         16,
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x1D\xC0\x95\x5C\x2C\xCA\x54\x1D",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x50\xDC\x01\x62\xBD\x75\x7F\x31",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=1024.
    /*add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("",
                         16,
                         "",
                         "",
                         "",
                         8)*/
};

#endif
