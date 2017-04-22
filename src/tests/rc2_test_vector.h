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

// INFO(Rafael): Well, the endian convention on RC2 Spec is a little "bit" confuse.

test_vector(rc2) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xB7\xEB\xF9\x73\x27\x93\xFF\x8E",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=63.
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x8B\x27\xE4\x27\x2F\x2E\x49\x0D",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x30\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x10\x00\x00\x00\x00\x01\x00",
                         "\x64\x30\xDF\x9E\xE7\x9B\xC2\xD2",
                         "\x00\x10\x00\x00\x00\x00\x01\x00",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x88",
                         1,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xA8\x61\x44\xA2\xAC\xAD\xF0\xCC",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x88\xBC\xA9\x0E\x90\x87\x5A",
                         7,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xCF\x6C\x08\x43\x4C\x97\x7F\x26",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x88\xBC\xA9\x0E\x90\x87\x5A\x7F\x0F\x79\xC3\x84\x62\x7B\xAF\xB2",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x80\x1A\x27\x7D\xBE\x2B\xB1\x5D",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=64.
    add_test_vector_data("\x88\xBC\xA9\x0E\x90\x87\x5A\x7F\x0F\x79\xC3\x84\x62\x7B\xAF\xB2",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x69\x22\x2A\x55\xF8\xB0\xA6\x5C",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8), // INFO(Rafael): Assuming T1=128.
    add_test_vector_data("\x88\xBC\xA9\x0E\x90\x87\x5A\x7F\x0F\x79\xC3\x84\x62\x7B\xAF\xB2"
                         "\x16\xF8\x0A\x6F\x85\x92\x05\x84\xC4\x2F\xCE\xB0\xBE\x25\x5D\xAF"
                         "\x1E",
                         33,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x78\x5B\xA4\xD3\xFF\x3D\xF1\xF1",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8) // INFO(Rafael): Assuming T1=129.
};

#endif
