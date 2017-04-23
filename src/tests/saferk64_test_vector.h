/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SAFERK64_TEST_VECTOR_H
#define KRYPTOS_TESTS_SAFERK64_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(saferk64) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x01\x02\x03\x04\x05\x06\x07\x08",
                         "\x7D\x28\x03\x86\x33\xB9\x2E\xB4",
                         "\x01\x02\x03\x04\x05\x06\x07\x08",
                         8),
    add_test_vector_data("\x01\x02\x03\x04\x05\x06\x07\x08",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x5A\xB2\x7F\x72\x14\xA3\x3A\xE1",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8),
    add_test_vector_data("\x08\x07\x06\x05\x04\x03\x02\x01",
                         8,
                         "\x01\x02\x03\x04\x05\x06\x07\x08",
                         "\xC8\xF2\x9C\xDD\x87\x78\x3E\xD9",
                         "\x01\x02\x03\x04\x05\x06\x07\x08",
                         8),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00",
                         8,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x03\x28\x08\xC9\x0E\xE7\xAB\x7F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8)

};

#endif
