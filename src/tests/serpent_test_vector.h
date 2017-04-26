/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SERPENT_TEST_VECTOR_H
#define KRYPTOS_TESTS_SERPENT_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(serpent) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x26\x4E\x54\x81\xEF\xF4\x2A\x46\x06\xAB\xDA\x06\xC0\xBF\xDA\x3D",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16)
};

#endif
