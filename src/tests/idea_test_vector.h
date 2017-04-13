/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_IDEA_TEST_VECTOR_H
#define KRYPTOS_TESTS_IDEA_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(idea) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xB1\xF5\xF7\xF8\x79\x01\x37\x0F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         8)
};

#endif // KRYPTOS_TESTS_IDEA_TEST_VECTOR_H
