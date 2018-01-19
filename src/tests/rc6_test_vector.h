/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_RC6_TEST_VECTOR_H
#define KRYPTOS_TESTS_RC6_TEST_VECTOR_H 1

#include "test_types.h"

// INFO(Rafael): All the following data came from NESSIE's test vectors.

test_vector(rc6_128, block_cipher) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x1A\xD5\x78\xA0\x2A\x08\x16\x28\x50\xA1\x5A\x15\x52\xA1\x7A\xD4",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x91\x2E\x9C\xF1\x47\x30\x35\xA8\x44\x3A\x82\x49\x5C\x07\x30\xD3",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x3D\x3E\x85\x1A\x80\xAB\xAF\x22\x17\x61\x93\x17\x47\x47\x30\x48",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x96\xCF\xC0\x51\x08\x19\xEE\xB7\xFC\xDF\x2C\xC7\xBE\xAB\xEF\x77",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x1A\xF1\xE6\x34\xB0\x62\x11\x66\x8C\xE2\x41\x0D\x5E\xDC\xA9\x68",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x81\x57\x39\x51\x06\x22\xBF\xE0\x8E\xEE\x06\xB7\x72\x36\x85\x24",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xE2\xF7\xD8\x41\x11\x81\xA2\x1B\x02\xC1\x46\x6E\x75\x00\x56\xC2",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x13\x09\x57\x92\xD8\xB1\xD7\x71\x37\x88\x39\xC9\x12\xCA\x3C\x41",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00",
                         "\xD5\xC6\x38\x80\x1B\x97\xA1\xC2\x58\x4E\xD4\x21\x32\xF4\x41\x09",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00",
                         "\xE5\x4A\x02\x1B\x14\x5B\x7B\x77\x61\x48\x7B\xCD\xFD\x0B\x03\x2F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00",
                         "\x3E\xB3\xAF\xE7\x35\x82\xEF\xAB\x03\x96\x10\x8B\x5E\x0C\xDE\xEC",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00",
                         "\x46\x3E\x10\x50\x7A\x26\xB7\x08\xA1\xDF\xF3\x76\x32\x76\xF5\xC9",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20",
                         16,
                         "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20",
                         "\xFF\x2C\x70\xAB\x53\x0B\x88\x9B\xFF\x5F\x3C\x90\x2D\xE6\x20\x9A",
                         "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20",
                         16),
    add_test_vector_data("\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         16,
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         "\xDA\xEA\x51\x8A\x36\x4B\xC4\x04\xEE\xDD\x69\x03\x47\x4B\xB5\x6D",
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         16),
    add_test_vector_data("\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94",
                         16,
                         "\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94",
                         "\x1A\x56\x64\x81\x31\x21\x48\x2F\x4D\xBE\x10\x26\x10\x4D\x84\xA8",
                         "\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94",
                         16),
    add_test_vector_data("\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95",
                         16,
                         "\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95",
                         "\xAE\xE4\xA8\x2C\xE2\xFF\x23\xE9\x1A\x49\x72\x69\xB8\x25\x30\xF6",
                         "\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95\x95",
                         16),
    add_test_vector_data("\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97",
                         16,
                         "\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97",
                         "\xFB\x23\xB3\x19\x99\xD3\xD8\x4A\xFD\x55\x60\x0B\x9E\xA7\x22\xCD",
                         "\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97\x97",
                         16),
    add_test_vector_data("\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99",
                         16,
                         "\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99",
                         "\x65\xCC\xAA\x13\x21\xD8\xCB\x3C\xA1\x84\x62\xC3\x7D\xBB\xE4\xE1",
                         "\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99",
                         16),
    add_test_vector_data("\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         16,
                         "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         "\xBC\xCE\x55\xDC\xAF\xF6\xBB\x7B\x4D\x0C\xAF\xD1\x12\xE8\x7F\xCD",
                         "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\xEF\xB1\x09\x97\x84\x22\xE5\x0F\xDC\xB0\x53\x35\xD0\x50\xD0\xD7",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16),
    add_test_vector_data("\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         16,
                         "\x4B\x66\x5C\x01\xEC\xCB\x68\xB0\x7D\xA5\xC6\xA6\x2E\x61\xF3\x88",
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         "\x4B\x66\x5C\x01\xEC\xCB\x68\xB0\x7D\xA5\xC6\xA6\x2E\x61\xF3\x88",
                         16),
    add_test_vector_data("\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF",
                         16,
                         "\xFB\x2E\xAF\xB3\x7E\x25\x39\x28\x50\x9F\x6F\x7A\x4F\x6A\x89\xD1",
                         "\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF",
                         "\xFB\x2E\xAF\xB3\x7E\x25\x39\x28\x50\x9F\x6F\x7A\x4F\x6A\x89\xD1",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                         16,
                         "\xB8\x4E\x1F\x38\x06\x24\xFE\xD8\xC8\xC6\x40\xCB\x28\xB6\xD9\xED",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\xB8\x4E\x1F\x38\x06\x24\xFE\xD8\xC8\xC6\x40\xCB\x28\xB6\xD9\xED",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         16,
                         "\xDE\x60\xBD\x4F\x1C\x95\x53\x22\xD2\x52\xB7\x95\x77\x71\xB8\xB5",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\xDE\x60\xBD\x4F\x1C\x95\x53\x22\xD2\x52\xB7\x95\x77\x71\xB8\xB5",
                         16)
};

#endif

