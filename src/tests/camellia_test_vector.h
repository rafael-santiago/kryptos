/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_CAMELLIA_TEST_VECTOR_H
#define KRYPTOS_TESTS_CAMELLIA_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(camellia128, block_cipher) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x6C\x22\x7F\x74\x93\x19\xA3\xAA\x7D\xA2\x35\xA9\xBB\xA0\x5A\x2C",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xF0\x4D\x51\xE4\x5E\x70\xFB\x6D\xEE\x0D\x16\xA2\x04\xFB\xBA\x16",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xED\x44\x24\x2E\x61\x9F\x8C\x32\xEA\xA2\xD3\x64\x1D\xA4\x7E\xA4",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xAC\x64\x0B\xBB\xF8\x4C\xD3\xB8\xE8\x25\x8B\xF6\x6C\x21\x0A\xE2",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D",
                         16,
                         "\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D",
                         "\xA1\x4F\x57\xCE\x4D\x9E\xA4\xC5\xE2\x82\x10\x8D\xF8\xFD\xE0\x0E",
                         "\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D",
                         16),
    add_test_vector_data("\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08",
                         16,
                         "\x31\x11\x78\xBE\xBB\xD7\x8F\x28\x0D\x93\xB5\x71\x85\xF4\x00\xBB",
                         "\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08",
                         "\x31\x11\x78\xBE\xBB\xD7\x8F\x28\x0D\x93\xB5\x71\x85\xF4\x00\xBB",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                         16,
                         "\x41\x0E\x33\xF3\x16\xDF\x4A\x72\xAA\x2B\xCD\x41\x14\xE2\x31\x4D",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x41\x0E\x33\xF3\x16\xDF\x4A\x72\xAA\x2B\xCD\x41\x14\xE2\x31\x4D",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         16,
                         "\x78\x35\x78\x66\xFD\x8B\x2C\xAE\xD4\xD1\xBB\xA3\xCF\xD5\x34\x0A",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x78\x35\x78\x66\xFD\x8B\x2C\xAE\xD4\xD1\xBB\xA3\xCF\xD5\x34\x0A",
                         16)
};

test_vector(camellia192, block_cipher) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x1B\x62\x20\xD3\x65\xC2\x17\x6C\x1D\x41\xA5\x82\x65\x20\xFC\xA1",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x0F\x6D\xAE\xEA\x95\xCF\xC8\x92\x5F\x23\xAF\xA9\x32\xDF\x48\x9B",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x73\x30\x19\x92\x25\xAD\x38\x4F\x8D\xD3\x95\x82\xD6\x13\x89\xBB",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x2C\xC5\xA4\x7D\x5C\x62\xF7\x06\x34\xE2\x7B\xA3\x32\xD3\x7D\x53",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xD8\xF1\x49\xC2\x07\xFA\xD4\x48\x0B\xA2\xFC\x60\x9B\xEB\x44\x71",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57",
                         24,
                         "\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57",
                         "\x15\x44\x57\xA7\x32\xBC\x11\xF0\xA4\xC4\x3B\xEC\x60\x7B\x9B\x91",
                         "\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57\x57",
                         16),
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         24,
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\xFE\x94\xD7\x33\xBA\xBE\xB5\xA5\x38\x2C\x28\x16\x31\x1E\x51\x5E",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17",
                         24,
                         "\x94\x1A\xC6\x45\x3C\x3F\x48\xA1\x69\xC2\xF4\xFE\x2B\xBE\x55\x32",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x94\x1A\xC6\x45\x3C\x3F\x48\xA1\x69\xC2\xF4\xFE\x2B\xBE\x55\x32",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48\x2B\xD6\x45\x9F\x82\xC5\xB3\x00",
                         24,
                         "\x29\x2C\x5B\xBF\xD7\x72\xAD\x27\x95\x09\x12\x0F\x3F\x0A\xCD\x48",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x29\x2C\x5B\xBF\xD7\x72\xAD\x27\x95\x09\x12\x0F\x3F\x0A\xCD\x48",
                         16)
};

test_vector(camellia256, block_cipher) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x21\x36\xFA\xBD\xA0\x91\xDF\xB5\x17\x1B\x94\xB8\xEF\xBB\x5D\x08",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x6E\xBC\x4F\x33\xB3\xEA\xDA\x5D\xBF\x25\x13\x0F\x3D\x02\xCD\x34",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x14\x76\x94\xE2\x23\x1F\xA0\x0D\x6B\x62\xD3\xE5\x1C\xC8\x20\x1D",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44"
                         "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44",
                         32,
                         "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44",
                         "\xCD\x98\x46\xE1\xB1\x20\x48\x2E\x6B\x6D\x71\xC4\xF5\xD7\x04\xFE",
                         "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44",
                         16),
   add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                        "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         32,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x4F\x05\xF2\x8C\xA2\x3E\xEA\xE2\x05\xB6\x7B\x1C\x95\xCD\x52\x80",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16),
   add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
                         32,
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x2E\xDF\x1F\x34\x18\xD5\x3B\x88\x84\x1F\xC8\x98\x5F\xB1\xEC\xF2",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48"
                         "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         32,
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x6D\x42\xE6\x7B\xCE\x92\x94\x32\x70\x18\x31\x7A\x7F\x83\x82\x13",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                         "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
                         32,
                         "\x06\x36\x9B\x36\x08\xAE\x43\xCA\x79\xC8\x8B\xCF\x49\x7F\x67\x71",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x06\x36\x9B\x36\x08\xAE\x43\xCA\x79\xC8\x8B\xCF\x49\x7F\x67\x71",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48"
                         "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         32,
                         "\xE6\x84\x42\x17\x16\xFC\x0B\x01\xAE\xB5\xC6\x76\x51\x20\xF9\x5F",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\xE6\x84\x42\x17\x16\xFC\x0B\x01\xAE\xB5\xC6\x76\x51\x20\xF9\x5F",
                         16)
};

#endif
