/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_NOEKEON_TEST_VECTOR_H
#define KRYPTOS_TESTS_NOEKEON_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(noekeon, block_cipher) = {
    // INFO(Rafael): Test vector from specification.
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xBA\x69\x33\x81\x92\x99\xC7\x16\x99\xA9\x9F\x08\xF6\x78\x17\x8B",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x52\xF8\x8A\x7B\x28\x3C\x1F\x7B\xDF\x7B\x6F\xAA\x50\x11\xC7\xD8",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16),
    add_test_vector_data("\xBA\x69\x33\x81\x92\x99\xC7\x16\x99\xA9\x9F\x08\xF6\x78\x17\x8B",
                         16,
                         "\x52\xF8\x8A\x7B\x28\x3C\x1F\x7B\xDF\x7B\x6F\xAA\x50\x11\xC7\xD8",
                         "\x50\x96\xF2\xBF\xC8\x2A\xE6\xE2\xD9\x49\x55\x15\xC2\x77\xFA\x70",
                         "\x52\xF8\x8A\x7B\x28\x3C\x1F\x7B\xDF\x7B\x6F\xAA\x50\x11\xC7\xD8",
                         16),
    // INFO(Rafael): Test vector from NESSIE.
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x98\xFE\x35\x9A\x01\xCD\x3F\x66\xF8\xD6\x62\xB7\x46\xF8\x25\xD7",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x35\xD8\x3B\x46\x67\x60\xB3\x53\x86\xA6\x3F\x2A\xC2\xC5\x94\x64",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xF0\xC1\xEB\x47\x4D\xB0\x0D\xAE\x36\x32\x47\x5D\x90\xEA\xBD\xC1",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x76\x5D\x3C\x81\x20\x7B\x59\x61\xBB\xE3\xC0\x15\x60\xE2\x9F\x9F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x43\xD0\x04\xD2\x2E\xA6\xE3\xB7\x0C\xE6\x65\x96\x2F\x04\x53\xC5",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xED\x28\x67\x22\xCB\x75\x83\xD7\xBD\xDB\x07\xD2\x2E\xD9\x04\xEC",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x6F\x10\x70\x2E\xDB\x9E\x67\x47\x07\x5D\xF8\xF1\x77\x31\xDC\x76",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x24\x52\x66\xAA\x68\xAA\x8A\xA2\xF3\x00\x9F\xB0\x29\x51\xF6\xB3",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x1A\xEF\x09\x05\x1E\xD5\x91\x4A\x95\xD4\x65\xA1\xFC\xDE\x72\x1E",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x13\xDF\xBD\xA3\x9D\x7C\xDD\x3F\x6D\xC4\x94\xC5\xFB\x9E\xB9\xAF",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xF3\x16\x32\x34\x0F\x3B\x34\xE6\x4D\xC7\x05\x85\x64\x50\x5B\xA8",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xD3\xE8\x46\xC3\x34\x00\xF9\x91\xFF\xD8\x51\x5C\x08\x95\x6D\x19",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xA8\xCA\xED\x79\x9A\xBF\xEB\x05\xCB\xC8\xD7\x65\x19\xAA\x29\x64",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xB9\x2F\x29\xA6\x9E\xCA\x0C\x84\x01\xA1\xCC\xF7\x17\x51\x64\x79",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x23\xFE\xD4\xEB\xCB\x07\xEE\x01\x05\x39\xEC\x43\x42\x51\xBA\xDF",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x2A\x15\x5D\x2E\x4E\xE4\x4A\x50\xA5\x52\xC6\x7E\x8A\xFF\x77\x05",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x28\xE0\xCD\xFF\x52\xFE\xB8\x1D\x99\x1E\x45\x2C\x97\x00\x13\xA4",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xB3\x19\x69\xF6\xE6\x79\x39\xED\x05\x07\x3B\xD3\x0E\x98\xE3\xAD",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x76\xAD\x68\xF9\xB1\x5D\xA2\x52\x23\x49\x1A\x9D\x84\x9A\x2F\x3F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x0A\xC6\x9A\x6B\x92\x65\x10\xD3\xB4\x26\x41\x8A\x27\x16\x28\x93",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xBD\xF1\xF7\xE6\x0E\xB7\x0D\x11\x0E\x62\x59\xED\xAA\x88\x58\xEA",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x6C\xC3\xA4\x14\x5E\x91\x60\xAB\x9E\xF8\x5B\xF3\xA5\xE9\xCD\xD6",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xB0\xDD\x3E\xA9\x04\xBA\xDD\x0D\x85\x3D\xC9\x73\x20\xE5\x26\x0B",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xBB\x19\x8C\x4B\x0D\xFE\x29\x0C\xE7\xCC\x3C\x10\x8D\x0F\x00\x07",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                         16,
                         "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                         "\x47\x1F\x49\x80\xB2\xAB\xAF\x5A\x0A\x48\x26\xC6\xBD\xEA\x10\xBE",
                         "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                         16),
    add_test_vector_data("\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08",
                         16,
                         "\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08",
                         "\xA5\x51\xEA\x4D\x8C\x18\x7B\xE3\x92\x3E\xA4\x24\x47\xDA\x38\x3E",
                         "\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08",
                         16),
    add_test_vector_data("\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A",
                         16,
                         "\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A",
                         "\xD0\xC6\x2D\x6E\x46\xB2\x8D\x35\x75\x06\x7E\xBD\xBC\x11\x19\xE1",
                         "\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A\x1A",
                         16),
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16,
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\x9F\x8E\x2A\xF0\x2C\x9A\x75\xBE\x28\x3C\xA4\xAF\xBB\x88\xEF\xE5",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16),
    add_test_vector_data("\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         16,
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         "\x27\x28\x77\x0A\xC5\xAB\xA3\xD3\xFC\x9F\x4A\xF6\xB7\xA8\xDB\x93",
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         16),
    add_test_vector_data("\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         16,
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         "\x27\x28\x77\x0A\xC5\xAB\xA3\xD3\xFC\x9F\x4A\xF6\xB7\xA8\xDB\x93",
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         16),
    add_test_vector_data("\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE",
                         16,
                         "\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE",
                         "\xB1\x15\x4E\x07\xCF\xF4\x10\x4A\x21\x6C\x44\x72\x9F\xCA\x38\x2D",
                         "\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE\xBE",
                         16),
    add_test_vector_data("\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         16,
                         "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         "\xCB\x58\xB2\x73\xBF\xEA\xAF\x45\x33\x68\x49\x1F\x08\xF8\xE8\x40",
                         "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         16),
    add_test_vector_data("\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD",
                         16,
                         "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD",
                         "\xCF\x7B\xC4\x4C\xE6\xEE\x9D\x78\x3F\xD0\x6B\xA1\xF1\xA3\xFC\xE8",
                         "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD",
                         16)
};

test_vector(noekeon_d, block_cipher) = {
    // INFO(Rafael): Test vector from specification.
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xB1\x65\x68\x51\x69\x9E\x29\xFA\x24\xB7\x01\x48\x50\x3D\x2D\xFC",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x2A\x78\x42\x1B\x87\xC7\xD0\x92\x4F\x26\x11\x3F\x1D\x13\x49\xB2",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16),
    add_test_vector_data("\xB1\x65\x68\x51\x69\x9E\x29\xFA\x24\xB7\x01\x48\x50\x3D\x2D\xFC",
                         16,
                         "\x2A\x78\x42\x1B\x87\xC7\xD0\x92\x4F\x26\x11\x3F\x1D\x13\x49\xB2",
                         "\xE2\xF6\x87\xE0\x7B\x75\x66\x0F\xFC\x37\x22\x33\xBC\x47\x53\x2C",
                         "\x2A\x78\x42\x1B\x87\xC7\xD0\x92\x4F\x26\x11\x3F\x1D\x13\x49\xB2",
                         16),
    // INFO(Rafael): Test vector from NESSIE.
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xEA\x65\x52\xBA\x79\x35\x46\xC2\x61\xE4\xB3\xE9\x04\x33\xF5\xA2",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xF2\x3A\x85\xB6\x4F\x36\xA5\x90\x8F\xE2\x3B\xC6\x20\x6B\xFF\x01",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xF0\xCD\xC9\x02\x55\x70\x05\xA5\xEF\x0E\x22\xA8\xD6\x83\x57\x9F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xAF\xAC\xC4\x62\x83\x8B\x10\xF7\x2B\x52\x02\xB4\xFE\xDC\xE0\x63",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x24\xF8\x78\xC4\x18\x3E\x64\xB6\x44\x1D\x8A\x45\xAA\xAE\x91\xB7",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xBB\x01\x72\x66\x79\x93\x62\xFF\xC8\xA6\x1E\x81\x76\xE8\x5D\xD2",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x3C\xFB\xEF\x3A\x60\x7D\xCF\x5F\x85\x01\x0A\xDB\x89\x71\x59\x27",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x13\x89\x19\xFB\x34\x43\xDC\x23\xF7\xCF\xDE\xFE\x48\x31\x42\xE1",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16",
                         16,
                         "\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16",
                         "\xDF\xC3\x66\x3C\xC2\xE9\xD2\xE1\xBF\xE9\xC7\x16\x26\x07\x05\xA8",
                         "\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16\x16",
                         16),
    add_test_vector_data("\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C",
                         16,
                         "\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C",
                         "\x3F\x57\x9D\x7C\x34\x5F\x26\xA2\xF9\x1E\xE4\x06\x89\x9B\x60\x52",
                         "\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C\x2C",
                         16),
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16,
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\xF8\x1A\xDF\x27\x5C\xC8\xD2\x4D\xCD\x89\xDF\x6F\x04\x4B\x19\xF1",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16),
    add_test_vector_data("\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99",
                         16,
                         "\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99",
                         "\x00\xB1\x2A\xDE\x86\xDB\x4D\x34\x7C\xB6\x63\x68\xE3\xFB\xAC\xCF",
                         "\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99",
                         16),
    add_test_vector_data("\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD",
                         16,
                         "\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD",
                         "\xDD\x75\xA2\x9E\x88\xE9\xF4\xC3\xFC\xFB\x9F\x16\x50\xDA\xDF\x75",
                         "\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD\xFD",
                         16)
};

#endif
