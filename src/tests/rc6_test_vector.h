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

// INFO(Rafael): All the following data came from NESSIE's test vectors. All these data assumes
//               the default rounds total suggested by the authors (20).

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

test_vector(rc6_192, block_cipher) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x83\x01\x73\x0C\x7D\x5F\xEF\xC4\x16\xBE\xEC\x11\x04\xC5\x1E\x36",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x23\x63\x97\xEB\x9E\xED\xA5\xEA\x8B\xF4\xA4\x28\x64\xA5\xA3\x9F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63"
                         "\x63\x63\x63\x63\x63\x63\x63\x63",
                         24,
                         "\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63",
                         "\x82\x2B\x7E\xDD\x01\x1C\x0D\x85\x35\x05\x0D\x9A\x42\xFA\x47\xC8",
                         "\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63\x63",
                         16),
    add_test_vector_data("\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A"
                         "\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A",
                         24,
                         "\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A",
                         "\xA1\x57\x40\xD0\x64\xC9\x89\x16\xA4\x39\xFF\x78\x41\x6F\x1F\xAD",
                         "\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A\x7A",
                         16),
    add_test_vector_data("\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
                         "\x90\x90\x90\x90\x90\x90\x90\x90",
                         24,
                         "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90",
                         "\xCD\x68\x9E\x38\x55\x6B\x4C\x53\x9E\xE4\x57\xFD\x63\x29\x84\x30",
                         "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90",
                         16),
    add_test_vector_data("\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93"
                         "\x93\x93\x93\x93\x93\x93\x93\x93",
                         24,
                         "\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93",
                         "\xB4\xDA\x15\xE1\xD7\x21\x1A\xE2\x8E\xBD\x66\x7C\x39\x9D\x62\x81",
                         "\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93\x93",
                         16),
    add_test_vector_data("\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE"
                         "\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE",
                         24,
                         "\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE",
                         "\xF3\x32\x5B\x5B\x39\xAD\x26\xCE\x85\xCF\xFE\xD5\x8D\x95\x60\x5B",
                         "\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE",
                         16),
    add_test_vector_data("\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF"
                         "\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF",
                         24,
                         "\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF",
                         "\x18\x5B\x3C\xBD\x17\xBF\x76\x0F\xB2\xFE\xF4\x28\x11\xD0\xA1\x52",
                         "\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF\xAF",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         24,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\xF3\x3D\x1E\x49\xC3\xD6\x26\x6C\x7F\x1C\x72\x38\xBB\xE7\xAB\x1F",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                         "\x10\x11\x12\x13\x14\x15\x16\x17",
                         24,
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x37\xE1\x3F\xB5\x35\x1B\xD7\x8D\x3E\x79\x12\xFD\xC5\xF8\x0F\xCD",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48"
                         "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00",
                         24,
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x50\xD2\x97\x45\x32\x96\x94\xB6\x5D\x6F\x54\xEE\x65\x45\x51\x80",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         16),
    add_test_vector_data("\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE"
                         "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE",
                         24,
                         "\x66\x5D\xF8\x51\x3D\xC8\x10\xD1\x77\x85\x6D\xFF\x0B\xE3\x74\xFB",
                         "\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE\xEE",
                         "\x66\x5D\xF8\x51\x3D\xC8\x10\xD1\x77\x85\x6D\xFF\x0B\xE3\x74\xFB",
                         16),
    add_test_vector_data("\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA"
                         "\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA",
                         24,
                         "\x3E\xFC\x13\x87\x5F\x50\x0D\x59\x92\x18\xD7\x71\x13\x71\x52\x86",
                         "\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA\xFA",
                         "\x3E\xFC\x13\x87\x5F\x50\x0D\x59\x92\x18\xD7\x71\x13\x71\x52\x86",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         24,
                         "\xF4\x35\x7B\x09\x13\xCC\x7F\xB8\xD4\x50\x97\xCD\x21\x36\xC7\x6E",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\xF4\x35\x7B\x09\x13\xCC\x7F\xB8\xD4\x50\x97\xCD\x21\x36\xC7\x6E",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                         "\x10\x11\x12\x13\x14\x15\x16\x17",
                         24,
                         "\x5A\x3B\xDC\xED\xAF\x03\xF5\xA2\xA9\x82\x3A\xAB\x33\x88\xD0\xB1",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x5A\x3B\xDC\xED\xAF\x03\xF5\xA2\xA9\x82\x3A\xAB\x33\x88\xD0\xB1",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48"
                         "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00",
                         24,
                         "\x80\xBE\x51\x09\xFB\xAE\x02\x9A\x43\x37\xE8\x2A\x13\xC6\xF8\x22",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x80\xBE\x51\x09\xFB\xAE\x02\x9A\x43\x37\xE8\x2A\x13\xC6\xF8\x22",
                         16)
};

test_vector(rc6_256, block_cipher) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x51\x72\x97\x8A\x58\x54\x3D\xE5\x97\x06\x09\x83\xFD\x79\x9F\x1B",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xBD\xD9\x39\xE7\xA9\x3F\x6F\xEC\xC7\x62\xE2\xE3\x32\x1D\xFE\xC7",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33"
                         "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33",
                         32,
                         "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33",
                         "\xAC\x2D\xE2\xAE\xCF\x63\x4D\x89\x80\xF1\xB8\xCE\x6C\x22\xDD\x25",
                         "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33",
                         16),
    add_test_vector_data("\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49"
                         "\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49",
                         32,
                         "\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49",
                         "\xBC\x76\x1F\x3B\xDA\x27\x47\x25\x13\x62\x48\x27\xE9\x38\x4E\x75",
                         "\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49\x49",
                         16),
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F"
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         32,
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\x44\x47\x3A\x65\xD5\x96\x10\xCB\x64\x83\x32\x1A\x10\xD4\x3C\xBE",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16),
    add_test_vector_data("\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
                         "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         32,
                         "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         "\x8B\x5F\x64\x48\xDC\x21\xB7\xA2\x55\x80\x6E\xE2\x16\xBA\x61\x0F",
                         "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         16),
    add_test_vector_data("\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E"
                         "\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E",
                         32,
                         "\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E",
                         "\x1C\x89\x4F\x59\xDE\xEA\x39\x3C\xC8\xF0\xB1\x0D\x07\x76\xC4\xD4",
                         "\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E\x9E",
                         16),
    add_test_vector_data("\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4"
                         "\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4",
                         32,
                         "\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4",
                         "\x7F\x31\x25\x33\xF3\x8F\xA2\xC4\xBF\x0D\x7C\x83\x91\x23\xE8\xB9",
                         "\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4\xA4",
                         16),
    add_test_vector_data("\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA"
                         "\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA",
                         32,
                         "\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA",
                         "\x1A\xDB\x99\x33\xFD\xBA\x27\xCF\x85\x9C\x82\xF7\xC0\x7D\xBA\x41",
                         "\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA\xCA",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x7F\xD8\x81\x03\x3E\x89\xD2\xF4\x51\x4D\x80\x17\x3D\x54\xED\x37",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                         "\x7F\xD8\x81\x03\x3E\x89\xD2\xF4\x51\x4D\x80\x17\x3D\x54\xED\x37",
                         16),
    add_test_vector_data("\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                         "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11",
                         32,
                         "\xB0\x98\x14\xB0\x9C\xC4\xBB\x68\x61\x53\x9B\x94\x90\xB8\x60\x12",
                         "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11",
                         "\xB0\x98\x14\xB0\x9C\xC4\xBB\x68\x61\x53\x9B\x94\x90\xB8\x60\x12",
                         16),
    add_test_vector_data("\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                         "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22",
                         32,
                         "\x27\x50\xC9\x13\x66\x5B\xD1\xBE\x65\xCD\xB3\xC6\x9A\x3B\xD0\x85",
                         "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22",
                         "\x27\x50\xC9\x13\x66\x5B\xD1\xBE\x65\xCD\xB3\xC6\x9A\x3B\xD0\x85",
                         16),
    add_test_vector_data("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
                         "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
                         32,
                         "\xB4\xCC\x1A\x59\x4C\xDD\x84\xD6\x78\x34\x17\x32\x8A\x8A\x0D\xDE",
                         "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
                         "\xB4\xCC\x1A\x59\x4C\xDD\x84\xD6\x78\x34\x17\x32\x8A\x8A\x0D\xDE",
                         16),
    add_test_vector_data("\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69"
                         "\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69",
                         32,
                         "\xD8\xE0\x05\x26\x4A\xD4\xA1\x4F\x45\x2E\x93\xCF\x54\xA4\x26\xBC",
                         "\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69\x69",
                         "\xD8\xE0\x05\x26\x4A\xD4\xA1\x4F\x45\x2E\x93\xCF\x54\xA4\x26\xBC",
                         16),
    add_test_vector_data("\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70"
                         "\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70",
                         32,
                         "\x17\x15\x15\x64\x12\x47\xB0\xF3\x6D\x8E\x3A\x9C\xD5\x4B\x32\x17",
                         "\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70",
                         "\x17\x15\x15\x64\x12\x47\xB0\xF3\x6D\x8E\x3A\x9C\xD5\x4B\x32\x17",
                         16),
    add_test_vector_data("\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78"
                         "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78",
                         32,
                         "\x62\x16\x8B\xCF\x96\x00\xDF\x6B\x08\x2F\xE6\x40\x12\xF3\x2C\xAA",
                         "\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78",
                         "\x62\x16\x8B\xCF\x96\x00\xDF\x6B\x08\x2F\xE6\x40\x12\xF3\x2C\xAA",
                         16),
    add_test_vector_data("\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82"
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         32,
                         "\xAE\x1B\x57\x6B\x3F\x8D\x7E\xB4\xE6\x4B\x78\x81\x89\x7D\xC2\x48",
                         "\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82",
                         "\xAE\x1B\x57\x6B\x3F\x8D\x7E\xB4\xE6\x4B\x78\x81\x89\x7D\xC2\x48",
                         16),
    add_test_vector_data("\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC"
                         "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         32,
                         "\xEA\x9D\x68\xFF\x5F\xA6\xED\xAB\x45\xE9\xC1\xA9\xD7\xEF\xE5\xD7",
                         "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC",
                         "\xEA\x9D\x68\xFF\x5F\xA6\xED\xAB\x45\xE9\xC1\xA9\xD7\xEF\xE5\xD7",
                         16),
    add_test_vector_data("\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
                         "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD",
                         32,
                         "\x72\xF9\x30\x63\x62\x03\xD0\x8B\xE5\x96\x3A\x84\x04\xBD\x6B\x48",
                         "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD",
                         "\x72\xF9\x30\x63\x62\x03\xD0\x8B\xE5\x96\x3A\x84\x04\xBD\x6B\x48",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         32,
                         "\xBC\x5A\x72\x32\x69\x83\x43\x9E\xC7\xFD\xAD\xE1\xFC\x77\x8C\x35",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\xBC\x5A\x72\x32\x69\x83\x43\x9E\xC7\xFD\xAD\xE1\xFC\x77\x8C\x35",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                         "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
                         32,
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\xE5\xC8\x2D\x38\x8E\xD5\x9B\x96\xEE\x87\xE3\xF4\x8A\x6E\x87\x9E",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48"
                         "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         32,
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\xA5\x65\xF4\xA3\xF2\xAE\xD0\x70\x8F\x38\x85\xBA\x9C\x21\x69\x46",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                         "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
                         32,
                         "\x95\x1C\x9C\xC4\x80\xFC\x2F\xB2\x81\x03\xA6\x5C\x15\xEA\x10\xEC",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x95\x1C\x9C\xC4\x80\xFC\x2F\xB2\x81\x03\xA6\x5C\x15\xEA\x10\xEC",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48"
                         "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         32,
                         "\xD9\x77\x28\x76\x15\x2C\x1D\xBE\x44\xEC\xA4\xA7\x4E\x16\xED\x43",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\xD9\x77\x28\x76\x15\x2C\x1D\xBE\x44\xEC\xA4\xA7\x4E\x16\xED\x43",
                         16)
};

#endif
