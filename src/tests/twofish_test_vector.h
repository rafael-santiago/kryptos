/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_TWOFISH_TEST_VECTOR_H
#define KRYPTOS_TESTS_TWOFISH_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(twofish128, block_cipher) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x9F\x58\x9F\x5C\xF6\x12\x2C\x32\xB6\xBF\xEC\x2F\x2A\xE8\xC3\x5A",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x9F\x58\x9F\x5C\xF6\x12\x2C\x32\xB6\xBF\xEC\x2F\x2A\xE8\xC3\x5A",
                         "\xD4\x91\xDB\x16\xE7\xB1\xC3\x9E\x86\xCB\x08\x6B\x78\x9F\x54\x19",
                         "\x9F\x58\x9F\x5C\xF6\x12\x2C\x32\xB6\xBF\xEC\x2F\x2A\xE8\xC3\x5A",
                         16),
    add_test_vector_data("\x9F\x58\x9F\x5C\xF6\x12\x2C\x32\xB6\xBF\xEC\x2F\x2A\xE8\xC3\x5A",
                         16,
                         "\xD4\x91\xDB\x16\xE7\xB1\xC3\x9E\x86\xCB\x08\x6B\x78\x9F\x54\x19",
                         "\x01\x9F\x98\x09\xDE\x17\x11\x85\x8F\xAA\xC3\xA3\xBA\x20\xFB\xC3",
                         "\xD4\x91\xDB\x16\xE7\xB1\xC3\x9E\x86\xCB\x08\x6B\x78\x9F\x54\x19",
                         16),
    add_test_vector_data("\xD4\x91\xDB\x16\xE7\xB1\xC3\x9E\x86\xCB\x08\x6B\x78\x9F\x54\x19",
                         16,
                         "\x01\x9F\x98\x09\xDE\x17\x11\x85\x8F\xAA\xC3\xA3\xBA\x20\xFB\xC3",
                         "\x63\x63\x97\x7D\xE8\x39\x48\x62\x97\xE6\x61\xC6\xC9\xD6\x68\xEB",
                         "\x01\x9F\x98\x09\xDE\x17\x11\x85\x8F\xAA\xC3\xA3\xBA\x20\xFB\xC3",
                         16),
    add_test_vector_data("\x01\x9F\x98\x09\xDE\x17\x11\x85\x8F\xAA\xC3\xA3\xBA\x20\xFB\xC3",
                         16,
                         "\x63\x63\x97\x7D\xE8\x39\x48\x62\x97\xE6\x61\xC6\xC9\xD6\x68\xEB",
                         "\x81\x6D\x5B\xD0\xFA\xE3\x53\x42\xBF\x2A\x74\x12\xC2\x46\xF7\x52",
                         "\x63\x63\x97\x7D\xE8\x39\x48\x62\x97\xE6\x61\xC6\xC9\xD6\x68\xEB",
                         16),
    add_test_vector_data("\x63\x63\x97\x7D\xE8\x39\x48\x62\x97\xE6\x61\xC6\xC9\xD6\x68\xEB",
                         16,
                         "\x81\x6D\x5B\xD0\xFA\xE3\x53\x42\xBF\x2A\x74\x12\xC2\x46\xF7\x52",
                         "\x54\x49\xEC\xA0\x08\xFF\x59\x21\x15\x5F\x59\x8A\xF4\xCE\xD4\xD0",
                         "\x81\x6D\x5B\xD0\xFA\xE3\x53\x42\xBF\x2A\x74\x12\xC2\x46\xF7\x52",
                         16),
    add_test_vector_data("\x81\x6D\x5B\xD0\xFA\xE3\x53\x42\xBF\x2A\x74\x12\xC2\x46\xF7\x52",
                         16,
                         "\x54\x49\xEC\xA0\x08\xFF\x59\x21\x15\x5F\x59\x8A\xF4\xCE\xD4\xD0",
                         "\x66\x00\x52\x2E\x97\xAE\xB3\x09\x4E\xD5\xF9\x2A\xFC\xBC\xDD\x10",
                         "\x54\x49\xEC\xA0\x08\xFF\x59\x21\x15\x5F\x59\x8A\xF4\xCE\xD4\xD0",
                         16),
    add_test_vector_data("\x54\x49\xEC\xA0\x08\xFF\x59\x21\x15\x5F\x59\x8A\xF4\xCE\xD4\xD0",
                         16,
                         "\x66\x00\x52\x2E\x97\xAE\xB3\x09\x4E\xD5\xF9\x2A\xFC\xBC\xDD\x10",
                         "\x34\xC8\xA5\xFB\x2D\x3D\x08\xA1\x70\xD1\x20\xAC\x6D\x26\xDB\xFA",
                         "\x66\x00\x52\x2E\x97\xAE\xB3\x09\x4E\xD5\xF9\x2A\xFC\xBC\xDD\x10",
                         16),
    add_test_vector_data("\x66\x00\x52\x2E\x97\xAE\xB3\x09\x4E\xD5\xF9\x2A\xFC\xBC\xDD\x10",
                         16,
                         "\x34\xC8\xA5\xFB\x2D\x3D\x08\xA1\x70\xD1\x20\xAC\x6D\x26\xDB\xFA",
                         "\x28\x53\x0B\x35\x8C\x1B\x42\xEF\x27\x7D\xE6\xD4\x40\x7F\xC5\x91",
                         "\x34\xC8\xA5\xFB\x2D\x3D\x08\xA1\x70\xD1\x20\xAC\x6D\x26\xDB\xFA",
                         16),
    add_test_vector_data("\x34\xC8\xA5\xFB\x2D\x3D\x08\xA1\x70\xD1\x20\xAC\x6D\x26\xDB\xFA",
                         16,
                         "\x28\x53\x0B\x35\x8C\x1B\x42\xEF\x27\x7D\xE6\xD4\x40\x7F\xC5\x91",
                         "\x8A\x8A\xB9\x83\x31\x0E\xD7\x8C\x8C\x0E\xCD\xE0\x30\xB8\xDC\xA4",
                         "\x28\x53\x0B\x35\x8C\x1B\x42\xEF\x27\x7D\xE6\xD4\x40\x7F\xC5\x91",
                         16),
    add_test_vector_data("\x13\x7A\x24\xCA\x47\xCD\x12\xBE\x81\x8D\xF4\xD2\xF4\x35\x59\x60",
                         16,
                         "\xBC\xA7\x24\xA5\x45\x33\xC6\x98\x7E\x14\xAA\x82\x79\x52\xF9\x21",
                         "\x6B\x45\x92\x86\xF3\xFF\xD2\x8D\x49\xF1\x5B\x15\x81\xB0\x8E\x42",
                         "\xBC\xA7\x24\xA5\x45\x33\xC6\x98\x7E\x14\xAA\x82\x79\x52\xF9\x21",
                         16),
    add_test_vector_data("\xBC\xA7\x24\xA5\x45\x33\xC6\x98\x7E\x14\xAA\x82\x79\x52\xF9\x21",
                         16,
                         "\x6B\x45\x92\x86\xF3\xFF\xD2\x8D\x49\xF1\x5B\x15\x81\xB0\x8E\x42",
                         "\x5D\x9D\x4E\xEF\xFA\x91\x51\x57\x55\x24\xF1\x15\x81\x5A\x12\xE0",
                         "\x6B\x45\x92\x86\xF3\xFF\xD2\x8D\x49\xF1\x5B\x15\x81\xB0\x8E\x42",
                         16),
};

test_vector(twofish192, block_cipher) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xEF\xA7\x1F\x78\x89\x65\xBD\x44\x53\xF8\x60\x17\x8F\xC1\x91\x01",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\xEF\xA7\x1F\x78\x89\x65\xBD\x44\x53\xF8\x60\x17\x8F\xC1\x91\x01",
                         "\x88\xB2\xB2\x70\x6B\x10\x5E\x36\xB4\x46\xBB\x6D\x73\x1A\x1E\x88",
                         "\xEF\xA7\x1F\x78\x89\x65\xBD\x44\x53\xF8\x60\x17\x8F\xC1\x91\x01",
                         16),
    add_test_vector_data("\xEF\xA7\x1F\x78\x89\x65\xBD\x44\x53\xF8\x60\x17\x8F\xC1\x91\x01"
                         "\x00\x00\x00\x00\x00\x00\x00\x00",
                         24,
                         "\x88\xB2\xB2\x70\x6B\x10\x5E\x36\xB4\x46\xBB\x6D\x73\x1A\x1E\x88",
                         "\x39\xDA\x69\xD6\xBA\x49\x97\xD5\x85\xB6\xDC\x07\x3C\xA3\x41\xB2",
                         "\x88\xB2\xB2\x70\x6B\x10\x5E\x36\xB4\x46\xBB\x6D\x73\x1A\x1E\x88",
                         16),
    add_test_vector_data("\x88\xB2\xB2\x70\x6B\x10\x5E\x36\xB4\x46\xBB\x6D\x73\x1A\x1E\x88"
                         "\xEF\xA7\x1F\x78\x89\x65\xBD\x44",
                         24,
                         "\x39\xDA\x69\xD6\xBA\x49\x97\xD5\x85\xB6\xDC\x07\x3C\xA3\x41\xB2",
                         "\x18\x2B\x02\xD8\x14\x97\xEA\x45\xF9\xDA\xAC\xDC\x29\x19\x3A\x65",
                         "\x39\xDA\x69\xD6\xBA\x49\x97\xD5\x85\xB6\xDC\x07\x3C\xA3\x41\xB2",
                         16),
    add_test_vector_data("\x39\xDA\x69\xD6\xBA\x49\x97\xD5\x85\xB6\xDC\x07\x3C\xA3\x41\xB2"
                         "\x88\xB2\xB2\x70\x6B\x10\x5E\x36",
                         24,
                         "\x18\x2B\x02\xD8\x14\x97\xEA\x45\xF9\xDA\xAC\xDC\x29\x19\x3A\x65",
                         "\x7A\xFF\x7A\x70\xCA\x2F\xF2\x8A\xC3\x1D\xD8\xAE\x5D\xAA\xAB\x63",
                         "\x18\x2B\x02\xD8\x14\x97\xEA\x45\xF9\xDA\xAC\xDC\x29\x19\x3A\x65",
                         16),
    add_test_vector_data("\x18\x2B\x02\xD8\x14\x97\xEA\x45\xF9\xDA\xAC\xDC\x29\x19\x3A\x65"
                         "\x39\xDA\x69\xD6\xBA\x49\x97\xD5",
                         24,
                         "\x7A\xFF\x7A\x70\xCA\x2F\xF2\x8A\xC3\x1D\xD8\xAE\x5D\xAA\xAB\x63",
                         "\xD1\x07\x9B\x78\x9F\x66\x66\x49\xB6\xBD\x7D\x16\x29\xF1\xF7\x7E",
                         "\x7A\xFF\x7A\x70\xCA\x2F\xF2\x8A\xC3\x1D\xD8\xAE\x5D\xAA\xAB\x63",
                         16),
    add_test_vector_data("\x7A\xFF\x7A\x70\xCA\x2F\xF2\x8A\xC3\x1D\xD8\xAE\x5D\xAA\xAB\x63"
                         "\x18\x2B\x02\xD8\x14\x97\xEA\x45",
                         24,
                         "\xD1\x07\x9B\x78\x9F\x66\x66\x49\xB6\xBD\x7D\x16\x29\xF1\xF7\x7E",
                         "\x3A\xF6\xF7\xCE\x5B\xD3\x5E\xF1\x8B\xEC\x6F\xA7\x87\xAB\x50\x6B",
                         "\xD1\x07\x9B\x78\x9F\x66\x66\x49\xB6\xBD\x7D\x16\x29\xF1\xF7\x7E",
                         16),
    add_test_vector_data("\xD1\x07\x9B\x78\x9F\x66\x66\x49\xB6\xBD\x7D\x16\x29\xF1\xF7\x7E"
                         "\x7A\xFF\x7A\x70\xCA\x2F\xF2\x8A",
                         24,
                         "\x3A\xF6\xF7\xCE\x5B\xD3\x5E\xF1\x8B\xEC\x6F\xA7\x87\xAB\x50\x6B",
                         "\xAE\x81\x09\xBF\xDA\x85\xC1\xF2\xC5\x03\x8B\x34\xED\x69\x1B\xFF",
                         "\x3A\xF6\xF7\xCE\x5B\xD3\x5E\xF1\x8B\xEC\x6F\xA7\x87\xAB\x50\x6B",
                         16),
    add_test_vector_data("\x3A\xF6\xF7\xCE\x5B\xD3\x5E\xF1\x8B\xEC\x6F\xA7\x87\xAB\x50\x6B"
                         "\xD1\x07\x9B\x78\x9F\x66\x66\x49",
                         24,
                        "\xAE\x81\x09\xBF\xDA\x85\xC1\xF2\xC5\x03\x8B\x34\xED\x69\x1B\xFF",
                        "\x89\x3F\xD6\x7B\x98\xC5\x50\x07\x35\x71\xBD\x63\x12\x63\xFC\x78",
                        "\xAE\x81\x09\xBF\xDA\x85\xC1\xF2\xC5\x03\x8B\x34\xED\x69\x1B\xFF",
                        16),
    add_test_vector_data("\xAE\x81\x09\xBF\xDA\x85\xC1\xF2\xC5\x03\x8B\x34\xED\x69\x1B\xFF"
                         "\x3A\xF6\xF7\xCE\x5B\xD3\x5E\xF1",
                         24,
                         "\x89\x3F\xD6\x7B\x98\xC5\x50\x07\x35\x71\xBD\x63\x12\x63\xFC\x78",
                         "\x16\x43\x4F\xC9\xC8\x84\x1A\x63\xD5\x87\x00\xB5\x57\x8E\x8F\x67",
                         "\x89\x3F\xD6\x7B\x98\xC5\x50\x07\x35\x71\xBD\x63\x12\x63\xFC\x78",
                         16),
    add_test_vector_data("\xDE\xA4\xF3\xDA\x75\xEC\x7A\x8E\xAC\x38\x61\xA9\x91\x24\x02\xCD"
                         "\x5D\xBE\x44\x03\x27\x69\xDF\x54",
                         24,
                         "\xFB\x66\x52\x2C\x33\x2F\xCC\x4C\x04\x2A\xBE\x32\xFA\x9E\x90\x2F",
                         "\xF0\xAB\x73\x30\x11\x25\xFA\x21\xEF\x70\xBE\x53\x85\xFB\x76\xB6",
                         "\xFB\x66\x52\x2C\x33\x2F\xCC\x4C\x04\x2A\xBE\x32\xFA\x9E\x90\x2F",
                         16),
    add_test_vector_data("\xFB\x66\x52\x2C\x33\x2F\xCC\x4C\x04\x2A\xBE\x32\xFA\x9E\x90\x2F"
                         "\xDE\xA4\xF3\xDA\x75\xEC\x7A\x8E",
                         24,
                         "\xF0\xAB\x73\x30\x11\x25\xFA\x21\xEF\x70\xBE\x53\x85\xFB\x76\xB6",
                         "\xE7\x54\x49\x21\x2B\xEE\xF9\xF4\xA3\x90\xBD\x86\x0A\x64\x09\x41",
                         "\xF0\xAB\x73\x30\x11\x25\xFA\x21\xEF\x70\xBE\x53\x85\xFB\x76\xB6",
                         16),
};

test_vector(twofish256, block_cipher) = {
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F",
                         "\xD4\x3B\xB7\x55\x6E\xA3\x2E\x46\xF2\xA2\x82\xB7\xD4\x5B\x4E\x0D",
                         "\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F",
                         16),
    add_test_vector_data("\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\xD4\x3B\xB7\x55\x6E\xA3\x2E\x46\xF2\xA2\x82\xB7\xD4\x5B\x4E\x0D",
                         "\x90\xAF\xE9\x1B\xB2\x88\x54\x4F\x2C\x32\xDC\x23\x9B\x26\x35\xE6",
                         "\xD4\x3B\xB7\x55\x6E\xA3\x2E\x46\xF2\xA2\x82\xB7\xD4\x5B\x4E\x0D",
                         16),
    add_test_vector_data("\xD4\x3B\xB7\x55\x6E\xA3\x2E\x46\xF2\xA2\x82\xB7\xD4\x5B\x4E\x0D"
                         "\x57\xFF\x73\x9D\x4D\xC9\x2C\x1B\xD7\xFC\x01\x70\x0C\xC8\x21\x6F",
                         32,
                         "\x90\xAF\xE9\x1B\xB2\x88\x54\x4F\x2C\x32\xDC\x23\x9B\x26\x35\xE6",
                         "\x6C\xB4\x56\x1C\x40\xBF\x0A\x97\x05\x93\x1C\xB6\xD4\x08\xE7\xFA",
                         "\x90\xAF\xE9\x1B\xB2\x88\x54\x4F\x2C\x32\xDC\x23\x9B\x26\x35\xE6",
                         16),

    add_test_vector_data("\x90\xAF\xE9\x1B\xB2\x88\x54\x4F\x2C\x32\xDC\x23\x9B\x26\x35\xE6"
                         "\xD4\x3B\xB7\x55\x6E\xA3\x2E\x46\xF2\xA2\x82\xB7\xD4\x5B\x4E\x0D",
                         32,
                         "\x6C\xB4\x56\x1C\x40\xBF\x0A\x97\x05\x93\x1C\xB6\xD4\x08\xE7\xFA",
                         "\x30\x59\xD6\xD6\x17\x53\xB9\x58\xD9\x2F\x47\x81\xC8\x64\x0E\x58",
                         "\x6C\xB4\x56\x1C\x40\xBF\x0A\x97\x05\x93\x1C\xB6\xD4\x08\xE7\xFA",
                         16),
    add_test_vector_data("\x6C\xB4\x56\x1C\x40\xBF\x0A\x97\x05\x93\x1C\xB6\xD4\x08\xE7\xFA"
                         "\x90\xAF\xE9\x1B\xB2\x88\x54\x4F\x2C\x32\xDC\x23\x9B\x26\x35\xE6",
                         32,
                         "\x30\x59\xD6\xD6\x17\x53\xB9\x58\xD9\x2F\x47\x81\xC8\x64\x0E\x58",
                         "\xE6\x94\x65\x77\x05\x05\xD7\xF8\x0E\xF6\x8C\xA3\x8A\xB3\xA3\xD6",
                         "\x30\x59\xD6\xD6\x17\x53\xB9\x58\xD9\x2F\x47\x81\xC8\x64\x0E\x58",
                         16),
    add_test_vector_data("\x30\x59\xD6\xD6\x17\x53\xB9\x58\xD9\x2F\x47\x81\xC8\x64\x0E\x58"
                         "\x6C\xB4\x56\x1C\x40\xBF\x0A\x97\x05\x93\x1C\xB6\xD4\x08\xE7\xFA",
                         32,
                         "\xE6\x94\x65\x77\x05\x05\xD7\xF8\x0E\xF6\x8C\xA3\x8A\xB3\xA3\xD6",
                         "\x5A\xB6\x7A\x5F\x85\x39\xA4\xA5\xFD\x9F\x03\x73\xBA\x46\x34\x66",
                         "\xE6\x94\x65\x77\x05\x05\xD7\xF8\x0E\xF6\x8C\xA3\x8A\xB3\xA3\xD6",
                         16),
    add_test_vector_data("\xE6\x94\x65\x77\x05\x05\xD7\xF8\x0E\xF6\x8C\xA3\x8A\xB3\xA3\xD6"
                         "\x30\x59\xD6\xD6\x17\x53\xB9\x58\xD9\x2F\x47\x81\xC8\x64\x0E\x58",
                         32,
                         "\x5A\xB6\x7A\x5F\x85\x39\xA4\xA5\xFD\x9F\x03\x73\xBA\x46\x34\x66",
                         "\xDC\x09\x6B\xCD\x99\xFC\x72\xF7\x99\x36\xD4\xC7\x48\xE7\x5A\xF7",
                         "\x5A\xB6\x7A\x5F\x85\x39\xA4\xA5\xFD\x9F\x03\x73\xBA\x46\x34\x66",
                         16),
    add_test_vector_data("\x5A\xB6\x7A\x5F\x85\x39\xA4\xA5\xFD\x9F\x03\x73\xBA\x46\x34\x66"
                         "\xE6\x94\x65\x77\x05\x05\xD7\xF8\x0E\xF6\x8C\xA3\x8A\xB3\xA3\xD6",
                         32,
                         "\xDC\x09\x6B\xCD\x99\xFC\x72\xF7\x99\x36\xD4\xC7\x48\xE7\x5A\xF7",
                         "\xC5\xA3\xE7\xCE\xE0\xF1\xB7\x26\x05\x28\xA6\x8F\xB4\xEA\x05\xF2",
                         "\xDC\x09\x6B\xCD\x99\xFC\x72\xF7\x99\x36\xD4\xC7\x48\xE7\x5A\xF7",
                         16),
    add_test_vector_data("\xDC\x09\x6B\xCD\x99\xFC\x72\xF7\x99\x36\xD4\xC7\x48\xE7\x5A\xF7"
                         "\x5A\xB6\x7A\x5F\x85\x39\xA4\xA5\xFD\x9F\x03\x73\xBA\x46\x34\x66",
                         32,
                         "\xC5\xA3\xE7\xCE\xE0\xF1\xB7\x26\x05\x28\xA6\x8F\xB4\xEA\x05\xF2",
                         "\x43\xD5\xCE\xC3\x27\xB2\x4A\xB9\x0A\xD3\x4A\x79\xD0\x46\x91\x51",
                         "\xC5\xA3\xE7\xCE\xE0\xF1\xB7\x26\x05\x28\xA6\x8F\xB4\xEA\x05\xF2",
                         16),
    add_test_vector_data("\x2E\x21\x58\xBC\x3E\x5F\xC7\x14\xC1\xEE\xEC\xA0\xEA\x69\x6D\x48"
                         "\xD2\xDE\xD7\x3E\x59\x31\x9A\x81\x38\xE0\x33\x1F\x0E\xA1\x49\xEA",
                         32,
                         "\x24\x8A\x7F\x35\x28\xB1\x68\xAC\xFD\xD1\x38\x6E\x3F\x51\xE3\x0C",
                         "\x43\x10\x58\xF4\xDB\xC7\xF7\x34\xDA\x4F\x02\xF0\x4C\xC4\xF4\x59",
                         "\x24\x8A\x7F\x35\x28\xB1\x68\xAC\xFD\xD1\x38\x6E\x3F\x51\xE3\x0C",
                         16),
    add_test_vector_data("\x24\x8A\x7F\x35\x28\xB1\x68\xAC\xFD\xD1\x38\x6E\x3F\x51\xE3\x0C"
                         "\x2E\x21\x58\xBC\x3E\x5F\xC7\x14\xC1\xEE\xEC\xA0\xEA\x69\x6D\x48",
                         32,
                         "\x43\x10\x58\xF4\xDB\xC7\xF7\x34\xDA\x4F\x02\xF0\x4C\xC4\xF4\x59",
                         "\x37\xFE\x26\xFF\x1C\xF6\x61\x75\xF5\xDD\xF4\xC3\x3B\x97\xA2\x05",
                         "\x43\x10\x58\xF4\xDB\xC7\xF7\x34\xDA\x4F\x02\xF0\x4C\xC4\xF4\x59",
                         16),
};

#endif
