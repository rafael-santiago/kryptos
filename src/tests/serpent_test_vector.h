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

test_vector(serpent, block_cipher) = {
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x26\x4E\x54\x81\xEF\xF4\x2A\x46\x06\xAB\xDA\x06\xC0\xBF\xDA\x3D",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x4A\x23\x1B\x3B\xC7\x27\x99\x34\x07\xAC\x6E\xC8\x35\x0E\x85\x24",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xE0\x32\x69\xF9\xE9\xFD\x85\x3C\x7D\x81\x56\xDF\x14\xB9\x8D\x56",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xA7\x98\x18\x1C\x30\x81\xAC\x59\xD5\xBA\x89\x75\x4D\xAC\xC4\x8F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x33\x40\x1C\xDF\xBE\xCC\xF4\x99\xB3\x22\x6B\x4C\x6A\xD8\xFD\xDF",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x2C\x06\x27\x86\x83\xB5\x75\x9C\x12\xB1\x47\xDE\x2B\x0E\x0B\xB1",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54",
                         16,
                         "\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54",
                         "\x5B\xC5\x23\x83\x84\xE5\x21\x5E\xA0\x5B\x27\x36\x98\x23\xF1\x3A",
                         "\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54\x54",
                         16),
    add_test_vector_data("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
                         16,
                         "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
                         "\x71\x13\xB6\x34\x7D\x1B\xEF\x61\xA1\xAB\xFA\xC6\x26\x6B\x74\x2B",
                         "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
                         16),
    add_test_vector_data("\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77",
                         16,
                         "\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77",
                         "\x3F\xEA\x78\xD3\x3C\xBB\xE7\x19\x33\x95\x55\x16\x2F\x73\x5C\xDE",
                         "\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77",
                         16),
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16,
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\x27\x99\x57\x81\x93\x59\xDE\x24\x7D\x1E\x39\x9D\xE5\x41\xBD\xEC",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16),
    add_test_vector_data("\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         16,
                         "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         "\xC4\xFA\xF7\x78\x7C\xAB\xBF\x3E\xAA\x89\x95\x59\x26\x38\xE1\xD1",
                         "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         16),
    add_test_vector_data("\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
                         16,
                         "\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
                         "\x4E\x6C\xD7\xAE\xAF\xC8\xF5\x1C\xF4\x38\x02\x9F\x42\xA4\x3D\xEC",
                         "\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
                         16),
    add_test_vector_data("\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F",
                         16,
                         "\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F",
                         "\xC1\x69\x07\x8C\x4C\x77\xD3\xD9\x85\xEF\x66\xD5\xB3\xA4\xE6\xFA",
                         "\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F\x8F",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x2D\xEE\x67\x5B\x6B\x74\x01\x36\x7D\xA2\xA8\x0F\xB4\x4B\x80\x65",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                         16,
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x56\x3E\x2C\xF8\x74\x0A\x27\xC1\x64\x80\x45\x60\x39\x1E\x9B\x27",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         16,
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x92\xD7\xF8\xEF\x2C\x36\xC5\x34\x09\xF2\x75\x90\x2F\x06\x53\x9F",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         16),
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\xEF\xA7\xE0\xC2\x89\x8A\xDA\x8B\x2D\x18\xE7\x82\x41\x63\x14\x8F",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xEF\xA7\xE0\xC2\x89\x8A\xDA\x8B\x2D\x18\xE7\x82\x41\x63\x14\x8F",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\xA4\x01\x88\x33\x94\x27\x94\xB4\x3F\xE8\x8C\xF7\x24\x8E\xC2\x8B",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xA4\x01\x88\x33\x94\x27\x94\xB4\x3F\xE8\x8C\xF7\x24\x8E\xC2\x8B",
                         16),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\x5A\x64\x1E\xFA\x96\x04\xC4\x3C\x01\xBD\xDB\xC5\x9E\xE4\x9D\xFF",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x5A\x64\x1E\xFA\x96\x04\xC4\x3C\x01\xBD\xDB\xC5\x9E\xE4\x9D\xFF",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16,
                         "\xCE\xDB\xDE\xD8\x66\xEA\x4C\x02\x8C\x9D\x02\x89\xE6\x06\x9A\xBB",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xCE\xDB\xDE\xD8\x66\xEA\x4C\x02\x8C\x9D\x02\x89\xE6\x06\x9A\xBB",
                         16),
    add_test_vector_data("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
                         16,
                         "\x2D\xDC\x7F\x21\xFD\x8C\x10\xF8\xF6\x45\x32\xA7\xF0\x8D\x41\xE8",
                         "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
                         "\x2D\xDC\x7F\x21\xFD\x8C\x10\xF8\xF6\x45\x32\xA7\xF0\x8D\x41\xE8",
                         16),
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16,
                         "\xD6\x04\xD0\xEC\x8C\x94\xF8\x10\x75\xF7\x03\xB4\x71\xF2\x4E\x51",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\xD6\x04\xD0\xEC\x8C\x94\xF8\x10\x75\xF7\x03\xB4\x71\xF2\x4E\x51",
                         16),
    add_test_vector_data("\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
                         16,
                         "\x39\x1B\x99\xCF\x5C\xFD\xCF\xEC\x78\x61\xD2\x09\x96\x6F\x2A\xA8",
                         "\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
                         "\x39\x1B\x99\xCF\x5C\xFD\xCF\xEC\x78\x61\xD2\x09\x96\x6F\x2A\xA8",
                         16),
    add_test_vector_data("\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE",
                         16,
                         "\xE0\xAE\xCB\x89\x9F\x95\x60\xEB\x4B\x09\xB9\x67\xBD\xBE\x0A\x49",
                         "\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE\xAE",
                         "\xE0\xAE\xCB\x89\x9F\x95\x60\xEB\x4B\x09\xB9\x67\xBD\xBE\x0A\x49",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                         16,
                         "\x33\xB3\xDC\x87\xED\xDD\x9B\x0F\x6A\x1F\x40\x7D\x14\x91\x93\x65",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x33\xB3\xDC\x87\xED\xDD\x9B\x0F\x6A\x1F\x40\x7D\x14\x91\x93\x65",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         16,
                         "\xBE\xB6\xC0\x69\x39\x38\x22\xD3\xBE\x73\xFF\x30\x52\x5E\xC4\x3E",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\xBE\xB6\xC0\x69\x39\x38\x22\xD3\xBE\x73\xFF\x30\x52\x5E\xC4\x3E",
                         16),
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xA2\x23\xAA\x12\x88\x46\x3C\x0E\x2B\xE3\x8E\xBD\x82\x56\x16\xC0",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xEA\xE1\xD4\x05\x57\x01\x74\xDF\x7D\xF2\xF9\x96\x6D\x50\x91\x59",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x65\xF3\x76\x84\x47\x1E\x92\x1D\xC8\xA3\x0F\x45\xB4\x3C\x44\x99",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x0E\xE0\x36\xD0\xBC\x32\xB8\x9C\x1C\xEF\x98\x7F\x52\x29\xE4\xA9",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x86\x9A\x57\x09\x98\x98\x8F\x68\x81\x9C\xCF\x30\x1E\xB0\x15\xDF",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xF6\x89\x9D\x57\xF7\x34\xAF\xD6\x47\x32\x78\xDB\xDE\x8F\xB9\x9D",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xA6\x72\x6C\xE5\x3B\xD6\x2B\xC8\x73\xF6\xC0\x46\x3A\x58\x41\xFC",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x98\x58\xFD\x31\xC9\xC6\xB5\x4A\xC0\xC9\x9C\xC5\x23\x24\xED\x34",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x0E\xBC\x39\x26\xD9\x24\xF3\x7B\xFD\x71\x6F\x40\x4C\xA8\x45\x0D",
                         "\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00",
                         16),
    add_test_vector_data("\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F"
                         "\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F",
                         32,
                         "\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F",
                         "\x22\xF4\x45\x2C\xA0\x00\xF6\xE4\x58\xB8\x67\x21\x4C\x85\xAD\xB9",
                         "\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F\x2F",
                         16),
    add_test_vector_data("\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30"
                         "\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30",
                         32,
                         "\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30",
                         "\xEF\x17\x6E\x73\x63\x13\x2B\x26\x62\x38\xEF\x91\xC4\x25\x68\x86",
                         "\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30",
                         16),
    add_test_vector_data("\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53"
                         "\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53",
                         32,
                         "\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53",
                         "\x17\xB7\xCC\xDA\x23\x12\x5B\x87\xA6\x9C\x46\x7A\x19\x27\x04\x64",
                         "\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53\x53",
                         16),
    add_test_vector_data("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
                         "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
                         32,
                         "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
                         "\x3D\x4A\x32\x9E\x2C\x0C\xB8\x2C\x3B\x55\xDC\x65\xD8\x2C\x8F\x5D",
                         "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55",
                         16),
    add_test_vector_data("\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70"
                         "\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70",
                         32,
                         "\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70",
                         "\xE3\x05\xEA\xF6\x46\x92\x4E\xFD\x56\x07\xFF\x9F\xB4\x52\x25\xEC",
                         "\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70\x70",
                         16),
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F"
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         32,
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\x56\x95\xD1\x75\xE8\xB5\x26\xCF\xD2\xDC\xB5\x9D\x08\x8E\xD2\x96",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         16),
    add_test_vector_data("\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
                         "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         32,
                         "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         "\xB3\x00\xF7\x00\x98\x7E\x62\xDD\xB4\x6A\xEA\xB2\x83\x5E\x28\x61",
                         "\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",
                         16),
    add_test_vector_data("\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88"
                         "\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
                         32,
                         "\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
                         "\x65\x9B\x79\x32\x8B\x70\x16\xCB\x66\x62\x0D\x01\xFF\x2B\x4B\xA6",
                         "\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88\x88",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         32,
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x6A\xC7\x57\x9D\x93\x77\x84\x5A\x81\x6C\xA6\xD7\x58\xF3\xFE\xFF",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                         "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
                         32,
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x28\x68\xB7\xA2\xD2\x8E\xCD\x5E\x4F\xDE\xFA\xC3\xC4\x33\x00\x74",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48"
                         "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         32,
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x3E\x50\x77\x30\x77\x6B\x93\xFD\xEA\x66\x12\x35\xE1\xDD\x99\xF0",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         16),
    add_test_vector_data("\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x99\xCA\xBA\xAA\x6C\x8D\xE9\xA3\xB7\xE8\x43\x0A\x0B\xBF\xB2\xD5",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x99\xCA\xBA\xAA\x6C\x8D\xE9\xA3\xB7\xE8\x43\x0A\x0B\xBF\xB2\xD5",
                         16),
    add_test_vector_data("\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\xA7\x9F\xC0\xC5\xF4\x9A\xEA\x38\x9F\x47\x02\x5D\x2A\x2D\x4A\x69",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xA7\x9F\xC0\xC5\xF4\x9A\xEA\x38\x9F\x47\x02\x5D\x2A\x2D\x4A\x69",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08",
                         32,
                         "\xB5\x47\xD4\xB0\x82\x4F\x52\x0B\x87\xE9\x86\x8B\x40\x3C\x4C\x47",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xB5\x47\xD4\xB0\x82\x4F\x52\x0B\x87\xE9\x86\x8B\x40\x3C\x4C\x47",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                         32,
                         "\xAF\xFA\x76\x2D\xF9\x38\x4A\x14\x1D\xA3\x69\x7E\xA4\xED\xF2\xF0",
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\xAF\xFA\x76\x2D\xF9\x38\x4A\x14\x1D\xA3\x69\x7E\xA4\xED\xF2\xF0",
                         16),
    add_test_vector_data("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         32,
                         "\x84\x45\xE3\xD3\xF1\xD9\x92\x74\x9B\x7A\x6D\xF2\xDF\x12\x3F\xE9",
                         "\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00",
                         "\x84\x45\xE3\xD3\xF1\xD9\x92\x74\x9B\x7A\x6D\xF2\xDF\x12\x3F\xE9",
                         16),
    add_test_vector_data("\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A"
                         "\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",
                         32,
                         "\xED\x91\xC5\xE3\xBA\x75\xCC\x37\x53\x51\x4C\xAF\xB2\x42\xA5\xD4",
                         "\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",
                         "\xED\x91\xC5\xE3\xBA\x75\xCC\x37\x53\x51\x4C\xAF\xB2\x42\xA5\xD4",
                         16),
    add_test_vector_data("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
                         "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
                         32,
                         "\x08\xFE\xD6\x55\xBF\x77\x17\x8B\xDA\xB0\x2D\x82\x7A\x2A\xDA\xCC",
                         "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
                         "\x08\xFE\xD6\x55\xBF\x77\x17\x8B\xDA\xB0\x2D\x82\x7A\x2A\xDA\xCC",
                         16),
    add_test_vector_data("\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                         "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11",
                         32,
                         "\xCB\x79\xD8\x81\x22\x83\x6D\xC1\xEE\x5D\xE3\xE2\xEE\x51\x8F\x1C",
                         "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11",
                         "\xCB\x79\xD8\x81\x22\x83\x6D\xC1\xEE\x5D\xE3\xE2\xEE\x51\x8F\x1C",
                         16),
    add_test_vector_data("\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77"
                         "\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77",
                         32,
                         "\xFF\xEF\x10\x70\xFC\x38\x96\x91\x2D\xEC\xD4\xEF\xB5\x4E\xCE\x3E",
                         "\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77",
                         "\xFF\xEF\x10\x70\xFC\x38\x96\x91\x2D\xEC\xD4\xEF\xB5\x4E\xCE\x3E",
                         16),
    add_test_vector_data("\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F"
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         32,
                         "\x2E\x8C\x13\x05\xA3\xF0\x80\x02\x04\x8B\xF8\x20\xFD\x7E\x96\x48",
                         "\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F\x7F",
                         "\x2E\x8C\x13\x05\xA3\xF0\x80\x02\x04\x8B\xF8\x20\xFD\x7E\x96\x48",
                         16),
    add_test_vector_data("\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94"
                         "\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94",
                         32,
                         "\x6D\xAA\xD0\xFB\xC0\x6E\x36\xCA\xB1\xCC\x77\x52\xF2\x1D\x6A\x0E",
                         "\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94\x94",
                         "\x6D\xAA\xD0\xFB\xC0\x6E\x36\xCA\xB1\xCC\x77\x52\xF2\x1D\x6A\x0E",
                         16),
    add_test_vector_data("\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96"
                         "\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96",
                         32,
                         "\xA0\xA7\x4E\xE2\x02\x15\xB4\xBD\x17\x2B\xCE\x6A\x06\x45\x0A\x67",
                         "\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96\x96",
                         "\xA0\xA7\x4E\xE2\x02\x15\xB4\xBD\x17\x2B\xCE\x6A\x06\x45\x0A\x67",
                         16),
    add_test_vector_data("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         32,
                         "\x24\xB8\x06\x36\x38\x88\x42\x26\x47\xBC\x51\x10\xE2\x2A\x0F\x56",
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                         "\x24\xB8\x06\x36\x38\x88\x42\x26\x47\xBC\x51\x10\xE2\x2A\x0F\x56",
                         16),
    add_test_vector_data("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                         "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F",
                         32,
                         "\x3D\xA4\x6F\xFA\x6F\x4D\x6F\x30\xCD\x25\x83\x33\xE5\xA6\x13\x69",
                         "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
                         "\x3D\xA4\x6F\xFA\x6F\x4D\x6F\x30\xCD\x25\x83\x33\xE5\xA6\x13\x69",
                         16),
    add_test_vector_data("\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48"
                         "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48",
                         32,
                         "\x67\x7C\x8D\xFA\xA0\x80\x71\x74\x3F\xD2\xB4\x15\xD1\xB2\x8A\xF2",
                         "\xEA\x02\x47\x14\xAD\x5C\x4D\x84\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
                         "\x67\x7C\x8D\xFA\xA0\x80\x71\x74\x3F\xD2\xB4\x15\xD1\xB2\x8A\xF2",
                         16)
};

#endif
