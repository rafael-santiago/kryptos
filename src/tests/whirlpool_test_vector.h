/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_WHIRLPOOL_TEST_VECTOR_H
#define KRYPTOS_TESTS_WHIRLPOOL_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(whirlpool, hash) = {
    add_test_vector_data("", 0,
                         "19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A7"
                         "3E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3", 128,
                         "\x19\xFA\x61\xD7\x55\x22\xA4\x66\x9B\x44\xE3\x9C\x1D\x2E\x17\x26"
                         "\xC5\x30\x23\x21\x30\xD4\x07\xF8\x9A\xFE\xE0\x96\x49\x97\xF7\xA7"
                         "\x3E\x83\xBE\x69\x8B\x28\x8F\xEB\xCF\x88\xE3\xE0\x3C\x4F\x07\x57"
                         "\xEA\x89\x64\xE5\x9B\x63\xD9\x37\x08\xB1\x38\xCC\x42\xA6\x6E\xB3", 64),
    add_test_vector_data("a", 1,
                         "8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42"
                         "D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A", 128,
                         "\x8A\xCA\x26\x02\x79\x2A\xEC\x6F\x11\xA6\x72\x06\x53\x1F\xB7\xD7"
                         "\xF0\xDF\xF5\x94\x13\x14\x5E\x69\x73\xC4\x50\x01\xD0\x08\x7B\x42"
                         "\xD1\x1B\xC6\x45\x41\x3A\xEF\xF6\x3A\x42\x39\x1A\x39\x14\x5A\x59"
                         "\x1A\x92\x20\x0D\x56\x01\x95\xE5\x3B\x47\x85\x84\xFD\xAE\x23\x1A", 64),
    add_test_vector_data("abc", 3,
                         "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C"
                         "7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5", 128,
                         "\x4E\x24\x48\xA4\xC6\xF4\x86\xBB\x16\xB6\x56\x2C\x73\xB4\x02\x0B"
                         "\xF3\x04\x3E\x3A\x73\x1B\xCE\x72\x1A\xE1\xB3\x03\xD9\x7E\x6D\x4C"
                         "\x71\x81\xEE\xBD\xB6\xC5\x7E\x27\x7D\x0E\x34\x95\x71\x14\xCB\xD6"
                         "\xC7\x97\xFC\x9D\x95\xD8\xB5\x82\xD2\x25\x29\x20\x76\xD4\xEE\xF5", 64),
    add_test_vector_data("message digest", 14,
                         "378C84A4126E2DC6E56DCC7458377AAC838D00032230F53CE1F5700C0FFB4D3B"
                         "8421557659EF55C106B4B52AC5A4AAA692ED920052838F3362E86DBD37A8903E", 128,
                         "\x37\x8C\x84\xA4\x12\x6E\x2D\xC6\xE5\x6D\xCC\x74\x58\x37\x7A\xAC"
                         "\x83\x8D\x00\x03\x22\x30\xF5\x3C\xE1\xF5\x70\x0C\x0F\xFB\x4D\x3B"
                         "\x84\x21\x55\x76\x59\xEF\x55\xC1\x06\xB4\xB5\x2A\xC5\xA4\xAA\xA6"
                         "\x92\xED\x92\x00\x52\x83\x8F\x33\x62\xE8\x6D\xBD\x37\xA8\x90\x3E", 64),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "F1D754662636FFE92C82EBB9212A484A8D38631EAD4238F5442EE13B8054E41B"
                         "08BF2A9251C30B6A0B8AAE86177AB4A6F68F673E7207865D5D9819A3DBA4EB3B", 128,
                         "\xF1\xD7\x54\x66\x26\x36\xFF\xE9\x2C\x82\xEB\xB9\x21\x2A\x48\x4A"
                         "\x8D\x38\x63\x1E\xAD\x42\x38\xF5\x44\x2E\xE1\x3B\x80\x54\xE4\x1B"
                         "\x08\xBF\x2A\x92\x51\xC3\x0B\x6A\x0B\x8A\xAE\x86\x17\x7A\xB4\xA6"
                         "\xF6\x8F\x67\x3E\x72\x07\x86\x5D\x5D\x98\x19\xA3\xDB\xA4\xEB\x3B", 64),
    add_test_vector_data("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
                         "DC37E008CF9EE69BF11F00ED9ABA26901DD7C28CDEC066CC6AF42E40F82F3A1E"
                         "08EBA26629129D8FB7CB57211B9281A65517CC879D7B962142C65F5A7AF01467", 128,
                         "\xDC\x37\xE0\x08\xCF\x9E\xE6\x9B\xF1\x1F\x00\xED\x9A\xBA\x26\x90"
                         "\x1D\xD7\xC2\x8C\xDE\xC0\x66\xCC\x6A\xF4\x2E\x40\xF8\x2F\x3A\x1E"
                         "\x08\xEB\xA2\x66\x29\x12\x9D\x8F\xB7\xCB\x57\x21\x1B\x92\x81\xA6"
                         "\x55\x17\xCC\x87\x9D\x7B\x96\x21\x42\xC6\x5F\x5A\x7A\xF0\x14\x67", 64),
    add_test_vector_data("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
                         "466EF18BABB0154D25B9D38A6414F5C08784372BCCB204D6549C4AFADB601429"
                         "4D5BD8DF2A6C44E538CD047B2681A51A2C60481E88C5A20B2C2A80CF3A9A083B", 128,
                         "\x46\x6E\xF1\x8B\xAB\xB0\x15\x4D\x25\xB9\xD3\x8A\x64\x14\xF5\xC0"
                         "\x87\x84\x37\x2B\xCC\xB2\x04\xD6\x54\x9C\x4A\xFA\xDB\x60\x14\x29"
                         "\x4D\x5B\xD8\xDF\x2A\x6C\x44\xE5\x38\xCD\x04\x7B\x26\x81\xA5\x1A"
                         "\x2C\x60\x48\x1E\x88\xC5\xA2\x0B\x2C\x2A\x80\xCF\x3A\x9A\x08\x3B", 64),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijk", 32,
                         "2A987EA40F917061F5D6F0A0E4644F488A7A5A52DEEE656207C562F988E95C69"
                         "16BDC8031BC5BE1B7B947639FE050B56939BAAA0ADFF9AE6745B7B181C3BE3FD", 128,
                         "\x2A\x98\x7E\xA4\x0F\x91\x70\x61\xF5\xD6\xF0\xA0\xE4\x64\x4F\x48"
                         "\x8A\x7A\x5A\x52\xDE\xEE\x65\x62\x07\xC5\x62\xF9\x88\xE9\x5C\x69"
                         "\x16\xBD\xC8\x03\x1B\xC5\xBE\x1B\x7B\x94\x76\x39\xFE\x05\x0B\x56"
                         "\x93\x9B\xAA\xA0\xAD\xFF\x9A\xE6\x74\x5B\x7B\x18\x1C\x3B\xE3\xFD", 64)
};

#endif
