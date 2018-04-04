/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_TESTS_SHA384_TEST_VECTOR_H
#define KRYPTOS_TESTS_SHA384_TEST_VECTOR_H 1

#include "test_types.h"

test_vector(sha384, hash) = {
    add_test_vector_data("", 0,
                         "38B060A751AC96384CD9327EB1B1E36A"
                         "21FDB71114BE07434C0CC7BF63F6E1DA"
                         "274EDEBFE76F65FBD51AD2F14898B95B", 96,
                         "\x38\xB0\x60\xA7\x51\xAC\x96\x38\x4C\xD9\x32\x7E\xB1\xB1\xE3\x6A"
                         "\x21\xFD\xB7\x11\x14\xBE\x07\x43\x4C\x0C\xC7\xBF\x63\xF6\xE1\xDA"
                         "\x27\x4E\xDE\xBF\xE7\x6F\x65\xFB\xD5\x1A\xD2\xF1\x48\x98\xB9\x5B", 48),
    add_test_vector_data("a", 1,
                         "54A59B9F22B0B80880D8427E548B7C23"
                         "ABD873486E1F035DCE9CD697E8517503"
                         "3CAA88E6D57BC35EFAE0B5AFD3145F31", 96,
                         "\x54\xA5\x9B\x9F\x22\xB0\xB8\x08\x80\xD8\x42\x7E\x54\x8B\x7C\x23"
                         "\xAB\xD8\x73\x48\x6E\x1F\x03\x5D\xCE\x9C\xD6\x97\xE8\x51\x75\x03"
                         "\x3C\xAA\x88\xE6\xD5\x7B\xC3\x5E\xFA\xE0\xB5\xAF\xD3\x14\x5F\x31", 48),
    add_test_vector_data("abc", 3,
                         "CB00753F45A35E8BB5A03D699AC65007"
                         "272C32AB0EDED1631A8B605A43FF5BED"
                         "8086072BA1E7CC2358BAECA134C825A7", 96,
                         "\xCB\x00\x75\x3F\x45\xA3\x5E\x8B\xB5\xA0\x3D\x69\x9A\xC6\x50\x07"
                         "\x27\x2C\x32\xAB\x0E\xDE\xD1\x63\x1A\x8B\x60\x5A\x43\xFF\x5B\xED"
                         "\x80\x86\x07\x2B\xA1\xE7\xCC\x23\x58\xBA\xEC\xA1\x34\xC8\x25\xA7", 48),
    add_test_vector_data("message digest", 14,
                         "473ED35167EC1F5D8E550368A3DB39BE"
                         "54639F828868E9454C239FC8B52E3C61"
                         "DBD0D8B4DE1390C256DCBB5D5FD99CD5", 96,
                         "\x47\x3E\xD3\x51\x67\xEC\x1F\x5D\x8E\x55\x03\x68\xA3\xDB\x39\xBE"
                         "\x54\x63\x9F\x82\x88\x68\xE9\x45\x4C\x23\x9F\xC8\xB5\x2E\x3C\x61"
                         "\xDB\xD0\xD8\xB4\xDE\x13\x90\xC2\x56\xDC\xBB\x5D\x5F\xD9\x9C\xD5", 48),
    add_test_vector_data("abcdefghijklmnopqrstuvwxyz", 26,
                         "FEB67349DF3DB6F5924815D6C3DC133F"
                         "091809213731FE5C7B5F4999E463479F"
                         "F2877F5F2936FA63BB43784B12F3EBB4", 96,
                         "\xFE\xB6\x73\x49\xDF\x3D\xB6\xF5\x92\x48\x15\xD6\xC3\xDC\x13\x3F"
                         "\x09\x18\x09\x21\x37\x31\xFE\x5C\x7B\x5F\x49\x99\xE4\x63\x47\x9F"
                         "\xF2\x87\x7F\x5F\x29\x36\xFA\x63\xBB\x43\x78\x4B\x12\xF3\xEB\xB4", 48),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                         "3391FDDDFC8DC7393707A65B1B470939"
                         "7CF8B1D162AF05ABFE8F450DE5F36BC6"
                         "B0455A8520BC4E6F5FE95B1FE3C8452B", 96,
                         "\x33\x91\xFD\xDD\xFC\x8D\xC7\x39\x37\x07\xA6\x5B\x1B\x47\x09\x39"
                         "\x7C\xF8\xB1\xD1\x62\xAF\x05\xAB\xFE\x8F\x45\x0D\xE5\xF3\x6B\xC6"
                         "\xB0\x45\x5A\x85\x20\xBC\x4E\x6F\x5F\xE9\x5B\x1F\xE3\xC8\x45\x2B", 48),
    add_test_vector_data("abcdbcdecdefdefgefghfghighijhijk", 32,
                         "D4CC646A83A55044DF94814DB93B6062"
                         "E656623DB0B9E2DAB8819174589BF0C9"
                         "D7192B9799E301698B97ADAA3D82E20C", 96,
                         "\xD4\xCC\x64\x6A\x83\xA5\x50\x44\xDF\x94\x81\x4D\xB9\x3B\x60\x62"
                         "\xE6\x56\x62\x3D\xB0\xB9\xE2\xDA\xB8\x81\x91\x74\x58\x9B\xF0\xC9"
                         "\xD7\x19\x2B\x97\x99\xE3\x01\x69\x8B\x97\xAD\xAA\x3D\x82\xE2\x0C", 48)
};

#endif
