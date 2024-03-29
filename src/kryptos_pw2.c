/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_types.h>
#include <kryptos_pw2.h>

// TIP(Rafael): Here "-2147483648" denotes our infinity, nan. The kryptos_pw2() was written for being used on a mod
//              division, i.e.: x % kryptos_pw2(exp); The "x" must be less than or equals to kryptos_pw2_lt_nr.

#define KRYPTOS_PW2_NAN -2147483647 - 1

static int kryptos_pw2_lt[255] = {
              1,           2,           4,           8,          16,          32,          64,         128,         256,
            512,        1024,        2048,        4096,        8192,       16384,       32768,       65536,      131072,
         262144,      524288,     1048576,     2097152,     4194304,     8388608,    16777216,    33554432,    67108864,
      134217728,   268435456,   536870912,  1073741824,
      //-------------------------------------------------------- Infinity do not cross ----------------------------------------------------------------------
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN,
      KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN, KRYPTOS_PW2_NAN
};

static size_t kryptos_pw2_lt_nr = sizeof(kryptos_pw2_lt) / sizeof(kryptos_pw2_lt[0]);

int kryptos_pw2(const int e) {
    return kryptos_pw2_lt[e % kryptos_pw2_lt_nr];
}
