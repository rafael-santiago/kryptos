/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "ecc_tests.h"
#include <kryptos_ec_utils.h>
#include <kryptos_mp.h>
#include <kryptos_memory.h>

CUTE_TEST_CASE(kryptos_ec_set_point_tests)
    kryptos_ec_pt_t *p = NULL;
    kryptos_mp_value_t *x = NULL, *y = NULL;
    x = kryptos_hex_value_as_mp("DEADBEEF", 8);
    CUTE_ASSERT(x != NULL);
    y = kryptos_hex_value_as_mp("CACACACA", 8);
    CUTE_ASSERT(y != NULL);
    CUTE_ASSERT(kryptos_ec_set_point(&p, x, y) == 1);
    CUTE_ASSERT(p != NULL);
    CUTE_ASSERT(kryptos_mp_eq(p->x, x) == 1);
    CUTE_ASSERT(kryptos_mp_eq(p->y, y) == 1);
    kryptos_del_mp_value(x);
    kryptos_del_mp_value(y);
    kryptos_ec_del_point(p); // INFO(Rafael): In case of any memory leak, the memory leak check system will warn us.
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ec_set_curve_tests)
    kryptos_ec_t *ec = NULL;
    kryptos_mp_value_t *a = NULL, *b = NULL, *p = NULL;
    a = kryptos_hex_value_as_mp("0123456789", 10);
    CUTE_ASSERT(a != NULL);
    b = kryptos_hex_value_as_mp("9876543210", 10);
    CUTE_ASSERT(b != NULL);
    p = kryptos_hex_value_as_mp("0123456789ABCDEFFEDCBA9876543210", 32);
    CUTE_ASSERT(p != NULL);
    CUTE_ASSERT(kryptos_ec_set_curve(&ec, a, b, p) == 1);
    CUTE_ASSERT(ec != NULL);
    CUTE_ASSERT(kryptos_mp_eq(ec->a, a) == 1);
    CUTE_ASSERT(kryptos_mp_eq(ec->b, b) == 1);
    CUTE_ASSERT(kryptos_mp_eq(ec->p, p) == 1);
    kryptos_del_mp_value(a);
    kryptos_del_mp_value(b);
    kryptos_del_mp_value(p);
    kryptos_ec_del_curve(ec); // INFO(Rafael): In case of any memory leak, the memory leak check system will warn us.
CUTE_TEST_CASE_END
