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

CUTE_TEST_CASE(kryptos_ec_add_tests)
    kryptos_ec_pt_t *P = NULL, *Q = NULL, *R = NULL;
    kryptos_ec_t *EC = NULL;
    kryptos_mp_value_t *p = NULL, *_5 = NULL, *_1 = NULL, *_6 = NULL, *_3 = NULL, *_2 = NULL;
    kryptos_mp_value_t *a = NULL, *b = NULL, *r = NULL, *q = NULL;

    p = kryptos_hex_value_as_mp("11", 2);
    CUTE_ASSERT(p != NULL);

    _5 = kryptos_hex_value_as_mp("05", 2);
    CUTE_ASSERT(_5 != NULL);

    _1 = kryptos_hex_value_as_mp("01", 2);
    CUTE_ASSERT(_1 != NULL);

    _6 = kryptos_hex_value_as_mp("06", 2);
    CUTE_ASSERT(_6 != NULL);

    _3 = kryptos_hex_value_as_mp("03", 2);
    CUTE_ASSERT(_3 != NULL);

    _2 = kryptos_hex_value_as_mp("02", 2);
    CUTE_ASSERT(_2 != NULL);

    CUTE_ASSERT(kryptos_ec_set_point(&P, _5, _1) == 1);
    CUTE_ASSERT(kryptos_ec_set_point(&Q, _5, _1) == 1);
    CUTE_ASSERT(kryptos_ec_set_curve(&EC, _2, _2, p) == 1);

    kryptos_ec_add(&R, P, Q, EC);

    CUTE_ASSERT(R != NULL);

    /*a = kryptos_hex_value_as_mp("FFFFFFF2", 8);
    b = kryptos_hex_value_as_mp("11", 2);
    q = kryptos_mp_div(a, b, &r);
    printf("q = "); kryptos_print_mp(q); printf("\n");
    printf("r = "); kryptos_print_mp(r); printf("\n");
    printf("a = "); kryptos_print_mp(a); printf("\n");
    kryptos_mp_not(a);
    printf("a(inv) = "); kryptos_print_mp(a); printf("\n");
    kryptos_mp_add(&a, _1);
    kryptos_mp_sub(&b, a);
    kryptos_mp_sub(&a, b);
    //printf("r' = "); kryptos_print_mp(a); printf("\n");
    printf("r' = "); kryptos_print_mp(b); printf("\n");
    exit(1);*/

    printf("P.x = "); kryptos_print_mp(P->x); printf("\n");
    printf("P.y = "); kryptos_print_mp(P->y); printf("\n");

    printf("Q.x = "); kryptos_print_mp(Q->x); printf("\n");
    printf("Q.y = "); kryptos_print_mp(Q->y); printf("\n");

    printf("R.X = "); kryptos_print_mp(R->x); printf("\n");
    printf("R.Y = "); kryptos_print_mp(R->y); printf("\n");

    CUTE_ASSERT(kryptos_mp_eq(R->x, _6) == 1);
    CUTE_ASSERT(kryptos_mp_eq(R->y, _3) == 1);

    kryptos_del_mp_value(_1);
    kryptos_del_mp_value(_2);
    kryptos_del_mp_value(_3);
    kryptos_del_mp_value(_5);
    kryptos_del_mp_value(_6);
    kryptos_del_mp_value(p);

    kryptos_ec_del_point(P);
    kryptos_ec_del_point(Q);
    kryptos_ec_del_point(R);

    kryptos_ec_del_curve(EC);
CUTE_TEST_CASE_END
