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

CUTE_TEST_CASE(kryptos_ec_dbl_tests)
    struct test_ctx {
        kryptos_u8_t *a;
        size_t a_size;
        kryptos_u8_t *b;
        size_t b_size;
        kryptos_u8_t *p;
        size_t p_size;
        kryptos_u8_t *x;
        size_t x_size;
        kryptos_u8_t *y;
        size_t y_size;
        kryptos_u8_t *ex;
        size_t ex_size;
        kryptos_u8_t *ey;
        size_t ey_size;
    };
    struct test_ctx test_vector[] = {
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "06", 2, "03", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_ec_pt_t *P = NULL, *R = NULL;
    kryptos_ec_t *EC = NULL;
    kryptos_mp_value_t *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *ex = NULL, *ey = NULL;

    for (t = 0; t < tv_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        CUTE_ASSERT(a != NULL);

        b = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        CUTE_ASSERT(b != NULL);

        p = kryptos_hex_value_as_mp(test_vector[t].p, test_vector[t].p_size);
        CUTE_ASSERT(p != NULL);

        x = kryptos_hex_value_as_mp(test_vector[t].x, test_vector[t].x_size);
        CUTE_ASSERT(x != NULL);

        y = kryptos_hex_value_as_mp(test_vector[t].y, test_vector[t].y_size);
        CUTE_ASSERT(y != NULL);

        ex = kryptos_hex_value_as_mp(test_vector[t].ex, test_vector[t].ex_size);
        CUTE_ASSERT(ex != NULL);

        ey = kryptos_hex_value_as_mp(test_vector[t].ey, test_vector[t].ey_size);
        CUTE_ASSERT(ey != NULL);

        CUTE_ASSERT(kryptos_ec_set_curve(&EC, a, b, p) == 1);

        CUTE_ASSERT(kryptos_ec_set_point(&P, x, y) == 1);

        kryptos_ec_dbl(&R, P, EC);

        CUTE_ASSERT(R != NULL);

        CUTE_ASSERT(kryptos_mp_eq(R->x, ex) == 1);
        CUTE_ASSERT(kryptos_mp_eq(R->y, ey) == 1);

        kryptos_ec_del_curve(EC);
        kryptos_ec_del_point(P);
        kryptos_ec_del_point(R);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(ex);
        kryptos_del_mp_value(ey);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ec_add_tests)
    struct test_ctx {
        kryptos_u8_t *a;
        size_t a_size;
        kryptos_u8_t *b;
        size_t b_size;
        kryptos_u8_t *p;
        size_t p_size;
        kryptos_u8_t *x1;
        size_t x1_size;
        kryptos_u8_t *y1;
        size_t y1_size;
        kryptos_u8_t *x2;
        size_t x2_size;
        kryptos_u8_t *y2;
        size_t y2_size;
        kryptos_u8_t *ex;
        size_t ex_size;
        kryptos_u8_t *ey;
        size_t ey_size;
    };
    struct test_ctx test_vector[] = {
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "05", 2, "01", 2, "06", 2, "03", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "02", 2, "04", 2, "0B", 2, "05", 2 },
        { "02", 2, "02", 2, "11", 2, "00", 2, "00", 2, "00", 2, "00", 2, "00", 2, "00", 2 },
        { "02", 2, "02", 2, "11", 2, "05", 2, "01", 2, "00", 2, "00", 2, "05", 2, "01", 2 },
        { "02", 2, "02", 2, "11", 2, "00", 2, "00", 2, "05", 2, "01", 2, "05", 2, "01", 2 },
        { "02", 2, "02", 2, "11", 2, "12", 2, "09", 2, "07", 2, "14", 2, "0A", 2, "00", 2 },
        { "02", 2, "02", 2, "11", 2, "18", 2, "09", 2, "07", 2, "14", 2, "03", 2, "08", 2 },
        { "02", 2, "02", 2, "11", 2, "4E", 2, "63", 2, "0F", 2, "22", 2, "08", 2, "0B", 2 },
        { "02", 2, "02", 2, "11", 2, "04", 2, "1E", 2, "1E", 2, "04", 2, "01", 2, "01", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_ec_pt_t *P = NULL, *Q = NULL, *R = NULL;
    kryptos_ec_t *EC = NULL;
    kryptos_mp_value_t *p = NULL, *a = NULL, *b = NULL, *x1 = NULL, *y1 = NULL, *x2 = NULL, *y2 = NULL, *ex = NULL, *ey = NULL;

    for (t = 0; t < tv_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        CUTE_ASSERT(a != NULL);

        b = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        CUTE_ASSERT(b != NULL);

        p = kryptos_hex_value_as_mp(test_vector[t].p, test_vector[t].p_size);
        CUTE_ASSERT(p != NULL);

        x1 = kryptos_hex_value_as_mp(test_vector[t].x1, test_vector[t].x1_size);
        CUTE_ASSERT(x1 != NULL);

        y1 = kryptos_hex_value_as_mp(test_vector[t].y1, test_vector[t].y1_size);
        CUTE_ASSERT(y1 != NULL);

        x2 = kryptos_hex_value_as_mp(test_vector[t].x2, test_vector[t].x2_size);
        CUTE_ASSERT(x2 != NULL);

        y2 = kryptos_hex_value_as_mp(test_vector[t].y2, test_vector[t].y2_size);
        CUTE_ASSERT(y2 != NULL);

        ex = kryptos_hex_value_as_mp(test_vector[t].ex, test_vector[t].ex_size);
        CUTE_ASSERT(ex != NULL);

        ey = kryptos_hex_value_as_mp(test_vector[t].ey, test_vector[t].ey_size);
        CUTE_ASSERT(ey != NULL);

        CUTE_ASSERT(kryptos_ec_set_curve(&EC, a, b, p) == 1);

        CUTE_ASSERT(kryptos_ec_set_point(&P, x1, y1) == 1);

        CUTE_ASSERT(kryptos_ec_set_point(&Q, x2, y2) == 1);

        kryptos_ec_add(&R, P, Q, EC);

        CUTE_ASSERT(R != NULL);

        CUTE_ASSERT(kryptos_mp_eq(R->x, ex) == 1);
        CUTE_ASSERT(kryptos_mp_eq(R->y, ey) == 1);

        kryptos_ec_del_curve(EC);
        kryptos_ec_del_point(P);
        kryptos_ec_del_point(Q);
        kryptos_ec_del_point(R);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(x1);
        kryptos_del_mp_value(y1);
        kryptos_del_mp_value(x2);
        kryptos_del_mp_value(y2);
        kryptos_del_mp_value(ex);
        kryptos_del_mp_value(ey);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ec_mul_tests)
    struct test_ctx {
        kryptos_u8_t *a;
        size_t a_size;
        kryptos_u8_t *b;
        size_t b_size;
        kryptos_u8_t *p;
        size_t p_size;
        kryptos_u8_t *x;
        size_t x_size;
        kryptos_u8_t *y;
        size_t y_size;
        kryptos_u8_t *d;
        size_t d_size;
        kryptos_u8_t *ex;
        size_t ex_size;
        kryptos_u8_t *ey;
        size_t ey_size;
    };
    struct test_ctx test_vector[] = {
        { "02", 2, "02", 2, "11", 2, "02", 2, "02", 2, "00", 2, "00", 2, "00", 2 },
        { "02", 2, "02", 2, "11", 2, "04", 2, "1E", 2, "02", 2, "0D", 2, "05", 2 },
        { "02", 2, "02", 2, "11", 2, "04", 2, "1E", 2, "03", 2, "01", 2, "07", 2 },
        { "02", 2, "02", 2, "11", 2, "02", 2, "02", 2, "14", 2, "02", 2, "0F", 2 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_ec_pt_t *P = NULL, *R = NULL;
    kryptos_ec_t *EC = NULL;
    kryptos_mp_value_t *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL, *ex = NULL, *ey = NULL, *d = NULL;

    for (t = 0; t < tv_nr; t++) {
        a = kryptos_hex_value_as_mp(test_vector[t].a, test_vector[t].a_size);
        CUTE_ASSERT(a != NULL);

        b = kryptos_hex_value_as_mp(test_vector[t].b, test_vector[t].b_size);
        CUTE_ASSERT(b != NULL);

        p = kryptos_hex_value_as_mp(test_vector[t].p, test_vector[t].p_size);
        CUTE_ASSERT(p != NULL);

        x = kryptos_hex_value_as_mp(test_vector[t].x, test_vector[t].x_size);
        CUTE_ASSERT(x != NULL);

        y = kryptos_hex_value_as_mp(test_vector[t].y, test_vector[t].y_size);
        CUTE_ASSERT(y != NULL);

        d = kryptos_hex_value_as_mp(test_vector[t].d, test_vector[t].d_size);
        CUTE_ASSERT(d != NULL);

        ex = kryptos_hex_value_as_mp(test_vector[t].ex, test_vector[t].ex_size);
        CUTE_ASSERT(ex != NULL);

        ey = kryptos_hex_value_as_mp(test_vector[t].ey, test_vector[t].ey_size);
        CUTE_ASSERT(ey != NULL);

        CUTE_ASSERT(kryptos_ec_set_curve(&EC, a, b, p) == 1);

        CUTE_ASSERT(kryptos_ec_set_point(&P, x, y) == 1);

        kryptos_ec_mul(&R, P, d, EC);

        CUTE_ASSERT(R != NULL);

        CUTE_ASSERT(kryptos_mp_eq(R->x, ex) == 1);
        CUTE_ASSERT(kryptos_mp_eq(R->y, ey) == 1);

        kryptos_ec_del_curve(EC);
        kryptos_ec_del_point(P);
        kryptos_ec_del_point(R);

        kryptos_del_mp_value(a);
        kryptos_del_mp_value(b);
        kryptos_del_mp_value(p);
        kryptos_del_mp_value(x);
        kryptos_del_mp_value(y);
        kryptos_del_mp_value(d);
        kryptos_del_mp_value(ex);
        kryptos_del_mp_value(ey);
    }
CUTE_TEST_CASE_END
