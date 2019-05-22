/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_EC_UTILS_H
#define KRYPTOS_KRYPTOS_EC_UTILS_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define kryptos_ec_del_point(p) {\
    if ((p) != NULL) {\
        kryptos_del_mp_value((p)->x);\
        kryptos_del_mp_value((p)->y);\
        kryptos_freeseg((p), sizeof(kryptos_ec_pt_t));\
        (p) = NULL;\
    }\
}

#define kryptos_ec_del_curve(c) {\
    if ((c) != NULL) {\
        kryptos_del_mp_value((c)->a);\
        kryptos_del_mp_value((c)->b);\
        kryptos_del_mp_value((c)->p);\
        kryptos_freeseg((c), sizeof(kryptos_ec_t));\
        (c) = NULL;\
    }\
}

int kryptos_ec_set_point(kryptos_ec_pt_t **p, kryptos_mp_value_t *x, kryptos_mp_value_t *y);

int kryptos_ec_set_curve(kryptos_ec_t **c, kryptos_mp_value_t *a, kryptos_mp_value_t *b, kryptos_mp_value_t *p);

void kryptos_ec_add(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_ec_pt_t *q, kryptos_ec_t *curve);

void kryptos_ec_dbl(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_ec_t *curve);

void kryptos_ec_mul(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_ec_pt_t *q, kryptos_ec_t *curve);

#ifdef __cplusplus
}
#endif

#endif
