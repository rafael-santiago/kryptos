/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_ec_utils.h>
#include <kryptos_mp.h>
#include <kryptos_memory.h>
#include <stdio.h>

#define KRYPTOS_EC_UTILS_DO_OR_DIE(stmt, escape_label) {\
    if ((stmt) == NULL) {\
        goto escape_label;\
    }\
}

#define kryptos_ec_new_point(p) {\
    if (((p) = (kryptos_ec_pt_t *) kryptos_newseg(sizeof(kryptos_ec_pt_t))) != NULL) {\
        (p)->x = (p)->y = NULL;\
    }\
}

#define kryptos_ec_new_curve(c) {\
    if (((c) = (kryptos_ec_t *) kryptos_newseg(sizeof(kryptos_ec_t))) != NULL) {\
        (c)->a = (c)->b = (c)->p = NULL;\
    }\
}

int kryptos_ec_set_point(kryptos_ec_pt_t **p, kryptos_mp_value_t *x, kryptos_mp_value_t *y) {
    int done = 0;

    kryptos_ec_new_point(*p);

    done = (*p != NULL);

    if (done) {
        done = (kryptos_assign_mp_value(&(*p)->x, x) != NULL);

        if (done) {
            done = (kryptos_assign_mp_value(&(*p)->y, y) != NULL);
        }

        if (!done) {
            kryptos_ec_del_point(*p);
        }
    }

    return done;
}

int kryptos_ec_set_curve(kryptos_ec_t **c, kryptos_mp_value_t *a, kryptos_mp_value_t *b, kryptos_mp_value_t *p) {
    int done = 0;

    kryptos_ec_new_curve(*c);

    done = (*c != NULL);

    if (done) {
        if ((done = (kryptos_assign_mp_value(&(*c)->a, a) != NULL)) != 0) {
            if ((done = (kryptos_assign_mp_value(&(*c)->b, b) != NULL)) != 0) {
                done = (kryptos_assign_mp_value(&(*c)->p, p) != NULL);
            }
        }

        if (!done) {
            kryptos_ec_del_curve(*c);
        }
    }

    return done;
}

void kryptos_ec_add(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_ec_pt_t *q, kryptos_ec_t *curve) {
    kryptos_ec_pt_t p_mod = { NULL, NULL }, q_mod = { NULL, NULL };
    kryptos_mp_value_t *temp1 = NULL, *_0 = NULL, *temp2 = NULL, *slope = NULL, *dq = NULL;
    int done = 0;

    *r = NULL;

#define kryptos_ec_pt_mod_p(pt, p, pt_rem, temp) {\
    KRYPTOS_EC_UTILS_DO_OR_DIE((temp) = kryptos_mp_div((pt)->x, (p), &(pt_rem).x), kryptos_ec_add_epilogue);\
    kryptos_del_mp_value((temp));\
    (temp) = NULL;\
    KRYPTOS_EC_UTILS_DO_OR_DIE((temp) = kryptos_mp_div((pt)->y, (p), &(pt_rem).y), kryptos_ec_add_epilogue);\
    kryptos_del_mp_value((temp));\
    (temp) = NULL;\
}

    kryptos_ec_pt_mod_p(p, curve->p, p_mod, temp1);
    kryptos_ec_pt_mod_p(q, curve->p, q_mod, temp1);

#undef kryptos_ec_pt_mod_p

    if ((_0 = kryptos_hex_value_as_mp("00", 2)) == NULL) {
        goto kryptos_ec_add_epilogue;
    }

    if (kryptos_mp_eq(p_mod.x, _0) && kryptos_mp_eq(p_mod.y, _0)) {
        kryptos_ec_set_point(r, q_mod.x, q_mod.y);
        done = 1;
        goto kryptos_ec_add_epilogue;
    }

    if (kryptos_mp_eq(q_mod.x, _0) && kryptos_mp_eq(q_mod.y, _0)) {
        kryptos_ec_set_point(r, p_mod.x, p_mod.y);
        done  = 1;
        goto kryptos_ec_add_epilogue;
    }

    if (!kryptos_mp_eq(q_mod.y, _0)) {
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, q_mod.y), kryptos_ec_add_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&temp1, curve->p), kryptos_ec_add_epilogue);
        printf("TEMP1 = "); kryptos_print_mp(temp1); printf("\n");
        kryptos_mp_mod(&temp1, curve->p);
        printf("TEMP1' = "); kryptos_print_mp(temp1); printf("\n");
        KRYPTOS_EC_UTILS_DO_OR_DIE(temp1, kryptos_ec_add_epilogue);
        //KRYPTOS_EC_UTILS_DO_OR_DIE((dq = kryptos_mp_div(temp1, curve->p, &temp2)), kryptos_ec_add_epilogue);
        //kryptos_del_mp_value(dq);
        //dq = NULL;
        //KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, temp2), kryptos_ec_add_epilogue);
        //kryptos_del_mp_value(temp2);
        //temp2 = NULL;
    } else {
        temp1 = kryptos_hex_value_as_mp("00", 2);
    }

    if (kryptos_mp_eq(p_mod.y, temp1) && kryptos_mp_eq(p_mod.x, q_mod.x)) {
        kryptos_ec_set_point(r, _0, _0);
        done = 1;
        goto kryptos_ec_add_epilogue;
    }

    if (kryptos_mp_eq(p_mod.x, q_mod.x) && kryptos_mp_eq(p_mod.y, q_mod.y)) {
        printf("booooooo!\n");
        kryptos_ec_dbl(r, &p_mod, curve);
        done = (*r != NULL);
        goto kryptos_ec_add_epilogue;
    }

    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, p_mod.x), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&temp1, q_mod.x), kryptos_ec_add_epilogue);
    kryptos_mp_mod(&temp1, curve->p);
    KRYPTOS_EC_UTILS_DO_OR_DIE(temp1, kryptos_ec_add_epilogue);
    //KRYPTOS_EC_UTILS_DO_OR_DIE((dq = kryptos_mp_div(temp1, curve->p, &temp2)), kryptos_ec_add_epilogue);
    //kryptos_del_mp_value(dq);
    //dq = NULL;
    //KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, temp2), kryptos_ec_add_epilogue);
    //kryptos_del_mp_value(temp2);
    KRYPTOS_EC_UTILS_DO_OR_DIE(temp2 = kryptos_mp_modinv(temp1, curve->p), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, temp2), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&slope, p_mod.y), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&slope, q_mod.y), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&slope, temp1), kryptos_ec_add_epilogue);
    kryptos_del_mp_value(temp2);
    temp2 = NULL;
    kryptos_mp_mod(&slope, curve->p);
    KRYPTOS_EC_UTILS_DO_OR_DIE(slope, kryptos_ec_add_epilogue);
    //KRYPTOS_EC_UTILS_DO_OR_DIE((dq = kryptos_mp_div(slope, curve->p, &temp2)), kryptos_ec_add_epilogue);
    //kryptos_del_mp_value(dq);
    //dq = NULL;
    //KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&slope, temp2), kryptos_ec_add_epilogue);
    //kryptos_del_mp_value(temp2);
    //temp2 = NULL;
    kryptos_ec_new_point(*r);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*r)->x, slope), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&(*r)->x, slope), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&(*r)->x, p_mod.x), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&(*r)->x, q_mod.x), kryptos_ec_add_epilogue);
    kryptos_mp_mod(&(*r)->x, curve->p);
    KRYPTOS_EC_UTILS_DO_OR_DIE((*r)->x, kryptos_ec_add_epilogue);
    //temp2 = (*r)->x;
    //(*r)->x = NULL;
    //KRYPTOS_EC_UTILS_DO_OR_DIE((dq = kryptos_mp_div(temp2, curve->p, &(*r)->x)), kryptos_ec_add_epilogue);
    //kryptos_del_mp_value(dq);
    //dq = NULL;
    kryptos_del_mp_value(temp1);
    temp1 = NULL;
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, p_mod.x), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&temp1, (*r)->x), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*r)->y, temp1), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&(*r)->y, slope), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&(*r)->y, p_mod.y), kryptos_ec_add_epilogue);
    kryptos_mp_mod(&(*r)->y, curve->p);
    KRYPTOS_EC_UTILS_DO_OR_DIE((*r)->y, kryptos_ec_add_epilogue);
    //kryptos_del_mp_value(temp1);
    //temp1 = (*r)->y;
    //(*r)->y = NULL;
    //KRYPTOS_EC_UTILS_DO_OR_DIE((dq = kryptos_mp_div(temp1, curve->p, &(*r)->y)), kryptos_ec_add_epilogue);
    //kryptos_del_mp_value(dq);
    //dq = NULL;

    done = 1;

kryptos_ec_add_epilogue:

    if (temp1 != NULL) {
        kryptos_del_mp_value(temp1);
    }

    if (temp2 != NULL) {
        kryptos_del_mp_value(temp2);
    }

    if (slope != NULL) {
        kryptos_del_mp_value(slope);
    }

    if (p_mod.x != NULL) {
        kryptos_del_mp_value(p_mod.x);
    }

    if (p_mod.y != NULL) {
        kryptos_del_mp_value(p_mod.y);
    }

    if (q_mod.x != NULL) {
        kryptos_del_mp_value(q_mod.x);
    }

    if (q_mod.y != NULL) {
        kryptos_del_mp_value(q_mod.y);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    if (dq != NULL) {
        kryptos_del_mp_value(dq);
    }

    if (!done) {
        kryptos_ec_del_point(*r);
    }
}

void kryptos_ec_dbl(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_ec_t *curve) {
    kryptos_mp_value_t *slope = NULL, *temp1 = NULL, *temp2 = NULL, *_0 = NULL, *q = NULL;
    int done = 0;

    *r = NULL;

    KRYPTOS_EC_UTILS_DO_OR_DIE(_0 = kryptos_hex_value_as_mp("00", 2), kryptos_ec_dbl_epilogue);

    if (kryptos_mp_eq(p->y, _0)) {
        kryptos_ec_set_point(r, _0, _0);
    } else {
        KRYPTOS_EC_UTILS_DO_OR_DIE(temp1 = kryptos_hex_value_as_mp("02", 2), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&temp1, p->y), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(temp2 = kryptos_mp_modinv(temp1, curve->p), kryptos_ec_dbl_epilogue);
        kryptos_del_mp_value(temp1);
        temp1 = temp2;
        printf("INV = "); kryptos_print_mp(temp1); printf("\n");
        temp2 = NULL;
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&slope, p->x), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&slope, p->x), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(temp2 = kryptos_hex_value_as_mp("03", 2), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&temp2, slope), kryptos_ec_dbl_epilogue);
        kryptos_del_mp_value(slope);
        slope = temp2;
        temp2 = NULL;
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_add(&slope, curve->a), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&slope, temp1), kryptos_ec_dbl_epilogue);
        kryptos_mp_mod(&slope, curve->p);
        //KRYPTOS_EC_UTILS_DO_OR_DIE((q = kryptos_mp_div(slope, curve->p, &temp2)), kryptos_ec_dbl_epilogue);
        //kryptos_del_mp_value(q);
        //q = NULL;
        //kryptos_del_mp_value(slope);
        //slope = temp2;
        //temp2 = NULL;
        kryptos_ec_new_point(*r);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*r)->x, slope), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&(*r)->x, slope), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&(*r)->x, p->x), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&(*r)->x, p->x), kryptos_ec_dbl_epilogue);
        kryptos_mp_mod(&(*r)->x, curve->p);
        //temp2 = (*r)->x;
        //(*r)->x = NULL;
        //KRYPTOS_EC_UTILS_DO_OR_DIE((q = kryptos_mp_div(temp2, curve->p, &(*r)->x)), kryptos_ec_dbl_epilogue);
        //printf("TEMP2 = "); kryptos_print_mp(temp2); printf("\n");
        //printf("P = "); kryptos_print_mp(curve->p); printf("\n");
        //printf("R->x = "); kryptos_print_mp((*r)->x); printf("\n");
        //kryptos_del_mp_value(q);
        //q = NULL;
        kryptos_del_mp_value(temp1);
        temp1 = NULL;
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, p->x), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&temp1, (*r)->x), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*r)->y, slope), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul(&(*r)->y, temp1), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub(&(*r)->y, p->y), kryptos_ec_dbl_epilogue);
        kryptos_mp_mod(&(*r)->y, curve->p);
        //kryptos_del_mp_value(temp1);
        //temp1 = (*r)->y;
        //(*r)->y = NULL;
        //KRYPTOS_EC_UTILS_DO_OR_DIE((q = kryptos_mp_div(curve->p, temp1, &(*r)->y)), kryptos_ec_dbl_epilogue);
        //printf("R->y = "); kryptos_print_mp((*r)->y); printf("\n");
        //kryptos_del_mp_value(q);
        //q = NULL;
    }

    done = 1;

kryptos_ec_dbl_epilogue:

    if (slope != NULL) {
        kryptos_del_mp_value(slope);
    }

    if (temp1 != NULL) {
        kryptos_del_mp_value(temp1);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (!done) {
        kryptos_ec_del_point(*r);
    }
}

void kryptos_ec_mul(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_mp_value_t *d, kryptos_ec_t *curve) {
    kryptos_ec_pt_t q = { NULL, NULL }, *t = NULL;
    kryptos_mp_value_t *_0 = NULL;
    ssize_t w;
    int done = 0;

    *r = NULL;

    KRYPTOS_EC_UTILS_DO_OR_DIE(_0 = kryptos_hex_value_as_mp("00", 2), kryptos_ec_mul_epilogue);

    if ((done = kryptos_mp_eq(d, _0)) != 0) {
        kryptos_ec_set_point(r, _0, _0);
        goto kryptos_ec_mul_epilogue;
    }

    kryptos_assign_mp_value(&q.x, p->x);
    kryptos_assign_mp_value(&q.y, p->y);

#define kryptos_ec_mul_step(r, t, q, d, w, bit, curve) {\
    if ((w) == 0 && (bit) == 0) {\
        continue;\
    }\
    kryptos_ec_dbl(&(t), &(q), (curve));\
    KRYPTOS_EC_UTILS_DO_OR_DIE((t), kryptos_ec_mul_epilogue);\
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(q).x, (t)->x), kryptos_ec_mul_epilogue);\
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(q).y, (t)->y), kryptos_ec_mul_epilogue);\
    kryptos_ec_del_point((t));\
    (t) = NULL;\
    if (( ((d)->data[w] & (1 << (bit))) >> (bit) )) {\
        kryptos_ec_add(&(t), &(q), *(r), (curve));\
        KRYPTOS_EC_UTILS_DO_OR_DIE(t, kryptos_ec_mul_epilogue);\
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*(r))->x, (t)->x), kryptos_ec_mul_epilogue);\
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*(r))->y, (t)->y), kryptos_ec_mul_epilogue);\
        kryptos_ec_del_point((t));\
        (t) = NULL;\
    }\
}

    if (!(d->data[0] & 0x1)) {
        kryptos_ec_set_point(r, _0, _0);
    } else {
        kryptos_ec_set_point(r, p->x, p->y);
    }

    for (w = d->data_size - 1; w >= 0; w--) {
#ifdef KRYPTOS_MP_U32_DIGIT
        kryptos_ec_mul_step(r, t, q, d, w, 31, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 30, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 29, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 28, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 27, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 26, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 25, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 24, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 23, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 22, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 21, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 20, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 19, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 18, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 17, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 16, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 15, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 14, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 13, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 12, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 11, curve);
        kryptos_ec_mul_step(r, t, q, d, w, 10, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  9, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  8, curve);
#endif
        kryptos_ec_mul_step(r, t, q, d, w,  7, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  6, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  5, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  4, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  3, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  2, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  1, curve);
        kryptos_ec_mul_step(r, t, q, d, w,  0, curve);
    }

#undef kryptos_ec_mul_step

    done = 1;

kryptos_ec_mul_epilogue:

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    if (t != NULL) {
        kryptos_ec_del_point(t);
    }

    if (q.x != NULL) {
        kryptos_del_mp_value(q.x);
    }

    if (q.y != NULL) {
        kryptos_del_mp_value(q.y);
    }

    if (!done) {
        kryptos_ec_del_point(*r);
    }
}

#undef kryptos_ec_new_point

#undef kryptos_ec_new_curve

#undef KRYPTOS_EC_UTILS_DO_OR_DIE