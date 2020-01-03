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
            *p = NULL;
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
            *c = NULL;
        }
    }

    return done;
}

void kryptos_ec_add(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_ec_pt_t *q, kryptos_ec_t *curve) {
    kryptos_ec_pt_t p_mod, q_mod;
    kryptos_mp_value_t *temp1 = NULL, *_0 = NULL, *temp2 = NULL, *slope = NULL, *dq = NULL;
    kryptos_mp_value_t *factor = NULL, *md = NULL;
    size_t sh;
    int done = 0;

    // TIP(Rafael): Initializing p_mod = { NULL, NULL} would suggest compiler to use memset (at least Clang 3.8.0).
    //              We do not want it due to library hooking avoidance issues.
    p_mod.x = NULL;
    p_mod.y = NULL;
    q_mod.x = NULL;
    q_mod.y = NULL;

    *r = NULL;

#define kryptos_ec_pt_mod_p(pt, p, pt_rem) {\
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(pt_rem).x, (pt)->x), kryptos_ec_add_epilogue);\
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(pt_rem).y, (pt)->y), kryptos_ec_add_epilogue);\
    KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction((pt_rem).x, &factor, &sh, p), kryptos_ec_add_epilogue);\
    kryptos_del_mp_value((pt_rem).x);\
    (pt_rem).x = md;\
    md = NULL;\
    KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction((pt_rem).y, &factor, &sh, p), kryptos_ec_add_epilogue);\
    kryptos_del_mp_value((pt_rem).y);\
    (pt_rem).y = md;\
    md = NULL;\
}

    kryptos_ec_pt_mod_p(p, curve->p, p_mod);
    kryptos_del_mp_value(factor);
    factor = NULL;
    //printf("[add] P.x = "); kryptos_print_mp(p_mod.x);
    //printf("[add] P.y = "); kryptos_print_mp(p_mod.y);
    kryptos_ec_pt_mod_p(q, curve->p, q_mod);
    kryptos_del_mp_value(factor);
    factor = NULL;
    //printf("[add] Q.x = "); kryptos_print_mp(q_mod.x);
    //printf("[add] Q.y = "); kryptos_print_mp(q_mod.y);

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
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, curve->p), kryptos_ec_add_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&temp1, q_mod.y), kryptos_ec_add_epilogue);
        //printf("[add] Q.y = "); kryptos_print_mp(temp1);
        KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction(temp1, &factor, &sh, curve->p), kryptos_ec_add_epilogue);
        kryptos_del_mp_value(temp1);
        temp1 = md;
        md = NULL;
        //printf("[add] Q.y = "); kryptos_print_mp(temp1);
    } else {
        temp1 = kryptos_hex_value_as_mp("00", 2);
    }

    if (kryptos_mp_eq(p_mod.y, temp1) && kryptos_mp_eq(p_mod.x, q_mod.x)) {
        kryptos_ec_set_point(r, _0, _0);
        done = 1;
        goto kryptos_ec_add_epilogue;
    }

    if (kryptos_mp_eq(p_mod.x, q_mod.x) && kryptos_mp_eq(p_mod.y, q_mod.y)) {
        kryptos_ec_dbl(r, &p_mod, curve);
        done = (*r != NULL);
        goto kryptos_ec_add_epilogue;
    }

    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, p_mod.x), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&temp1, q_mod.x), kryptos_ec_add_epilogue);
    //printf("[add] temp = "); kryptos_print_mp(temp1);
    KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction(temp1, &factor, &sh, curve->p), kryptos_ec_add_epilogue);
    kryptos_del_mp_value(temp1);
    temp1 = md;
    md = NULL;
    KRYPTOS_EC_UTILS_DO_OR_DIE(temp1, kryptos_ec_add_epilogue);
    //printf("[add] temp = "); kryptos_print_mp(temp1);
    KRYPTOS_EC_UTILS_DO_OR_DIE(temp2 = kryptos_mp_modinv_rs(temp1, curve->p), kryptos_ec_add_epilogue);
    //printf("[add] temp = "); kryptos_print_mp(temp2);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, temp2), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&slope, p_mod.y), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&slope, q_mod.y), kryptos_ec_add_epilogue);
    //printf("[add] slope = "); kryptos_print_mp(slope);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&slope, temp1), kryptos_ec_add_epilogue);
    //printf("[add] slope = "); kryptos_print_mp(slope);
    kryptos_del_mp_value(temp2);
    temp2 = NULL;
    KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction(slope, &factor, &sh, curve->p), kryptos_ec_add_epilogue);
    kryptos_del_mp_value(slope);
    slope = md;
    md = NULL;
    //printf("[add] slope = "); kryptos_print_mp(slope);
    kryptos_ec_new_point(*r);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*r)->x, slope), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&(*r)->x, slope), kryptos_ec_add_epilogue);
    //printf("[add] R.x = "); kryptos_print_mp((*r)->x);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&(*r)->x, p_mod.x), kryptos_ec_add_epilogue);
    //printf("[add] R.x = "); kryptos_print_mp((*r)->x);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&(*r)->x, q_mod.x), kryptos_ec_add_epilogue);
    //printf("[add] R.x = "); kryptos_print_mp((*r)->x);
    KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction((*r)->x, &factor, &sh, curve->p), kryptos_ec_add_epilogue);
    kryptos_del_mp_value((*r)->x);
    (*r)->x = md;
    md = NULL;
    //printf("[add] R.x = "); kryptos_print_mp((*r)->x);
    kryptos_del_mp_value(temp1);
    temp1 = NULL;
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, p_mod.x), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&temp1, (*r)->x), kryptos_ec_add_epilogue);
    //printf("[add] temp = "); kryptos_print_mp(temp1);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*r)->y, temp1), kryptos_ec_add_epilogue);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&(*r)->y, slope), kryptos_ec_add_epilogue);
    //printf("[add] R.y = "); kryptos_print_mp((*r)->y);
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&(*r)->y, p_mod.y), kryptos_ec_add_epilogue);
    //printf("[add] R.y = "); kryptos_print_mp((*r)->y);
    KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction((*r)->y, &factor, &sh, curve->p), kryptos_ec_add_epilogue);
    kryptos_del_mp_value((*r)->y);
    (*r)->y = md;
    md = NULL;
    KRYPTOS_EC_UTILS_DO_OR_DIE((*r)->y, kryptos_ec_add_epilogue);
    //printf("[add] R.y = "); kryptos_print_mp((*r)->y);

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

    if (md != NULL) {
        kryptos_del_mp_value(md);
    }

    if (factor != NULL) {
        kryptos_del_mp_value(factor);
    }

    sh = 0;

    if (!done) {
        kryptos_ec_del_point(*r);
        *r = NULL;
    }
}

void kryptos_ec_dbl(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_ec_t *curve) {
    kryptos_mp_value_t *slope = NULL, *temp1 = NULL, *temp2 = NULL, *_0 = NULL, *q = NULL;
    kryptos_mp_value_t *factor = NULL, *md = NULL;
    size_t sh;
    int done = 0;

    *r = NULL;
    KRYPTOS_EC_UTILS_DO_OR_DIE(_0 = kryptos_hex_value_as_mp("00", 2), kryptos_ec_dbl_epilogue);

    if (kryptos_mp_eq(p->y, _0)) {
        kryptos_ec_set_point(r, _0, _0);
    } else {
        KRYPTOS_EC_UTILS_DO_OR_DIE(temp1 = kryptos_hex_value_as_mp("02", 2), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&temp1, p->y), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(temp2 = kryptos_mp_modinv_rs(temp1, curve->p), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] temp = "); kryptos_print_mp(temp2);
        kryptos_del_mp_value(temp1);
        temp1 = temp2;
        temp2 = NULL;
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&slope, p->x), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&slope, p->x), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] slope = "); kryptos_print_mp(slope);
        KRYPTOS_EC_UTILS_DO_OR_DIE(temp2 = kryptos_hex_value_as_mp("03", 2), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&temp2, slope), kryptos_ec_dbl_epilogue);
        kryptos_del_mp_value(slope);
        slope = temp2;
        temp2 = NULL;
        //printf("\t[dbl] slope = "); kryptos_print_mp(slope);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_add_s(&slope, curve->a), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] slope = "); kryptos_print_mp(slope);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&slope, temp1), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] slope = "); kryptos_print_mp(slope);
        KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction(slope, &factor, &sh, curve->p), kryptos_ec_dbl_epilogue);
        kryptos_del_mp_value(slope);
        slope = md;
        md = NULL;
        //printf("\t[dbl] slope = "); kryptos_print_mp(slope);
        kryptos_ec_new_point(*r);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*r)->x, slope), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&(*r)->x, slope), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] R.x = "); kryptos_print_mp((*r)->x);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&(*r)->x, p->x), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] R.x = "); kryptos_print_mp((*r)->x);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&(*r)->x, p->x), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] R.x = "); kryptos_print_mp((*r)->x);
        KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction((*r)->x, &factor, &sh, curve->p), kryptos_ec_dbl_epilogue);
        kryptos_del_mp_value((*r)->x);
        (*r)->x = md;
        md = NULL;
        //printf("\t[dbl] R.x = "); kryptos_print_mp((*r)->x);
        kryptos_del_mp_value(temp1);
        temp1 = NULL;
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&temp1, p->x), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&temp1, (*r)->x), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] temp = "); kryptos_print_mp(temp1);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*r)->y, slope), kryptos_ec_dbl_epilogue);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_mul_s(&(*r)->y, temp1), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] R.y = "); kryptos_print_mp((*r)->y);
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_mp_sub_s(&(*r)->y, p->y), kryptos_ec_dbl_epilogue);
        //printf("\t[dbl] R.y = "); kryptos_print_mp((*r)->y);
        KRYPTOS_EC_UTILS_DO_OR_DIE(md = kryptos_mp_barrett_reduction((*r)->y, &factor, &sh, curve->p), kryptos_ec_dbl_epilogue);
        kryptos_del_mp_value((*r)->y);
        (*r)->y = md;
        md = NULL;
        //printf("\t[dbl] R.y = "); kryptos_print_mp((*r)->y);
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

    if (factor != NULL) {
        kryptos_del_mp_value(factor);
    }

    if (md != NULL) {
        kryptos_del_mp_value(md);
    }

    sh = 0;

    if (!done) {
        kryptos_ec_del_point(*r);
        *r = NULL;
    }
}

void kryptos_ec_mul(kryptos_ec_pt_t **r, kryptos_ec_pt_t *p, kryptos_mp_value_t *d, kryptos_ec_t *curve) {
    kryptos_ec_pt_t q, *t = NULL;
    kryptos_mp_value_t *_0 = NULL;
    int done = 0;
    kryptos_u8_t *bitmap = NULL, *bp = NULL, *bp_end = NULL;
    size_t bitmap_size = 0;

    // TIP(Rafael): q = { NULL, NULL } would suggest compiler to use memset (at least Clang 3.8.0).
    //              We do not want it due to library hooking avoidance issues.
    q.x = NULL;
    q.y = NULL;

    *r = NULL;

    KRYPTOS_EC_UTILS_DO_OR_DIE(_0 = kryptos_hex_value_as_mp("00", 2), kryptos_ec_mul_epilogue);

    if ((done = kryptos_mp_eq(d, _0)) != 0) {
        kryptos_ec_set_point(r, _0, _0);
        goto kryptos_ec_mul_epilogue;
    }

    bitmap = kryptos_mp_get_bitmap(d, &bitmap_size);
    KRYPTOS_EC_UTILS_DO_OR_DIE(bitmap, kryptos_ec_mul_epilogue);

    bp = bitmap;
    bp_end = bp + bitmap_size - 1;

    while (bp != bp_end && *bp != 1) {
        bp++;
    }

    kryptos_assign_mp_value(&q.x, p->x);
    kryptos_assign_mp_value(&q.y, p->y);

    if (*bp_end == 0) {
        kryptos_ec_set_point(r, _0, _0);
    } else {
        kryptos_ec_set_point(r, p->x, p->y);
    }

    kryptos_del_mp_value(_0);
    _0 = NULL;

#define kryptos_ec_mul_step(r, t, q, bit, curve) {\
    kryptos_ec_dbl(&(t), &(q), (curve));\
    /*printf("[mul/dbl] Q.x = "); kryptos_print_mp((q).x);*/\
    /*printf("[mul/dbl] Q.y = "); kryptos_print_mp((q).y);*/\
    /*printf("[mul/dbl] T.x = "); kryptos_print_mp((t)->x);*/\
    /*printf("[mul/dbl] T.y = "); kryptos_print_mp((t)->y);*/\
    KRYPTOS_EC_UTILS_DO_OR_DIE((t), kryptos_ec_mul_epilogue);\
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(q).x, (t)->x), kryptos_ec_mul_epilogue);\
    KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(q).y, (t)->y), kryptos_ec_mul_epilogue);\
    kryptos_ec_del_point((t));\
    (t) = NULL;\
    if (bit) {\
        /*printf("[mul/add] R.x = "); kryptos_print_mp((*(r))->x);*/\
        /*printf("[mul/add] R.y = "); kryptos_print_mp((*(r))->y);*/\
        /*printf("[mul/add] Q.x = "); kryptos_print_mp((q).x);*/\
        /*printf("[mul/add] Q.y = "); kryptos_print_mp((q).y);*/\
        kryptos_ec_add(&(t), *(r), &(q), (curve));\
        KRYPTOS_EC_UTILS_DO_OR_DIE(t, kryptos_ec_mul_epilogue);\
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*(r))->x, (t)->x), kryptos_ec_mul_epilogue);\
        KRYPTOS_EC_UTILS_DO_OR_DIE(kryptos_assign_mp_value(&(*(r))->y, (t)->y), kryptos_ec_mul_epilogue);\
        /*printf("[mul/add] R.x = "); kryptos_print_mp((*(r))->x);*/\
        /*printf("[mul/add] R.y = "); kryptos_print_mp((*(r))->y);*/\
        kryptos_ec_del_point((t));\
        (t) = NULL;\
    }\
}

    bp_end -= 1;

    do {
        kryptos_ec_mul_step(r, t, q, *bp_end, curve);
        bp_end--;
    } while (bp_end >= bp);

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

    if (bitmap != NULL) {
        kryptos_freeseg(bitmap, bitmap_size);
        bp = bp_end = NULL;
        bitmap_size = 0;
    }

    if (!done) {
        kryptos_ec_del_point(*r);
        *r = NULL;
    }
}

#undef kryptos_ec_new_point

#undef kryptos_ec_new_curve

#undef KRYPTOS_EC_UTILS_DO_OR_DIE
