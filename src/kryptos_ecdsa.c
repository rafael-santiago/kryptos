/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_ecdsa.h>
#include <kryptos_memory.h>
#include <kryptos_ec_utils.h>
#include <kryptos_mp.h>
#include <kryptos_random.h>
#include <kryptos_pem.h>
#include <kryptos.h>

static kryptos_task_result_t kryptos_ecdsa_get_random_d(kryptos_mp_value_t **d, const kryptos_mp_value_t *q,
                                                        const size_t bits);

kryptos_task_result_t kryptos_ecdsa_mk_key_pair(const kryptos_curve_ctx *e,
                                                kryptos_u8_t **k_pub, size_t *k_pub_size,
                                                kryptos_u8_t **k_priv, size_t *k_priv_size) {
    kryptos_task_result_t result = kKryptosProcessError;
    kryptos_ec_pt_t *b = NULL;
    kryptos_mp_value_t *d = NULL;

    if (e == NULL || k_pub == NULL || k_pub_size == NULL || k_priv == NULL || k_priv_size == NULL) {
        return kKryptosInvalidParams;
    }

    if ((result = kryptos_ecdsa_get_random_d(&d, e->q, e->bits)) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    kryptos_ec_mul(&b, e->g, d, e->ec);

    if (b == NULL) {
        result = kKryptosProcessError;
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    // INFO(Rafael): Exporting the public parameters.

    if ((result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_P,
                                       (kryptos_u8_t *)e->ec->p->data,
                                       e->ec->p->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_A,
                                       (kryptos_u8_t *)e->ec->a->data,
                                       e->ec->a->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_B,
                                       (kryptos_u8_t *)e->ec->b->data,
                                       e->ec->b->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_Q,
                                       (kryptos_u8_t *)e->q->data,
                                       e->q->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_AX,
                                       (kryptos_u8_t *)e->g->x->data,
                                       e->g->x->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_AY,
                                       (kryptos_u8_t *)e->g->y->data,
                                       e->g->y->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_BX,
                                       (kryptos_u8_t *)b->x->data,
                                       b->x->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_BY,
                                       (kryptos_u8_t *)b->y->data,
                                       b->y->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    // INFO(Rafael): Exporting the private parameter (for the sake of convenience, excepting point B(x,y), let's include
    //                                                the public parameters into the private buffer too).

    if ((result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_D,
                                       (kryptos_u8_t *)d->data,
                                       d->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_P,
                                       (kryptos_u8_t *)e->ec->p->data,
                                       e->ec->p->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_A,
                                       (kryptos_u8_t *)e->ec->a->data,
                                       e->ec->a->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_B,
                                       (kryptos_u8_t *)e->ec->b->data,
                                       e->ec->b->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_Q,
                                       (kryptos_u8_t *)e->q->data,
                                       e->q->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_AX,
                                       (kryptos_u8_t *)e->g->x->data,
                                       e->g->x->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

    if ((result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ECDSA_PEM_HDR_PARAM_AY,
                                       (kryptos_u8_t *)e->g->y->data,
                                       e->g->y->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        goto kryptos_ecdsa_mk_key_pair_epilogue;
    }

kryptos_ecdsa_mk_key_pair_epilogue:

    if (result != kKryptosSuccess && (*k_pub) != NULL) {
        kryptos_freeseg(*k_pub, *k_pub_size);
        *k_pub = NULL;
        *k_pub_size = 0;
    }

    if (result != kKryptosSuccess && (*k_priv) != NULL) {
        kryptos_freeseg(*k_priv, *k_priv_size);
        *k_priv = NULL;
        *k_priv_size = 0;
    }

    if (b != NULL) {
        kryptos_ec_del_point(b);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    return result;
}

void kryptos_ecdsa_sign(kryptos_task_ctx **ktask) {
    kryptos_curve_ctx e;
    kryptos_mp_value_t *x = NULL, *y = NULL, *a = NULL, *b = NULL, *p = NULL, *d = NULL, *ke = NULL, *ke_inv = NULL;
    kryptos_ec_pt_t *r = NULL;
    kryptos_hash_func hash;
    kryptos_hash_size_func hash_size;
    kryptos_task_ctx htsk, *htask = &htsk;

    if (ktask == NULL) {
        return;
    }

    e.ec = NULL;
    e.g  = NULL;
    e.q  = NULL;

    kryptos_task_init_as_null(htask);

    if ((*ktask)->in == NULL || (*ktask)->in_size == 0 || (*ktask)->key == NULL || (*ktask)->key_size == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid parameters.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if ((*ktask)->arg[0] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Null hash function.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if ((*ktask)->arg[1] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Null hash size function.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    hash = (kryptos_hash_func)(*ktask)->arg[0];
    hash_size = (kryptos_hash_size_func)(*ktask)->arg[1];

    // INFO(Rafael): Loading the private parameter d.

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_D,
                                                    (*ktask)->key, (*ktask)->key_size, &d)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get d.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    // INFO(Rafael): Loading the remaining public parameters.

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_P,
                                                    (*ktask)->key, (*ktask)->key_size, &p)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get p.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    e.bits = kryptos_mp_byte2bit(p->data_size);

    if ((hash_size() << 3) < e.bits) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "The hash is too short.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_A,
                                                    (*ktask)->key, (*ktask)->key_size, &a)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get a.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_B,
                                                    (*ktask)->key, (*ktask)->key_size, &b)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get b.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (!kryptos_ec_set_curve(&e.ec, a, b, p)) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set elliptic curve.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_Q,
                                                    (*ktask)->key, (*ktask)->key_size, &e.q)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get q.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_AX,
                                                    (*ktask)->key, (*ktask)->key_size, &x)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get a->x.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_AY,
                                                    (*ktask)->key, (*ktask)->key_size, &y)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get a->y.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (!kryptos_ec_set_point(&e.g, x, y)) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set elliptic curve point.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    // INFO(Rafael): Now signing...

    if (((*ktask)->result = kryptos_ecdsa_get_random_d(&ke, e.q, e.bits)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get a random ke.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    kryptos_ec_mul(&r, e.g, ke, e.ec);

    if (r == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error on point multiplying.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if ((ke_inv = kryptos_mp_modinv(ke, e.q)) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating the ke inverse.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    kryptos_mp_mul(&d, r->x);

    htask->in = (*ktask)->in;
    htask->in_size = (*ktask)->in_size;
    hash(&htask, 0);

    if (htask->result != kKryptosSuccess || htask->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while computing hash.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    kryptos_del_mp_value(x);
    x = kryptos_raw_buffer_as_mp(htask->out, htask->out_size);

    if (x == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while parsing hash output.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (kryptos_mp_add(&x, d) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating x + d.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (kryptos_mp_mul(&x, ke_inv) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating x * ke_inv.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (!kryptos_mp_mod(&x, e.q)) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating x mod q.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    // INFO(Rafael): We need to export ktask->in, r->x and the signature in x.

    if (((*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                                 KRYPTOS_ECDSA_PEM_HDR_PARAM_X,
                                                 (kryptos_u8_t *)(*ktask)->in,
                                                 (*ktask)->in_size)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting signature data.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                                 KRYPTOS_ECDSA_PEM_HDR_PARAM_R,
                                                 (kryptos_u8_t *)r->x->data,
                                                 r->x->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting signature data.";
        goto kryptos_ecdsa_sign_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                                 KRYPTOS_ECDSA_PEM_HDR_PARAM_S,
                                                 (kryptos_u8_t *)x->data,
                                                 x->data_size * sizeof(kryptos_mp_digit_t))) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting signature data.";
    }

kryptos_ecdsa_sign_epilogue:

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (ke != NULL) {
        kryptos_del_mp_value(ke);
    }

    if (ke_inv != NULL) {
        kryptos_del_mp_value(ke_inv);
    }

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (r != NULL) {
        kryptos_ec_del_point(r);
    }

    if (e.ec != NULL) {
        kryptos_ec_del_curve(e.ec);
    }

    if (e.g != NULL) {
        kryptos_ec_del_point(e.g);
    }

    if (e.q != NULL) {
        kryptos_del_mp_value(e.q);
    }

    kryptos_task_free(htask, KRYPTOS_TASK_OUT);
}

void kryptos_ecdsa_verify(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *s = NULL, *s_inv = NULL, *u1 = NULL, *u2 = NULL, *r = NULL;
    kryptos_mp_value_t *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL;
    kryptos_curve_ctx e;
    kryptos_ec_pt_t *B = NULL, *A = NULL, *P = NULL, *BP = NULL, *AP = NULL;
    kryptos_hash_func hash;
    kryptos_hash_size_func hash_size;
    kryptos_task_ctx htsk, *htask = &htsk;

    if (ktask == NULL) {
        return;
    }

    e.ec = NULL;
    e.g  = NULL;
    e.q  = NULL;

    (*ktask)->out = NULL;
    (*ktask)->out_size = 0;

    if ((*ktask)->arg[0] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Null hash function.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if ((*ktask)->arg[1] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Null hash size function.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    hash = (kryptos_hash_func)(*ktask)->arg[0];
    hash_size = (kryptos_hash_size_func)(*ktask)->arg[1];

    if ((*ktask)->in == NULL || (*ktask)->in_size == 0 || (*ktask)->key == NULL || (*ktask)->key_size == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid parameters.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    // INFO(Rafael): All boring code of parsing the key to get all public parameters.

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_P,
                                                    (*ktask)->key, (*ktask)->key_size, &p)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get p.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_A,
                                                    (*ktask)->key, (*ktask)->key_size, &a)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get a.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_B,
                                                    (*ktask)->key, (*ktask)->key_size, &b)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get b.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (!kryptos_ec_set_curve(&e.ec, a, b, p)) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set elliptic curve.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    e.bits = kryptos_mp_byte2bit(p->data_size);

    if ((hash_size() << 3) < e.bits) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "The hash is too short.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_Q,
                                                    (*ktask)->key, (*ktask)->key_size, &e.q)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get q.";
        goto kryptos_ecdsa_verify_epilogue;
    }


    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_AX,
                                                    (*ktask)->key, (*ktask)->key_size, &x)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get a->x.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_AY,
                                                    (*ktask)->key, (*ktask)->key_size, &y)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get a->y.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (!kryptos_ec_set_point(&A, x, y)) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set point A.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    kryptos_del_mp_value(x);
    kryptos_del_mp_value(y);
    x = y = NULL;

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_BX,
                                                    (*ktask)->key, (*ktask)->key_size, &x)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get b->x.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_BY,
                                                    (*ktask)->key, (*ktask)->key_size, &y)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get b->y.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (!kryptos_ec_set_point(&B, x, y)) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set point B.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    // INFO(Rafael): Parsing the input parameters (R, S and X).

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_R,
                                                    (*ktask)->in, (*ktask)->in_size, &r)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get r.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (((*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_S,
                                                    (*ktask)->in, (*ktask)->in_size, &s)) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get s.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    kryptos_task_init_as_null(htask);
    htask->in = kryptos_pem_get_data(KRYPTOS_ECDSA_PEM_HDR_PARAM_X, (*ktask)->in, (*ktask)->in_size, &htask->in_size);

    if (htask->in == NULL || htask->in_size == 0) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get x.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if ((s_inv = kryptos_mp_modinv(s, e.q)) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating s^1 mod q.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    hash(&htask, 0);

    if (htask->result != kKryptosSuccess || htask->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while computing hash(x).";
        goto kryptos_ecdsa_verify_epilogue;
    }

    kryptos_del_mp_value(x);
    x = kryptos_raw_buffer_as_mp(htask->out, htask->out_size);

    kryptos_task_free(htask, KRYPTOS_TASK_OUT);

    if (x == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while parsing hash output.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (kryptos_assign_mp_value(&u1, s_inv) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error on u1 = s_inv.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (kryptos_mp_mul(&u1, x) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating u1 * x.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (!kryptos_mp_mod(&u1, e.q)) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating u1 mod q.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (kryptos_assign_mp_value(&u2, s_inv) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error on u2 = s_inv.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (kryptos_mp_mul(&u2, r) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating u2 * r.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (!kryptos_mp_mod(&u2, e.q)) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating u2 mod q.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    kryptos_ec_mul(&AP, A, u1, e.ec);

    if (AP == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating u1 * A.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    kryptos_ec_mul(&BP, B, u2, e.ec);

    if (BP == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating u2 * B.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    kryptos_ec_add(&P, AP, BP, e.ec);

    if (P == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating AP + BP.";
        goto kryptos_ecdsa_verify_epilogue;
    }

    if (!kryptos_mp_eq(P->x, r)) {
        (*ktask)->result = kKryptosInvalidSignature;
        (*ktask)->result_verbose = "The signature is invalid.";
        kryptos_task_free(htask, KRYPTOS_TASK_IN);
    } else {
        (*ktask)->out = htask->in;
        (*ktask)->out_size = htask->in_size;
        htask->in = NULL;
        htask->in_size = 0;
    }

kryptos_ecdsa_verify_epilogue:

    if (r != NULL) {
        kryptos_del_mp_value(r);
    }

    if (s != NULL) {
        kryptos_del_mp_value(s);
    }

    if (s_inv != NULL) {
        kryptos_del_mp_value(s_inv);
    }

    if (u1 != NULL) {
        kryptos_del_mp_value(u1);
    }

    if (u2 != NULL) {
        kryptos_del_mp_value(u2);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (e.g != NULL) {
        kryptos_ec_del_point(e.g);
    }

    if (e.ec != NULL) {
        kryptos_ec_del_curve(e.ec);
    }

    if (e.q != NULL) {
        kryptos_del_mp_value(e.q);
    }

    if (B != NULL) {
        kryptos_ec_del_point(B);
    }

    if (A != NULL) {
        kryptos_ec_del_point(A);
    }

    if (P != NULL) {
        kryptos_ec_del_point(P);
    }

    if (AP != NULL) {
        kryptos_ec_del_point(AP);
    }

    if (BP != NULL) {
        kryptos_ec_del_point(BP);
    }
}

void kryptos_ecdsa_digital_signature_setup(kryptos_task_ctx *ktask, kryptos_u8_t *in, size_t in_size,
                                           kryptos_u8_t *key, size_t key_size,
                                           kryptos_hash_func hash, kryptos_hash_size_func hash_size) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherECDSA;

    ktask->in = in;
    ktask->in_size = in_size;

    ktask->key = key;
    ktask->key_size = key_size;

    ktask->arg[0] = (void *)hash;
    ktask->arg[1] = (void *)hash_size;
}

static kryptos_task_result_t kryptos_ecdsa_get_random_d(kryptos_mp_value_t **d, const kryptos_mp_value_t *q,
                                                        const size_t bits) {
    kryptos_mp_digit_t mask;
    size_t i;

#if defined(KRYPTOS_MP_U32_DIGIT)
    mask = 0xFFFFFFFF;
    if (bits < 32) {
        mask = mask >> (32 - bits);
    }
#else
    mask = 0xFF;
#endif

    (*d) = kryptos_new_mp_value((bits == 0 || kryptos_mp_bit2byte(bits) > q->data_size) ? kryptos_mp_byte2bit(q->data_size) :
                                                                                         bits);

    if ((*d) == NULL) {
        return kKryptosProcessError;
    }

    do {
        for (i = 0; i < (*d)->data_size; i++) {
#if defined(KRYPTOS_MP_U32_DIGIT)
            (*d)->data[i] = (((kryptos_u32_t)kryptos_get_random_byte() << 24) |
                             ((kryptos_u32_t)kryptos_get_random_byte() << 16) |
                             ((kryptos_u32_t)kryptos_get_random_byte() <<  8) |
                              (kryptos_u32_t)kryptos_get_random_byte()) & mask;
#else
            (*d)->data[i] = kryptos_get_random_byte();
#endif
        }
    } while (kryptos_mp_is_zero(*d) || kryptos_mp_ge(*d, q));

    return kKryptosSuccess;
}
