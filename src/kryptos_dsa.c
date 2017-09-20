/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_dsa.h>
#include <kryptos_memory.h>
#include <kryptos_mp.h>
#include <kryptos_dl_params.h>
#include <kryptos_pem.h>

static kryptos_mp_value_t *kryptos_dsa_get_random_d(const kryptos_mp_value_t *n);

kryptos_task_result_t kryptos_dsa_mk_key_pair(const size_t p_bits, const size_t q_bits,
                                              kryptos_u8_t **k_pub, size_t *k_pub_size,
                                              kryptos_u8_t **k_priv, size_t *k_priv_size) {
    kryptos_task_result_t result = kKryptosProcessError;
    kryptos_mp_value_t *p = NULL, *g = NULL, *q = NULL, *e = NULL, *d = NULL;

    if (k_pub == NULL || k_pub_size == NULL || k_priv == NULL || k_priv_size == NULL) {
        return kKryptosInvalidParams;
    }

    (*k_pub) = NULL;
    *k_pub_size = 0;

    (*k_priv) = NULL;
    *k_priv_size = 0;

    // INFO(Rafael): Generating the domain parameters based on discrete logarithm stuff.

    result = kryptos_generate_dl_params(p_bits, q_bits, &p, &q, &g);

    if (result != kKryptosSuccess) {
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    d = kryptos_dsa_get_random_d(q);

    if (d == NULL) {
        result = kKryptosProcessError;
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    // INFO(Rafael): Building up the public buffer.

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_DSA_PEM_HDR_PARAM_P,
                                  (kryptos_u8_t *)p->data, p->data_size * sizeof(kryptos_mp_digit_t));

    if (result  != kKryptosSuccess) {
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_DSA_PEM_HDR_PARAM_Q,
                                  (kryptos_u8_t *)q->data, q->data_size * sizeof(kryptos_mp_digit_t));

    if (result  != kKryptosSuccess) {
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_DSA_PEM_HDR_PARAM_G,
                                  (kryptos_u8_t *)g->data, g->data_size * sizeof(kryptos_mp_digit_t));


    if (result  != kKryptosSuccess) {
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    e = kryptos_mp_me_mod_n(g, d, p);

    if (e == NULL) {
        result = kKryptosProcessError;
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_DSA_PEM_HDR_PARAM_E,
                                 (kryptos_u8_t *)e->data, e->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    // INFO(Rafael): Building up the private buffer.

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_DSA_PEM_HDR_PARAM_P,
                                  (kryptos_u8_t *)p->data, p->data_size * sizeof(kryptos_mp_digit_t));

    if (result  != kKryptosSuccess) {
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_DSA_PEM_HDR_PARAM_Q,
                                  (kryptos_u8_t *)q->data, q->data_size * sizeof(kryptos_mp_digit_t));

    if (result  != kKryptosSuccess) {
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_DSA_PEM_HDR_PARAM_G,
                                  (kryptos_u8_t *)g->data, g->data_size * sizeof(kryptos_mp_digit_t));

    if (result  != kKryptosSuccess) {
        goto kryptos_dsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_DSA_PEM_HDR_PARAM_D,
                                  (kryptos_u8_t *)d->data, d->data_size * sizeof(kryptos_mp_digit_t));

kryptos_dsa_mk_key_pair_epilogue:

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (e != NULL) {
        kryptos_del_mp_value(e);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (result != kKryptosSuccess) {
        if (*k_pub != NULL) {
            kryptos_freeseg(*k_pub);
            (*k_pub) = NULL;
            *k_pub_size = 0;
        }

        if (*k_priv != NULL) {
            kryptos_freeseg(*k_priv);
            (*k_priv) = NULL;
            *k_priv_size = 0;
        }
    }

    return result;
}

static kryptos_mp_value_t *kryptos_dsa_get_random_d(const kryptos_mp_value_t *n) {
    kryptos_mp_value_t *_1 = NULL, *n_1 = NULL;
    kryptos_mp_value_t *r = NULL;
    ssize_t d;

    if (n == NULL) {
        return NULL;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        goto kryptos_dsa_get_random_d_epilogue;
    }

    n_1 = kryptos_assign_mp_value(&n_1, n);

    if (n_1 == NULL) {
        goto kryptos_dsa_get_random_d_epilogue;
    }

    n_1 = kryptos_mp_sub(&n_1, _1);

    if (n_1 == NULL) {
        goto kryptos_dsa_get_random_d_epilogue;
    }


    do {
        if (r != NULL) {
            kryptos_del_mp_value(r);
        }

        r = kryptos_mp_rand(kryptos_mp_byte2bit(n->data_size));

        if (r == NULL) {
            goto kryptos_dsa_get_random_d_epilogue;
        }

    } while (kryptos_mp_lt(r, _1) || kryptos_mp_gt(r, n_1));

kryptos_dsa_get_random_d_epilogue:

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (n_1 != NULL) {
        kryptos_del_mp_value(n_1);
    }

    d = 0;

    return r;
}

void kryptos_dsa_sign(kryptos_task_ctx **ktask) {
    // TODO(Rafael);
}

void kryptos_dsa_verify(kryptos_task_ctx **ktask) {
    // TODO(Rafael);
}
