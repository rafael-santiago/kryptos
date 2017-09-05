/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_dl_params.h>
#include <kryptos_mp.h>

// CLUE(Rafael): This code stuff generates the triple <p, q, g> for discrete logarithm cryptosystems.

static kryptos_mp_value_t *kryptos_dl_get_h(const kryptos_mp_value_t *p);

static kryptos_mp_value_t *kryptos_dl_get_g(kryptos_mp_value_t **g, const kryptos_mp_value_t *p, const kryptos_mp_value_t *j);

static kryptos_task_result_t kryptos_generate_dl_temp_params(const size_t p_bits, const size_t q_bits,
                               kryptos_mp_value_t **p, kryptos_mp_value_t **q, kryptos_mp_value_t **g);

kryptos_task_result_t kryptos_generate_dl_params(const size_t p_bits, const size_t q_bits,
                               kryptos_mp_value_t **p, kryptos_mp_value_t **q, kryptos_mp_value_t **g) {
    kryptos_task_result_t result;

    result = kryptos_generate_dl_temp_params(p_bits, q_bits, p, q, g);

    while (result == kKryptosSuccess && kryptos_verify_dl_params(*p, *q, *g) == kKryptosInvalidParams) {
        kryptos_del_mp_value(*p);
        kryptos_del_mp_value(*q);
        kryptos_del_mp_value(*g);
        (*p) = (*q) = (*g) = NULL;
        result = kryptos_generate_dl_temp_params(p_bits, q_bits, p, q, g);
    }

    return result;
}

static kryptos_task_result_t kryptos_generate_dl_temp_params(const size_t p_bits, const size_t q_bits,
                               kryptos_mp_value_t **p, kryptos_mp_value_t **q, kryptos_mp_value_t **g) {
    kryptos_task_result_t result = kKryptosSuccess;
    kryptos_mp_value_t *j = NULL, *_1 = NULL, *d = NULL;
    size_t j_bits = 0;

    if (p == NULL || q == NULL || g == NULL) {
        return kKryptosInvalidParams;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        return kKryptosProcessError;
    }

    // INFO(Rafael): Generating a random prime q.

    (*q) = kryptos_mp_gen_prime(q_bits);

    if (*q == NULL) {
        result = kKryptosProcessError;
        goto kryptos_generate_dl_params_epilogue;
    }

    if (p_bits > q_bits) {
        j_bits = p_bits - q_bits;
    } else {
        j_bits = q_bits - p_bits;
    }

    do {
        if (*p != NULL) {
            kryptos_del_mp_value(*p);
            (*p) = NULL;
        }

        if (j != NULL) {
            kryptos_del_mp_value(j);
            j = NULL;
        }

        // INFO(Rafael): Picking an even j with bitlength == p_bits - q_bits.

        j = kryptos_mp_rand(j_bits);

        if (!kryptos_mp_is_even(j)) {
            j->data[0] &= (~0x1);
        }

        if (j == NULL) {
            result = kKryptosProcessError;
            goto kryptos_generate_dl_params_epilogue;
        }

        // INFO(Rafael): Calculating "p = jq + 1" and checking if it is prime.

        (*p) = kryptos_assign_mp_value(p, j);
        (*p) = kryptos_mp_mul(p, *q);
        (*p) = kryptos_mp_add(p, _1);

    } while (!kryptos_mp_is_prime(*p));

    if (((*g) = kryptos_dl_get_g(g, *p, j)) == NULL) {
        result = kKryptosProcessError;
    }

kryptos_generate_dl_params_epilogue:

    if (result != kKryptosSuccess) {
        if (*p != NULL) {
            kryptos_del_mp_value(*p);
            (*p) = NULL;
        }

        if (*q != NULL) {
            kryptos_del_mp_value(*q);
            (*q) = NULL;
        }

        if (*g != NULL) {
            kryptos_del_mp_value(*g);
            (*g) = NULL;
        }
    }

    if (j != NULL) {
        kryptos_del_mp_value(j);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    j_bits = 0;

    return result;
}

kryptos_task_result_t kryptos_verify_dl_params(const kryptos_mp_value_t *p,
                                               const kryptos_mp_value_t *q,
                                               const kryptos_mp_value_t *g) {
    kryptos_task_result_t result = kKryptosSuccess;
    kryptos_mp_value_t *_0 = NULL, *_1 = NULL, *p_1 = NULL, *d = NULL, *r = NULL, *e = NULL;

    if (p == NULL || q == NULL || g == NULL) {
        return kKryptosInvalidParams;
    }

    if ((_1 = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    if ((_0 = kryptos_hex_value_as_mp("0", 1)) == NULL) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    if ((p_1 = kryptos_assign_mp_value(&p_1, p)) == NULL) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    if ((p_1 = kryptos_mp_sub(&p_1, _1)) == NULL) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    // INFO(Rafael): 1 < g < p - 1.
    if (kryptos_mp_le(g, _1) || kryptos_mp_ge(g, p_1)) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    // INFO(Rafael): q must be prime.
    if (!kryptos_mp_is_prime(q)) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    // INFO(Rafael): p also must be prime.
    if (!kryptos_mp_is_prime(p)) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    // INFO(Rafael): (p - 1) mod q must be 0.
    d = kryptos_mp_div(p_1, q, &r);

    if (d == NULL || r == NULL) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    if (kryptos_mp_ne(r, _0)) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

    // INFO(Rafael): g^q mod p must be 1.

    e = kryptos_mp_me_mod_n(g, q, p);

    if (kryptos_mp_ne(e, _1)) {
        result = kKryptosInvalidParams;
        goto kryptos_verify_dl_params_epilogue;
    }

kryptos_verify_dl_params_epilogue:

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (p_1 != NULL) {
        kryptos_del_mp_value(p_1);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (r != NULL) {
        kryptos_del_mp_value(r);
    }

    if (e != NULL) {
        kryptos_del_mp_value(e);
    }

    return result;
}

static kryptos_mp_value_t *kryptos_dl_get_h(const kryptos_mp_value_t *p) {
    kryptos_mp_value_t *p_1 = NULL, *_1 = NULL, *h = NULL;

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        return NULL;
    }

    if ((p_1 = kryptos_assign_mp_value(&p_1, p)) == NULL) {
        goto kryptos_dl_get_h_epilogue;
    }

    if ((p_1 = kryptos_mp_sub(&p_1, _1)) == NULL) {
        goto kryptos_dl_get_h_epilogue;
    }

    do {
        if (h != NULL) {
            kryptos_del_mp_value(h);
        }

        h = kryptos_mp_rand(kryptos_mp_byte2bit(p->data_size));

        if (h == NULL) {
            goto kryptos_dl_get_h_epilogue;
        }
    } while (kryptos_mp_le(h, _1) || kryptos_mp_ge(h, p_1));

kryptos_dl_get_h_epilogue:

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (p_1 != NULL) {
        kryptos_del_mp_value(p_1);
    }

    return h;
}

static kryptos_mp_value_t *kryptos_dl_get_g(kryptos_mp_value_t **g, const kryptos_mp_value_t *p, const kryptos_mp_value_t *j) {
    kryptos_mp_value_t *h = NULL, *_1 = NULL;

    (*g) = NULL;

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        return NULL;
    }

    do {
        if (*g != NULL) {
            kryptos_del_mp_value(*g);
            (*g) = NULL;
        }

        if (h != NULL) {
            kryptos_del_mp_value(h);
            h = NULL;
        }

        // INFO(Rafael): Picking a random number between 2 and p - 2.

        h = kryptos_dl_get_h(p);

        if (h == NULL) {
            goto kryptos_dl_get_g_epilogue;
        }

        (*g) = kryptos_mp_me_mod_n(h, j, p);

        if (*g == NULL) {
            goto kryptos_dl_get_g_epilogue;
        }
    } while (kryptos_mp_eq(*g, _1));

kryptos_dl_get_g_epilogue:

    if (h != NULL) {
        kryptos_del_mp_value(h);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    return (*g);
}
