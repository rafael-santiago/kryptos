/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_rsa.h>
#include <kryptos_mp.h>
#include <kryptos_random.h>
#include <kryptos_pem.h>
#include <stdio.h>

static kryptos_mp_value_t *kryptos_rsa_eval_e(const kryptos_mp_value_t *euler_phi_f);

kryptos_task_result_t kryptos_rsa_mk_key_pair(const size_t bits, kryptos_u8_t **k_pub, size_t *k_pub_size,
                                              kryptos_u8_t **k_priv, size_t *k_priv_size) {
    kryptos_mp_value_t *p = NULL, *q = NULL;
    kryptos_mp_value_t *n = NULL, *euler_phi_f = NULL, *t = NULL, *e = NULL, *d = NULL;
    kryptos_mp_value_t *_1 = NULL;
    kryptos_task_result_t result = kKryptosProcessError;
    int eval_again;

    if (bits < 16) {
        return kKryptosInvalidParams;
    }

    if ((_1 = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        goto kryptos_rsa_mk_key_pair_epilogue;
    }

    do {
        eval_again = 0;
        // INFO(Rafael): Step 1.
        if ((p = kryptos_mp_gen_prime(bits >> 1)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        if ((q = kryptos_mp_gen_prime(bits >> 1)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        // INFO(Rafael): Step 2.
        if ((n = kryptos_assign_mp_value(&n, p)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        if ((n = kryptos_mp_mul(&n, q)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        // INFO(Rafael): Step 3.
        if ((t = kryptos_assign_mp_value(&t, p)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        if ((t = kryptos_mp_sub(&t, _1)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        if ((euler_phi_f = kryptos_assign_mp_value(&euler_phi_f, t)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        if ((t = kryptos_assign_mp_value(&t, q)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        if ((t = kryptos_mp_sub(&t, _1)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        if ((euler_phi_f = kryptos_mp_mul(&euler_phi_f, t)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        kryptos_del_mp_value(t);
        t = NULL;

        // INFO(Rafael): Step 4.
        if ((e = kryptos_rsa_eval_e(euler_phi_f)) == NULL) {
            goto kryptos_rsa_mk_key_pair_epilogue;
        }

        // INFO(Rafael): Step 5.
        if ((d = kryptos_mp_modinv(e, euler_phi_f)) == NULL) {
            // INFO(Rafael): This should never happen since the gcd of e and euler_phi_f is 1, anyway,
            //               if some unexpected behavior occur we still can return a valid RSA key pair.
            eval_again = 1;
            kryptos_del_mp_value(euler_phi_f);
            kryptos_del_mp_value(p);
            kryptos_del_mp_value(q);
            kryptos_del_mp_value(e);
            kryptos_del_mp_value(n);
            euler_phi_f = n = p = q = e = n = NULL;
        }
    } while (eval_again);

    // INFO(Rafael): Exporting the key pair data.
    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_RSA_PEM_HDR_PARAM_N,
                                  (kryptos_u8_t *)n->data, n->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_rsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_RSA_PEM_HDR_PARAM_E,
                                  (kryptos_u8_t *)e->data, e->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_rsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_RSA_PEM_HDR_PARAM_N,
                                  (kryptos_u8_t *)n->data, n->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_rsa_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_RSA_PEM_HDR_PARAM_D,
                                  (kryptos_u8_t *)d->data, d->data_size * sizeof(kryptos_mp_digit_t));

kryptos_rsa_mk_key_pair_epilogue:

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (n != NULL) {
        kryptos_del_mp_value(n);
    }

    if (euler_phi_f != NULL) {
        kryptos_del_mp_value(euler_phi_f);
    }

    if (t != NULL) {
        kryptos_del_mp_value(t);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (e != NULL) {
        kryptos_del_mp_value(e);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    return result;
}

static kryptos_mp_value_t *kryptos_rsa_eval_e(const kryptos_mp_value_t *euler_phi_f) {
    kryptos_mp_value_t *_1 = NULL, *gcd = NULL, *e = NULL;
    ssize_t d;

    if ((_1 = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        goto kryptos_rsa_eval_e_epilogue;
    }

    if ((e = kryptos_new_mp_value(kryptos_mp_byte2bit(euler_phi_f->data_size))) == NULL) {
        goto kryptos_rsa_eval_e_epilogue;
    }

    do {

        do {
            for (d = 0; d < e->data_size; d++) {
#ifndef KRYPTOS_MP_U32_DIGIT
                e->data[d] = kryptos_get_random_byte();
#else
                e->data[d] = kryptos_get_random_byte() << 24 |
                             kryptos_get_random_byte() << 16 |
                             kryptos_get_random_byte() <<  8 |
                             kryptos_get_random_byte();
#endif
            }
        } while (kryptos_mp_ge(e, euler_phi_f));

        if (gcd != NULL) {
            kryptos_del_mp_value(gcd);
        }

        if ((gcd = kryptos_mp_gcd(e, euler_phi_f)) == NULL) {
            goto kryptos_rsa_eval_e_epilogue;
        }
    } while (kryptos_mp_ne(gcd, _1));

kryptos_rsa_eval_e_epilogue:

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (gcd != NULL) {
        kryptos_del_mp_value(gcd);
    }

    d = 0;

    return e;
}

void kryptos_rsa_cipher(kryptos_task_ctx **ktask) {
}
