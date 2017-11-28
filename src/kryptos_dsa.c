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
#include <kryptos_sha1.h>
#include <kryptos_task_check.h>
#include <kryptos_pem.h>
#include <kryptos_endianess_utils.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

static kryptos_mp_value_t *kryptos_dsa_get_random(const kryptos_mp_value_t *n);

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

    d = kryptos_dsa_get_random(q);

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

static kryptos_mp_value_t *kryptos_dsa_get_random(const kryptos_mp_value_t *n) {
    kryptos_mp_value_t *_1 = NULL, *n_1 = NULL;
    kryptos_mp_value_t *r = NULL;

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

    return r;
}

void kryptos_dsa_digital_signature_setup(kryptos_task_ctx *ktask, kryptos_u8_t *in, size_t in_size,
                                         kryptos_u8_t *key, size_t key_size, kryptos_hash_func hash) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherDSA;

    ktask->in = in;
    ktask->in_size = in_size;

    ktask->key = key;
    ktask->key_size = key_size;

    ktask->arg[0] = hash;
}

void kryptos_dsa_sign(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *ke = NULL, *ke_inv = NULL, *p = NULL, *g = NULL, *q = NULL, *r = NULL, *s = NULL, *d = NULL, *h = NULL;
    kryptos_mp_value_t *div = NULL, *mod = NULL;
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_task_ctx ht, *htask = &ht;

    if (ktask == NULL) {
        return;
    }

    if (kryptos_task_check_sign(ktask) == 0) {
        return;
    }

    (*ktask)->out = NULL;
    (*ktask)->out_size = 0;

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &p);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get p.";
        goto kryptos_dsa_sign_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_G, (*ktask)->key, (*ktask)->key_size, &g);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get g.";
        goto kryptos_dsa_sign_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_Q, (*ktask)->key, (*ktask)->key_size, &q);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get q.";
        goto kryptos_dsa_sign_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &d);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get d.";
        goto kryptos_dsa_sign_epilogue;
    }

    // INFO(Rafael): Picking a value for ke and computing its inverse.

    do {
        // WARN(Rafael): It should not run in kernel mode. Even running it should not hang forever.
        ke = kryptos_dsa_get_random(q);
        if ((ke_inv = kryptos_mp_modinv(ke, q)) == NULL) {
            kryptos_del_mp_value(ke);
            ke = NULL;
        }
    } while (ke == NULL);

    if (ke == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to generate the ephemeral key.";
        goto kryptos_dsa_sign_epilogue;
    }

    // INFO(Rafael): r = (g^ke mod p) mod q.

    r = kryptos_mp_me_mod_n(g, ke, p);

    if (r == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute g^ke mod p.";
        goto kryptos_dsa_sign_epilogue;
    }

    div = kryptos_mp_div(r, q, &mod);

    if (div == NULL || mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute (g^ke mod p) mod q.";
        goto kryptos_dsa_sign_epilogue;
    }

    kryptos_del_mp_value(r);
    r = NULL;

    r = kryptos_assign_mp_value(&r, mod);

    kryptos_del_mp_value(div);
    kryptos_del_mp_value(mod);

    div = mod = NULL;

    // INFO(Rafael): s = (HASH(x) + d * r) * ke^-1 mod q.

    if ((*ktask)->arg[0] != NULL) {
        hash = (kryptos_hash_func)(*ktask)->arg[0];
    }

    kryptos_task_init_as_null(htask);

    htask->in = (*ktask)->in;
    htask->in_size = (*ktask)->in_size;

    hash(&htask, 0);

    if (htask->result != kKryptosSuccess || htask->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute Hash(in).";
        goto kryptos_dsa_sign_epilogue;
    }

    h = kryptos_raw_buffer_as_mp(htask->out, htask->out_size);

    kryptos_task_free(htask, KRYPTOS_TASK_OUT);

    if (h == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to parse h.";
        goto kryptos_dsa_sign_epilogue;
    }

    d = kryptos_mp_mul(&d, r);

    if (d == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute d * r.";
        goto kryptos_dsa_sign_epilogue;
    }

    d = kryptos_mp_add(&d, h);

    if (d == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute h + d.";
        goto kryptos_dsa_sign_epilogue;
    }

    d = kryptos_mp_mul(&d, ke_inv);

    if (d == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute d * ke^-1.";
        goto kryptos_dsa_sign_epilogue;
    }

    div = kryptos_mp_div(d, q, &s);

    if (div == NULL || s == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute d mod q.";
        goto kryptos_dsa_sign_epilogue;
    }

    // INFO(Rafael): Now exporting X, R and S parameters.

    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_DSA_PEM_HDR_PARAM_X,
                                            (kryptos_u8_t *)(*ktask)->in, (*ktask)->in_size);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting the signature data.";
        goto kryptos_dsa_sign_epilogue;
    }

    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_DSA_PEM_HDR_PARAM_R,
                                            (kryptos_u8_t *)r->data, r->data_size * sizeof(kryptos_mp_digit_t));

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting the signature data.";
        goto kryptos_dsa_sign_epilogue;
    }

    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_DSA_PEM_HDR_PARAM_S,
                                            (kryptos_u8_t *)s->data, s->data_size * sizeof(kryptos_mp_digit_t));

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting the signature data.";
    }

kryptos_dsa_sign_epilogue:

    if (ke != NULL) {
        kryptos_del_mp_value(ke);
    }

    if (ke_inv != NULL) {
        kryptos_del_mp_value(ke_inv);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (r != NULL) {
        kryptos_del_mp_value(r);
    }

    if (s != NULL) {
        kryptos_del_mp_value(s);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (h != NULL) {
        kryptos_del_mp_value(h);
    }

    if (div != NULL) {
        kryptos_del_mp_value(div);
    }

    if (mod != NULL) {
        kryptos_del_mp_value(mod);
    }

    if (htask->out != NULL) {
        kryptos_task_free(htask, KRYPTOS_TASK_OUT);
    }

    kryptos_task_init_as_null(htask);

    if ((*ktask)->result != kKryptosSuccess && (*ktask)->out != NULL) {
        kryptos_freeseg((*ktask)->out);
        (*ktask)->out_size = 0;
    }
}

void kryptos_dsa_verify(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *r = NULL, *s = NULL, *s_inv = NULL, *u1 = NULL, *u2 = NULL, *w = NULL, *p = NULL, *g = NULL, *q = NULL,
                       *e = NULL, *h = NULL, *e2u2 = NULL, *v = NULL;

    kryptos_mp_value_t *div = NULL, *mod = NULL;
    kryptos_u8_t *x = NULL;
    size_t x_size = 0;
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_task_ctx ht, *htask = &ht;

    if (ktask == NULL) {
        return;
    }

    if (kryptos_task_check_verify(ktask) == 0) {
        return;
    }

    // INFO(Rafael): Parsing the public key.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &p);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get p.";
        goto kryptos_dsa_verify_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_G, (*ktask)->key, (*ktask)->key_size, &g);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get g.";
        goto kryptos_dsa_verify_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_Q, (*ktask)->key, (*ktask)->key_size, &q);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get q.";
        goto kryptos_dsa_verify_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_E, (*ktask)->key, (*ktask)->key_size, &e);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get e.";
        goto kryptos_dsa_verify_epilogue;
    }

    // INFO(Rafael): Parsing all parameters from task input buffer.

    x = kryptos_pem_get_data(KRYPTOS_DSA_PEM_HDR_PARAM_X, (*ktask)->in, (*ktask)->in_size, &x_size);

    if (x == NULL || x_size == 0) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to parse x.";
        goto kryptos_dsa_verify_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_R, (*ktask)->in, (*ktask)->in_size, &r);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to parse r.";
        goto kryptos_dsa_verify_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_DSA_PEM_HDR_PARAM_S, (*ktask)->in, (*ktask)->in_size, &s);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to parse s.";
        goto kryptos_dsa_verify_epilogue;
    }

    if ((*ktask)->arg[0] != NULL) {
        hash = (*ktask)->arg[0];
    }

    s_inv = kryptos_mp_modinv(s, q);

    if (s_inv == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute s^-1.";
        goto kryptos_dsa_verify_epilogue;
    }

    div = kryptos_mp_div(s_inv, q, &w); // TODO(Rafael): ??!!!

    if (div == NULL || w == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute s^1 mod q.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(div);
    div = NULL;

    u1 = kryptos_assign_mp_value(&u1, w);

    if (u1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set u1.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_task_init_as_null(htask);

    htask->in = x;
    htask->in_size = x_size;

    hash(&htask, 0);

    if (htask->result != kKryptosSuccess || htask->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute Hash(x).";
        goto kryptos_dsa_verify_epilogue;
    }

    h = kryptos_raw_buffer_as_mp(htask->out, htask->out_size);

    kryptos_task_free(htask, KRYPTOS_TASK_OUT);

    if (h == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to parse h.";
        goto kryptos_dsa_verify_epilogue;
    }

    u1 = kryptos_mp_mul(&u1, h);

    if (u1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute w * Hash(x).";
        goto kryptos_dsa_verify_epilogue;
    }

    div = kryptos_mp_div(u1, q, &mod);

    if (div == NULL || mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute w * Hash(x) mod q.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(div);
    div = NULL;

    kryptos_del_mp_value(u1);
    u1 = NULL;

    u1 = kryptos_assign_mp_value(&u1, mod);

    if (u1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set u1.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(mod);
    mod = NULL;

    u2 = kryptos_assign_mp_value(&u2, w);

    if (u2 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable set u2.";
        goto kryptos_dsa_verify_epilogue;
    }

    u2 = kryptos_mp_mul(&u2, r);

    if (u2 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute u2 * r.";
        goto kryptos_dsa_verify_epilogue;
    }

    div = kryptos_mp_div(u2, q, &mod);

    if (div == NULL || mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute u2 mod q.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(div);
    div = NULL;

    kryptos_del_mp_value(u2);
    u2 = NULL;

    u2 = kryptos_assign_mp_value(&u2, mod);

    if (u2 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set u2.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(mod);
    mod = NULL;

    // CLUE(Rafael): The idea here is explore the following 'equivalence':
    //
    //                          g^u1 * e^u2 mod p == ((g^u1 mod p) * (e^u2 mod p)) mod p.
    //
    // g^u1, e^u2 are pretty slow operations, kryptos_mp_me_mod_n() will avoid the exponential growing of those values,
    // as a result it will speed up the whole process.

    v = kryptos_mp_me_mod_n(g, u1, p);

    if (v == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute g^u1.";
        goto kryptos_dsa_verify_epilogue;
    }

    e2u2 = kryptos_mp_me_mod_n(e, u2, p);

    if (e2u2 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute e^u2.";
        goto kryptos_dsa_verify_epilogue;
    }

    v = kryptos_mp_mul(&v, e2u2);

    if (v == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute g^u1 * e^u2.";
        goto kryptos_dsa_verify_epilogue;
    }

    div = kryptos_mp_div(v, p, &mod);

    if (div == NULL || mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute v mod p.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(div);
    div = NULL;

    kryptos_del_mp_value(v);
    v = NULL;

    v = kryptos_assign_mp_value(&v, mod);

    if (v == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set v.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(mod);
    mod = NULL;

    div = kryptos_mp_div(v, q, &mod);

    if (div == NULL || mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute v mod q.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(div);
    div = NULL;

    kryptos_del_mp_value(v);
    v = NULL;

    v = kryptos_assign_mp_value(&v, mod);

    if (v == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set v.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(mod);
    mod = NULL;

    div = kryptos_mp_div(r, q, &mod);

    if (div == NULL || mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute r mod q.";
        goto kryptos_dsa_verify_epilogue;
    }

    kryptos_del_mp_value(div);
    div = NULL;

    kryptos_del_mp_value(r);
    r = NULL;

    r = kryptos_assign_mp_value(&r, mod);

    if (r == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to set r.";
        goto kryptos_dsa_verify_epilogue;
    }

    if (kryptos_mp_eq(v, r)) {
        if (h == NULL) {
            (*ktask)->result = kKryptosProcessError;
            (*ktask)->result_verbose = "Error while exporting x.";
            goto kryptos_dsa_verify_epilogue;
        }

        (*ktask)->out = x;
        (*ktask)->out_size = x_size;

        x = NULL;
        x_size = 0;
    } else {
        (*ktask)->result = kKryptosInvalidSignature;
        (*ktask)->result_verbose = "The signature is invalid.";
    }

kryptos_dsa_verify_epilogue:

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

    if (w != NULL) {
        kryptos_del_mp_value(w);
    }

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

    if (h != NULL) {
        kryptos_del_mp_value(h);
    }

    if (x != NULL) {
        kryptos_freeseg(x);
        x_size = 0;
    }

    if (v != NULL) {
        kryptos_del_mp_value(v);
    }

    if (div != NULL) {
        kryptos_del_mp_value(div);
    }

    if (mod != NULL) {
        kryptos_del_mp_value(mod);
    }

    if (e2u2 != NULL) {
        kryptos_del_mp_value(e2u2);
    }

    if (htask->out != NULL) {
        kryptos_freeseg(htask->out);
    }

    kryptos_task_init_as_null(htask);

    if ((*ktask)->result != kKryptosSuccess && (*ktask)->out != NULL) {
        kryptos_freeseg((*ktask)->out);
        (*ktask)->out = NULL;
        (*ktask)->out_size = 0;
    }
}
