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
#include <kryptos_padding.h>
#include <kryptos_task_check.h>
#include <kryptos_memory.h>
#include <kryptos_endianess_utils.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

static kryptos_mp_value_t *kryptos_rsa_eval_e(const kryptos_mp_value_t *euler_phi_f);

static void kryptos_rsa_encrypt(kryptos_task_ctx **ktask);

static void kryptos_rsa_decrypt(kryptos_task_ctx **ktask);

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
            euler_phi_f = n = p = q = e = NULL;
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

void kryptos_rsa_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherRSA;

    ktask->key = key;
    ktask->key_size = key_size;
}

void kryptos_rsa_cipher(kryptos_task_ctx **ktask) {
    if (ktask == NULL) {
        return;
    }

    if (kryptos_task_check(ktask) == 0) {
        return;
    }

    if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Null input buffer.";
        return;
    }

    if ((*ktask)->action == kKryptosEncrypt) {
        kryptos_rsa_encrypt(ktask);
    } else if ((*ktask)->action == kKryptosDecrypt) {
        kryptos_rsa_decrypt(ktask);
    } else {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid action.";
    }
}

void kryptos_rsa_oaep_cipher(kryptos_task_ctx **ktask) {
    kryptos_u8_t *temp = NULL, *old_in = NULL;
    size_t old_in_size;
    kryptos_mp_value_t *n = NULL;

    if (ktask == NULL) {
        return;
    }

    if ((*ktask)->action != kKryptosEncrypt && (*ktask)->action != kKryptosDecrypt) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid action.";
        return;
    }

    if (kryptos_task_check(ktask) == 0) {
        return;
    }

    if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Null input buffer.";
        return;
    }

    if (kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &n) != kKryptosSuccess) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Unable to get the N parameter.";
        return;
    }

    if ((*ktask)->action == kKryptosEncrypt) {
        old_in = (*ktask)->in;
        old_in_size = (*ktask)->in_size;

        temp = kryptos_apply_oaep_padding((*ktask)->in, &(*ktask)->in_size, kryptos_mp_byte2bit(n->data_size) >> 3,
                                          (*ktask)->arg[0],
                                          *(size_t *)(*ktask)->arg[1],
                                          (kryptos_hash_func)(*ktask)->arg[2],
                                          (kryptos_hash_size_func)(*ktask)->arg[3]);

        if (temp == NULL) {
            (*ktask)->result = kKryptosProcessError;
            (*ktask)->result_verbose = "Error during OAEP padding.";
            goto kryptos_rsa_oaep_cipher_epilogue;
        }

        (*ktask)->in = temp;
        kryptos_rsa_encrypt(ktask);
    } else {
        kryptos_rsa_decrypt(ktask);

        if ((*ktask)->result == kKryptosSuccess) {
            temp = (*ktask)->out;

            (*ktask)->out = kryptos_drop_oaep_padding(temp, &(*ktask)->out_size, kryptos_mp_byte2bit(n->data_size) >> 3,
                                                     (*ktask)->arg[0],
                                                     *(size_t *)(*ktask)->arg[1],
                                                     (kryptos_hash_func)(*ktask)->arg[2],
                                                     (kryptos_hash_size_func)(*ktask)->arg[3]);

            if ((*ktask)->out == NULL) {
                (*ktask)->result = kKryptosProcessError;
                (*ktask)->result_verbose = "The cryptogram is corrupted.";
                (*ktask)->out_size = 0;
                // WARN(Rafael): Do not jump to epilogue, temp must be freed.
            }
        }
    }

    if (temp != NULL) {
        kryptos_freeseg(temp);
    }

kryptos_rsa_oaep_cipher_epilogue:

    if (n != NULL) {
        kryptos_del_mp_value(n);
    }

    if (old_in != NULL) {
        (*ktask)->in = old_in;
        (*ktask)->in_size = old_in_size;
        old_in = NULL;
        old_in_size = 0;
    }
}

static void kryptos_rsa_encrypt(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *e = NULL, *n = NULL, *m = NULL, *c = NULL;

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &n);

    if ((*ktask)->result != kKryptosSuccess) {
        return;
    }

    if ((*ktask)->in_size > (kryptos_mp_byte2bit(n->data_size) >> 3)) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "RSA input is too long.";
        goto kryptos_rsa_encrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_E, (*ktask)->key, (*ktask)->key_size, &e);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_rsa_encrypt_epilogue;
    }

    m = kryptos_raw_buffer_as_mp((*ktask)->in, (*ktask)->in_size);

    if (m == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Error while reading the input buffer.";
        goto kryptos_rsa_encrypt_epilogue;
    }

    c = kryptos_mp_me_mod_n(m, e, n);

    if (c == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while encrypting.";
        goto kryptos_rsa_encrypt_epilogue;
    }

    (*ktask)->out = NULL;
    (*ktask)->out_size = 0;
    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_RSA_PEM_HDR_PARAM_C,
                                            (kryptos_u8_t *)c->data, c->data_size * sizeof(kryptos_mp_digit_t));
kryptos_rsa_encrypt_epilogue:

    if (n != NULL) {
        kryptos_del_mp_value(n);
    }

    if (e != NULL) {
        kryptos_del_mp_value(e);
    }

    if (m != NULL) {
        kryptos_del_mp_value(m);
    }

    if (c != NULL) {
        kryptos_del_mp_value(c);
    }
}

static void kryptos_rsa_decrypt(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *d = NULL, *n = NULL, *c = NULL, *m = NULL;
    ssize_t xd;
    ssize_t o_size;
    kryptos_u8_t *o = NULL;

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &n);

    if ((*ktask)->result != kKryptosSuccess) {
        return;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &d);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_rsa_decrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_C, (*ktask)->in, (*ktask)->in_size, &c);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_rsa_decrypt_epilogue;
    }

    if (c == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "NULL input.";
        goto kryptos_rsa_decrypt_epilogue;
    }

    m = kryptos_mp_me_mod_n(c, d, n);

    if (m == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while decrypting.";
        goto kryptos_rsa_decrypt_epilogue;
    }

    kryptos_mp_as_task_out(ktask, m, o, o_size, xd, kryptos_rsa_decrypt_epilogue);

kryptos_rsa_decrypt_epilogue:

    if (n != NULL) {
        kryptos_del_mp_value(n);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (c != NULL) {
        kryptos_del_mp_value(c);
    }

    if (m != NULL) {
        kryptos_del_mp_value(m);
    }
}

void kryptos_rsa_oaep_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size,
                            kryptos_u8_t *label, size_t *label_size,
                            kryptos_hash_func hash,
                            kryptos_hash_size_func hash_size) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherRSAOAEP;

    ktask->key = key;
    ktask->key_size = key_size;

    ktask->arg[0] = label;
    ktask->arg[1] = label_size;
    ktask->arg[2] = hash;
    ktask->arg[3] = hash_size;
}

void kryptos_rsa_digital_signature_setup(kryptos_task_ctx *ktask, kryptos_u8_t *in, size_t in_size,
                                         kryptos_u8_t *key, size_t key_size) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherRSA;

    ktask->key = key;
    ktask->key_size = key_size;

    ktask->in = in;
    ktask->in_size = in_size;
}

void kryptos_rsa_emsa_pss_digital_signature_setup(kryptos_task_ctx *ktask, kryptos_u8_t *in, size_t in_size,
                                                  kryptos_u8_t *key, size_t key_size, size_t *salt_size,
                                                  kryptos_hash_func hash, kryptos_hash_size_func hash_size) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherRSAEMSAPSS;

    ktask->key = key;
    ktask->key_size = key_size;

    ktask->in = in;
    ktask->in_size = in_size;

    ktask->arg[0] = salt_size;
    ktask->arg[1] = hash;
    ktask->arg[2] = hash_size;
}

void kryptos_rsa_emsa_pss_sign(kryptos_task_ctx **ktask) {
    kryptos_rsa_sign(ktask);
}

void kryptos_rsa_emsa_pss_verify(kryptos_task_ctx **ktask) {
    kryptos_rsa_verify(ktask);
}

void kryptos_rsa_sign(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *d = NULL, *n = NULL, *x = NULL, *s = NULL;
    kryptos_u8_t *old_in = NULL;
    size_t old_in_size = 0;

    if (ktask == NULL) {
        return;
    }

    if (kryptos_task_check_sign(ktask) == 0) {
        return;
    }

    // INFO(Rafael): Parsing all multiprecision data.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &d);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get d.";
        goto kryptos_rsa_sign_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &n);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get n.";
        goto kryptos_rsa_sign_epilogue;
    }

    if ((*ktask)->in_size > (kryptos_mp_byte2bit(n->data_size) >> 3)) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "RSA input is too long.";
        goto kryptos_rsa_sign_epilogue;
    }

    if ((*ktask)->cipher == kKryptosCipherRSAEMSAPSS) {
        old_in = (*ktask)->in;
        old_in_size = (*ktask)->in_size;
        (*ktask)->in = kryptos_pss_encode(old_in, &(*ktask)->in_size,
                                          kryptos_mp_byte2bit(n->data_size) >> 3, *(size_t *)(*ktask)->arg[0],
                                          (kryptos_hash_func)(*ktask)->arg[1], (kryptos_hash_size_func)(*ktask)->arg[2]);

        if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {
            (*ktask)->result = kKryptosInvalidParams;
            (*ktask)->result_verbose = "Error during PSS encoding.";
            goto kryptos_rsa_sign_epilogue;
        }
    }

    x = kryptos_raw_buffer_as_mp((*ktask)->in, (*ktask)->in_size);

    if (x == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get x.";
        goto kryptos_rsa_sign_epilogue;
    }

    // INFO(Rafael): Computing the signature.

    s = kryptos_mp_me_mod_n(x, d, n);

    if (s == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute s.";
        goto kryptos_rsa_sign_epilogue;
    }

    // INFO(Rafael): Exporting the relevant multiprecision data.

    (*ktask)->out = NULL;
    (*ktask)->out_size = 0;

    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_RSA_PEM_HDR_PARAM_X,
                                            (kryptos_u8_t *)x->data, x->data_size * sizeof(kryptos_mp_digit_t));

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting the signature data.";
        goto kryptos_rsa_sign_epilogue;
    }

    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_RSA_PEM_HDR_PARAM_S,
                                            (kryptos_u8_t *)s->data, s->data_size * sizeof(kryptos_mp_digit_t));

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting the signature data.";
    }

kryptos_rsa_sign_epilogue:

    // INFO(Rafael): Some housekeeping.

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (n != NULL) {
        kryptos_del_mp_value(n);
    }

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (s != NULL) {
        kryptos_del_mp_value(s);
    }

    if (old_in != NULL) {
        kryptos_task_free(*ktask, KRYPTOS_TASK_IN);
        (*ktask)->in = old_in;
        (*ktask)->in_size = old_in_size;
        old_in = NULL;
        old_in_size = 0;
    }

    if ((*ktask)->result != kKryptosSuccess && (*ktask)->out != NULL) {
        kryptos_freeseg((*ktask)->out);
        (*ktask)->out = NULL;
        (*ktask)->out_size = 0;
    }
}

void kryptos_rsa_verify(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *xp = NULL, *x = NULL, *s = NULL, *e = NULL, *n = NULL;
    kryptos_u8_t *o = NULL;
    ssize_t o_size = 0, xd = 0;
    kryptos_task_ctx em_task, *em = NULL;

    if (ktask == NULL) {
        return;
    }

    (*ktask)->cipher = kKryptosCipherRSA;

    if (kryptos_task_check_verify(ktask) == 0) {
        return;
    }

    // INFO(Rafael): Parsing stuff for multiprecision data.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_X, (*ktask)->in, (*ktask)->in_size, &x);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get x.";
        goto kryptos_rsa_verify_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_S, (*ktask)->in, (*ktask)->in_size, &s);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get s.";
        goto kryptos_rsa_verify_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_E, (*ktask)->key, (*ktask)->key_size, &e);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get e.";
        goto kryptos_rsa_verify_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_RSA_PEM_HDR_PARAM_N, (*ktask)->key, (*ktask)->key_size, &n);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get n.";
        goto kryptos_rsa_verify_epilogue;
    }

    // INFO(Rafael): Computing x'. I.e.: Verifying the supplied signature.

    xp = kryptos_mp_me_mod_n(s, e, n);

    if (xp == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to compute x'.";
        goto kryptos_rsa_verify_epilogue;
    }

    (*ktask)->out = NULL;
    (*ktask)->out_size = 0;

    if ((*ktask)->cipher == kKryptosCipherRSAEMSAPSS) {
        // INFO(Rafael): Our verification task also offers another service, return a copy of the original x, if it has a
        //               valid signature.
        kryptos_mp_as_task_out(ktask, x, o, o_size, xd, kryptos_rsa_verify_epilogue);

        em = &em_task;
        kryptos_task_init_as_null(em);
        kryptos_mp_as_task_out(&em, xp, o, o_size, xd, kryptos_rsa_verify_epilogue);

        if (kryptos_pss_verify((*ktask)->out, (*ktask)->out_size,
                               em->out, em->out_size,
                               kryptos_mp_byte2bit(n->data_size) >> 3,
                               *(size_t *)(*ktask)->arg[0],
                               (kryptos_hash_func)(*ktask)->arg[1],
                               (kryptos_hash_size_func)(*ktask)->arg[2]) != (*ktask)->out) {
            kryptos_task_free(*ktask, KRYPTOS_TASK_OUT);
            (*ktask)->result = kKryptosInvalidSignature;
            (*ktask)->result_verbose = "The signature is invalid.";
        }
    } else {

        if (kryptos_mp_ne(x, xp)) {
            (*ktask)->result = kKryptosInvalidSignature;
            (*ktask)->result_verbose = "The signature is invalid.";
            goto kryptos_rsa_verify_epilogue;
        }

        // INFO(Rafael): Our verification task also offers another service, return a copy of the original x, if it has a
        //               valid signature.

        kryptos_mp_as_task_out(ktask, x, o, o_size, xd, kryptos_rsa_verify_epilogue);
    }

kryptos_rsa_verify_epilogue:

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (s != NULL) {
        kryptos_del_mp_value(s);
    }

    if (e != NULL) {
        kryptos_del_mp_value(e);
    }

    if (n != NULL) {
        kryptos_del_mp_value(n);
    }

    if (xp != NULL) {
        kryptos_del_mp_value(xp);
    }

    if ((*ktask)->cipher == kKryptosCipherRSAEMSAPSS && em != NULL) {
        kryptos_task_free(em, KRYPTOS_TASK_OUT);
        kryptos_task_init_as_null(em);
        em = NULL;
    }

    if ((*ktask)->result != kKryptosSuccess && (*ktask)->out != NULL) {
        kryptos_freeseg((*ktask)->out);
        (*ktask)->out = NULL;
        (*ktask)->out_size = 0;
    }
}

