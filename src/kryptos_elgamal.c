/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_elgamal.h>
#include <kryptos_dl_params.h>
#include <kryptos_padding.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <kryptos_mp.h>
#include <kryptos_pem.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#ifndef KRYPTOS_KERNEL_MODE
#include <string.h>
#endif

static kryptos_mp_value_t *kryptos_elgamal_get_random_mp(kryptos_mp_value_t **mp,
                                                         const kryptos_mp_value_t *q);

static void kryptos_elgamal_encrypt(kryptos_task_ctx **ktask);

static void kryptos_elgamal_decrypt(kryptos_task_ctx **ktask);

kryptos_task_result_t kryptos_elgamal_mk_key_pair(const size_t p_bits, const size_t q_bits,
                                                  kryptos_u8_t **k_pub, size_t *k_pub_size,
                                                  kryptos_u8_t **k_priv, size_t *k_priv_size) {

    kryptos_mp_value_t *p = NULL, *q = NULL, *g = NULL, *d = NULL, *b = NULL;
    kryptos_task_result_t result = kKryptosProcessError;

    if (k_pub == NULL || k_pub_size == NULL || k_priv == NULL || k_priv_size == NULL) {
        return kKryptosInvalidParams;
    }

    (*k_pub) = (*k_priv) = NULL;
    *k_pub_size = *k_priv_size = 0;

    // INFO(Rafael): Generating the domain parameters and their derived values: public b and private d.

    if ((result = kryptos_generate_dl_params(p_bits, q_bits, &p, &q, &g)) == kKryptosSuccess) {
        if ((d = kryptos_elgamal_get_random_mp(&d, q)) == NULL) {
            result = kKryptosProcessError;
            goto kryptos_elgamal_mk_key_pair_epilogue;
        }

        if ((b = kryptos_mp_me_mod_n(g, d, p)) == NULL) {
            result = kKryptosProcessError;
            goto kryptos_elgamal_mk_key_pair_epilogue;
        }
    }

    // INFO(Rafael): Building up the public key's PEM buffer.

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P,
                                  (kryptos_u8_t *)p->data, p->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Q,
                                  (kryptos_u8_t *)q->data, q->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_G,
                                  (kryptos_u8_t *)g->data, g->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_B,
                                  (kryptos_u8_t *)b->data, b->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    // INFO(Rafael): Building up the private key's PEM buffer.

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P,
                                  (kryptos_u8_t *)p->data, p->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_D,
                                  (kryptos_u8_t *)d->data, d->data_size * sizeof(kryptos_mp_digit_t));

kryptos_elgamal_mk_key_pair_epilogue:

    if (result != kKryptosSuccess) {
        if ((*k_pub) != NULL) {
            kryptos_freeseg(*k_pub);
            *k_pub_size = 0;
        }

        if ((*k_priv) != NULL) {
            kryptos_freeseg(*k_priv);
            *k_priv_size = 0;
        }
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    return result;
}

kryptos_task_result_t kryptos_elgamal_verify_public_key(const kryptos_u8_t *k_pub, const size_t k_pub_size) {
    kryptos_mp_value_t *p = NULL, *q = NULL, *g = NULL, *b = NULL;
    kryptos_task_result_t result = kKryptosInvalidParams;

    if (k_pub == NULL || k_pub_size == 0) {
        result = kKryptosInvalidParams;
        return kKryptosInvalidParams;
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_B, k_pub, k_pub_size, &b);

    if (result != kKryptosSuccess) {
        result = kKryptosInvalidParams;
        goto kryptos_elgamal_verify_public_key_epilogue;
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, k_pub, k_pub_size, &p);

    if (result != kKryptosSuccess) {
        result = kKryptosInvalidParams;
        goto kryptos_elgamal_verify_public_key_epilogue;
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Q, k_pub, k_pub_size, &q);

    if (result != kKryptosSuccess) {
        // WARN(Rafael): It may not be really invalid but without q is impossible ascertain that
        //               the passed public key can be considered strong, so this function returns
        //               "invalid".
        //
        //               A key with a P, any G from the interval [2, P - 2] and a B will work but
        //               some smart attacker may take advantage of this "sloppiness".
        //
        result = kKryptosInvalidParams;
        goto kryptos_elgamal_verify_public_key_epilogue;
    }

    result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_G, k_pub, k_pub_size, &g);

    if (result != kKryptosSuccess) {
        result = kKryptosInvalidParams;
        goto kryptos_elgamal_verify_public_key_epilogue;
    }

    result = kryptos_verify_dl_params(p, q, g);

kryptos_elgamal_verify_public_key_epilogue:

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    return result;
}

void kryptos_elgamal_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherELGAMAL;

    ktask->key = key;
    ktask->key_size = key_size;
}

void kryptos_elgamal_cipher(kryptos_task_ctx **ktask) {
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
        kryptos_elgamal_encrypt(ktask);
    } else if ((*ktask)->action == kKryptosDecrypt) {
        kryptos_elgamal_decrypt(ktask);
    } else {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "Invalid action.";
    }
}

void kryptos_elgamal_oaep_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size,
                                kryptos_u8_t *label, size_t *label_size,
                                kryptos_hash_func hash,
                                kryptos_hash_size_func hash_size) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherELGAMALOAEP;

    ktask->key = key;
    ktask->key_size = key_size;

    ktask->arg[0] = label;
    ktask->arg[1] = label_size;
    ktask->arg[2] = hash;
    ktask->arg[3] = hash_size;
}

void kryptos_elgamal_oaep_cipher(kryptos_task_ctx **ktask) {
    // WARN(Rafael): Even having a probabilistic encryption in essence, I find nice to combine OAEP and Elgamal.
    kryptos_u8_t *old_in = NULL, *temp = NULL;
    size_t old_in_size = 0;
    kryptos_mp_value_t *p = NULL;

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

    if (kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &p) != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get p.";
        goto kryptos_elgamal_oaep_cipher_epilogue;
    }

    if ((*ktask)->action == kKryptosEncrypt) {
        old_in = (*ktask)->in;
        old_in_size = (*ktask)->in_size;

        temp = kryptos_apply_oaep_padding((*ktask)->in, &(*ktask)->in_size, kryptos_mp_byte2bit(p->data_size) >> 3,
                                          (*ktask)->arg[0], (*ktask)->arg[1] != NULL ? *(size_t *)(*ktask)->arg[1] : 0,
                                          (kryptos_hash_func)(*ktask)->arg[2], (kryptos_hash_size_func)(*ktask)->arg[3]);

        if (temp == NULL) {
            (*ktask)->result = kKryptosProcessError;
            (*ktask)->result_verbose = "Error during OAEP padding.";
            goto kryptos_elgamal_oaep_cipher_epilogue;
        }

        (*ktask)->in = temp;
        kryptos_elgamal_encrypt(ktask);
    } else {
        kryptos_elgamal_decrypt(ktask);

        if ((*ktask)->result == kKryptosSuccess) {
            temp = (*ktask)->out;

            (*ktask)->out = kryptos_drop_oaep_padding(temp, &(*ktask)->out_size, kryptos_mp_byte2bit(p->data_size) >> 3,
                                                      (*ktask)->arg[0],
                                                      (*ktask)->arg[1] != NULL ? *(size_t *)(*ktask)->arg[1] : 0,
                                                      (kryptos_hash_func)(*ktask)->arg[2],
                                                      (kryptos_hash_size_func)(*ktask)->arg[3]);

            if ((*ktask)->out == NULL) {
                (*ktask)->result = kKryptosProcessError;
                (*ktask)->result_verbose = "The cryptogram is corrupted.";
                (*ktask)->out_size = 0;
            }
        }
    }

    if (temp != NULL) {
        kryptos_freeseg(temp);
    }

kryptos_elgamal_oaep_cipher_epilogue:

    if (old_in != NULL) {
        (*ktask)->in = old_in;
        (*ktask)->in_size = old_in_size;
        old_in = NULL;
        old_in_size = 0;
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }
}

static kryptos_mp_value_t *kryptos_elgamal_get_random_mp(kryptos_mp_value_t **mp,
                                                         const kryptos_mp_value_t *q) {
    kryptos_mp_value_t *_2 = NULL, *q_2 = NULL;
    size_t bits;

    if (mp == NULL || q == NULL) {
        return NULL;
    }

    (*mp) = NULL;

    _2 = kryptos_hex_value_as_mp("2", 1);

    if (_2 == NULL) {
        goto kryptos_elgamal_get_random_mp_epilogue;
    }

    q_2 = kryptos_assign_mp_value(&q_2, q);

    if (q_2 == NULL) {
        goto kryptos_elgamal_get_random_mp_epilogue;
    }

    q_2 = kryptos_mp_sub(&q_2, _2);

    if (q_2 == NULL) {
        goto kryptos_elgamal_get_random_mp_epilogue;
    }

    bits = kryptos_mp_byte2bit(q->data_size);

    do {
        if (*mp != NULL) {
            kryptos_del_mp_value(*mp);
        }
        (*mp) = kryptos_mp_rand(bits);
    } while (*mp == NULL || kryptos_mp_lt(*mp, _2) || kryptos_mp_gt(*mp, q_2));

kryptos_elgamal_get_random_mp_epilogue:

    if (_2 != NULL) {
        kryptos_del_mp_value(_2);
    }

    if (q_2 != NULL) {
        kryptos_del_mp_value(q_2);
    }

    return (*mp);
}

static void kryptos_elgamal_encrypt(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *p = NULL, *q = NULL, *g = NULL, *b = NULL, *i = NULL, *ke = NULL, *km = NULL, *p_1 = NULL, *_1 = NULL;
    kryptos_mp_value_t *x = NULL, *y = NULL, *y_mod = NULL;

    // WARN(Rafael): If you was stupid enough to call this with out pointing to another well-allocated memory chunk... your
    //               fault.

    (*ktask)->out = NULL;
    (*ktask)->out_size = 0;

    // INFO(Rafael): Extracting all public domain parameters.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &p);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get p from key buffer.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    p_1 = kryptos_assign_mp_value(&p_1, p);

    if (p_1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to eval p - 1.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to eval p - 1.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    p_1 = kryptos_mp_sub(&p_1, _1);

    if (p_1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to eval p - 1.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    x = kryptos_raw_buffer_as_mp((*ktask)->in, (*ktask)->in_size);

    if (x == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "The input may be null.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    if (kryptos_mp_lt(x, _1) || kryptos_mp_gt(x, p_1)) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "ELGAMAL input is too long.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    kryptos_del_mp_value(_1);
    kryptos_del_mp_value(p_1);

    p_1 = _1 = NULL;

    // INFO(Rafael): Let's make permissible q be NULL and use the interval 2, p-2 instead.

    kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Q, (*ktask)->key, (*ktask)->key_size, &q);

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_G, (*ktask)->key, (*ktask)->key_size, &g);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get g from key buffer.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_B, (*ktask)->key, (*ktask)->key_size, &b);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get b from key buffer.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Picking an i based between [2, q-2] or [2, p-2].

    i = kryptos_elgamal_get_random_mp(&i, (q != NULL) ? q : p);

    if (i == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get a valid i value.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Calculating the ephemeral key.

    ke = kryptos_mp_me_mod_n(g, i, p);

    // INFO(Rafael): Now the masking key.

    km = kryptos_mp_me_mod_n(b, i, p);

    // INFO(Rafael): Encrypting.

    x = kryptos_mp_mul(&x, km);

    if (x == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while encrypting.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    y = kryptos_mp_div(x, p, &y_mod);

    if (y == NULL || y_mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while encrypting.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Exporting y(_mod) and ke.

    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Y,
                                            (kryptos_u8_t *)y_mod->data, y_mod->data_size * sizeof(kryptos_mp_digit_t));

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting y.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_ELGAMAL_PEM_HDR_PARAM_E,
                                            (kryptos_u8_t *)ke->data, ke->data_size * sizeof(kryptos_mp_digit_t));

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while exporting e.";
    }

kryptos_elgamal_encrypt_epilogue:

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (p_1 != NULL) {
        kryptos_del_mp_value(p_1);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    if (i != NULL) {
        kryptos_del_mp_value(i);
    }

    if (ke != NULL) {
        kryptos_del_mp_value(ke);
    }

    if (km != NULL) {
        kryptos_del_mp_value(km);
    }

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (y_mod != NULL) {
        kryptos_del_mp_value(y_mod);
    }

    if ((*ktask)->result != kKryptosSuccess && (*ktask)->out != NULL) {
        kryptos_freeseg((*ktask)->out);
        (*ktask)->out_size = 0;
    }
}

static void kryptos_elgamal_decrypt(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *km_inv = NULL, *_1 = NULL, *p_d_1 = NULL, *d = NULL, *p = NULL, *ke = NULL;
    kryptos_mp_value_t *y = NULL, *x = NULL, *x_mod = NULL;
    kryptos_u8_t *o;
    ssize_t o_size, xd;

    (*ktask)->out = NULL;
    (*ktask)->out_size = 0;

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &p);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get p.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &d);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get d.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to eval p - d - 1.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    p_d_1 = kryptos_assign_mp_value(&p_d_1, p);

    if (p_d_1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to eval p - d - 1.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    p_d_1 = kryptos_mp_sub(&p_d_1, d);

    if (p_d_1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to eval p - d - 1.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    p_d_1 = kryptos_mp_sub(&p_d_1, _1);

    if (p_d_1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to eval p - d - 1.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Getting the ephemeral key from the input.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_E, (*ktask)->in, (*ktask)->in_size, &ke);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get e.";
    }

    // INFO(Rafael): Pierre de Fermat rocks! :)

    km_inv = kryptos_mp_me_mod_n(ke, p_d_1, p);

    if (km_inv == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to eval km^-1.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Getting the cryptogram.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Y, (*ktask)->in, (*ktask)->in_size, &y);

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to get y.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Decrypting.

    y = kryptos_mp_mul(&y, km_inv);

    if (y == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while decrypting.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    x = kryptos_mp_div(y, p, &x_mod);

    if (x == NULL || x_mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while decrypting.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): The hardest part! ;)

    kryptos_mp_as_task_out(ktask, x_mod, o, o_size, xd, kryptos_elgamal_decrypt_epilogue);

kryptos_elgamal_decrypt_epilogue:

    if (km_inv != NULL) {
        kryptos_del_mp_value(km_inv);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (p_d_1 != NULL) {
        kryptos_del_mp_value(p_d_1);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (ke != NULL) {
        kryptos_del_mp_value(ke);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (x_mod != NULL) {
        kryptos_del_mp_value(x_mod);
    }

    if ((*ktask)->result != kKryptosSuccess && (*ktask)->out != NULL) {
        kryptos_freeseg((*ktask)->out);
        (*ktask)->out_size = 0;
    }
}
