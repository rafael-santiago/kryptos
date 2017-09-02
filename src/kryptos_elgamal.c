/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_elgamal.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <kryptos_mp.h>
#include <kryptos_pem.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_task_check.h>
#ifndef KRYPTOS_KERNEL_MODE
#include <string.h>
#endif

static kryptos_task_result_t kryptos_elgamal_generate_p_a_d(const size_t bits,
                                                            kryptos_mp_value_t **p,
                                                            kryptos_mp_value_t **a,
                                                            kryptos_mp_value_t **d);

static kryptos_mp_value_t *kryptos_elgamal_get_random_mp(kryptos_mp_value_t **mp,
                                                         const size_t bits, const kryptos_mp_value_t *p);

static void kryptos_elgamal_encrypt(kryptos_task_ctx **ktask);

static void kryptos_elgamal_decrypt(kryptos_task_ctx **ktask);

kryptos_task_result_t kryptos_elgamal_mk_key_pair(const size_t bits, kryptos_u8_t **k_pub, size_t *k_pub_size,
                                                  kryptos_u8_t **k_priv, size_t *k_priv_size) {
    kryptos_mp_value_t *p = NULL, *a = NULL, *d = NULL, *b = NULL;
    kryptos_task_result_t result = kKryptosSuccess;

    if (k_pub == NULL || k_pub_size == NULL || k_priv == NULL || k_priv_size == NULL) {
        return kKryptosInvalidParams;
    }

    if (bits < 16) {
        return kKryptosInvalidParams;
    }

    result = kryptos_elgamal_generate_p_a_d(bits, &p, &a, &d);

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    b = kryptos_mp_me_mod_n(a, d, p);

    if (b == NULL) {
        result = kKryptosProcessError;
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_A,
                                  (kryptos_u8_t *)a->data, a->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P,
                                  (kryptos_u8_t *)p->data, p->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_pub, k_pub_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_B,
                                  (kryptos_u8_t *)b->data, b->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_A,
                                  (kryptos_u8_t *)a->data, a->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P,
                                  (kryptos_u8_t *)p->data, p->data_size * sizeof(kryptos_mp_digit_t));

    if (result != kKryptosSuccess) {
        goto kryptos_elgamal_mk_key_pair_epilogue;
    }

    result = kryptos_pem_put_data(k_priv, k_priv_size, KRYPTOS_ELGAMAL_PEM_HDR_PARAM_D,
                                  (kryptos_u8_t *)d->data, d->data_size * sizeof(kryptos_mp_digit_t));

kryptos_elgamal_mk_key_pair_epilogue:

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
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

static kryptos_task_result_t kryptos_elgamal_generate_p_a_d(const size_t bits,
                                                            kryptos_mp_value_t **p,
                                                            kryptos_mp_value_t **a,
                                                            kryptos_mp_value_t **d) {
    kryptos_task_result_t result = kKryptosSuccess;

    (*p) = kryptos_mp_gen_prime(bits);

    if (*p == NULL) {
        return kKryptosProcessError;
    }

    (*a) = kryptos_elgamal_get_random_mp(a, bits, *p);

    if ((*a) == NULL) {
        result = kKryptosProcessError;
        goto kryptos_elgamal_generate_p_a_d_epilogue;
    }

    (*d) = kryptos_elgamal_get_random_mp(d, bits, *p);

    if ((*d) == NULL) {
        result = kKryptosProcessError;
    }

kryptos_elgamal_generate_p_a_d_epilogue:

    if (result != kKryptosSuccess) {
        if ((*p) != NULL) {
            kryptos_del_mp_value(*p);
            (*p) = NULL;
        }

        if ((*a) != NULL) {
            kryptos_del_mp_value(*a);
            (*a) = NULL;
        }

        if ((*d) != NULL) {
            kryptos_del_mp_value(*d);
            (*d) = NULL;
        }
    }

    return result;
}

static kryptos_mp_value_t *kryptos_elgamal_get_random_mp(kryptos_mp_value_t **mp,
                                                         const size_t bits, const kryptos_mp_value_t *p) {
    kryptos_mp_value_t *_2 = NULL, *p_2 = NULL;
    kryptos_u8_t t;

    if (mp == NULL || p == NULL) {
        return NULL;
    }

    (*mp) = NULL;

    _2 = kryptos_hex_value_as_mp("2", 1);

    if (_2 == NULL) {
        goto kryptos_elgamal_get_random_mp_epilogue;
    }

    p_2 = kryptos_assign_mp_value(&p_2, p);

    if (p_2 == NULL) {
        goto kryptos_elgamal_get_random_mp_epilogue;
    }

    p_2 = kryptos_mp_sub(&p_2, _2);

    if (p_2 == NULL) {
        goto kryptos_elgamal_get_random_mp_epilogue;
    }

    t = kryptos_get_random_byte() & 0x1;

    do {
        if (*mp == NULL) {
            (*mp) = kryptos_mp_rand(bits);
        } else {
            if (t & 1) {
                (*mp) = kryptos_mp_sub(mp, _2);
            } else {
                (*mp) = kryptos_mp_sub(mp, p);
            }
        }
        t++;
    } while (*mp == NULL || kryptos_mp_lt(*mp, _2) || kryptos_mp_gt(*mp, p_2));

kryptos_elgamal_get_random_mp_epilogue:

    if (_2 != NULL) {
        kryptos_del_mp_value(_2);
    }

    if (p_2 != NULL) {
        kryptos_del_mp_value(p_2);
    }

    return (*mp);
}

static void kryptos_elgamal_encrypt(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *p = NULL, *b = NULL, *a = NULL, *km = NULL, *ke = NULL, *i = NULL, *m = NULL, *y = NULL, *y_mod = NULL;
    size_t bits = 0;

    if (ktask == NULL) {
        return;
    }

    // INFO(Rafael): Extracting the P, Beta and Alpha public parameters from the public key buffer.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &p);

    if ((*ktask)->result != kKryptosSuccess) {
        return;
    }

    bits = (kryptos_mp_byte2bit(p->data_size) >> 3);

    if ((*ktask)->in_size > bits) {
        (*ktask)->result = kKryptosInvalidParams;
        (*ktask)->result_verbose = "ELGAMAL input is too long.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_B, (*ktask)->key, (*ktask)->key_size, &b);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_elgamal_encrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_A, (*ktask)->key, (*ktask)->key_size, &a);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Picking a random value for building up our ephemeral key.

    i = kryptos_elgamal_get_random_mp(&i, bits, p);

    if (i == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "An error has occurred while trying to get a valid random i.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Now actually calculating this ephemeral value.

    ke = kryptos_mp_me_mod_n(a, i, p);

    if (ke == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "An error has occurred while trying to calculate ke.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Calculating the masking key.

    km = kryptos_mp_me_mod_n(b, i, p);

    if (km == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "An error has occurred while trying to calculate km.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Input buffer reading.

    m = kryptos_raw_buffer_as_mp((*ktask)->in, (*ktask)->in_size);

    if (m == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while reading the input buffer.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Encryption.

    if ((m = kryptos_mp_mul(&m, km)) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating y.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    if ((y = kryptos_mp_div(m, p, &y_mod)) == NULL || y_mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating y mod p.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    // INFO(Rafael): Exporting the ephemeral key and the cryptogram.

    (*ktask)->out = NULL;
    (*ktask)->out_size = 0;
    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_ELGAMAL_PEM_HDR_PARAM_E,
                                            (kryptos_u8_t *)ke->data, ke->data_size * sizeof(kryptos_mp_digit_t));

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result_verbose = "Error while exporting ke data.";
        goto kryptos_elgamal_encrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_put_data(&(*ktask)->out, &(*ktask)->out_size,
                                            KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Y,
                                            (kryptos_u8_t *)y_mod->data, y_mod->data_size * sizeof(kryptos_mp_digit_t));

    if ((*ktask)->result != kKryptosSuccess) {
        (*ktask)->result_verbose = "Error while exporting y data.";
    }

kryptos_elgamal_encrypt_epilogue:

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (km != NULL) {
        kryptos_del_mp_value(km);
    }

    if (ke != NULL) {
        kryptos_del_mp_value(ke);
    }

    if (i != NULL) {
        kryptos_del_mp_value(i);
    }

    if (m != NULL) {
        kryptos_del_mp_value(m);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (y_mod != NULL) {
        kryptos_del_mp_value(y_mod);
    }

    bits = 0;

    if ((*ktask)->result != kKryptosSuccess && (*ktask)->out != NULL) {
        kryptos_freeseg((*ktask)->out);
        (*ktask)->out = NULL;
        (*ktask)->out_size = 0;
    }
}

static void kryptos_elgamal_decrypt(kryptos_task_ctx **ktask) {
    kryptos_mp_value_t *x = NULL, *x_mod = NULL, *y = NULL, *p_d_1 = NULL, *p = NULL, *d = NULL, *_1 = NULL, *ke = NULL,
                       *km_inv = NULL;
    ssize_t xd, o_size;
    kryptos_u8_t *o = NULL;

    if (ktask == NULL) {
        return;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Unable to alocate multiprecision constant.";
        return;
    }

    // INFO(Rafael): Reading the P and D parameters from the private key buffer.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P, (*ktask)->key, (*ktask)->key_size, &p);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_elgamal_decrypt_epilogue;
    }

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_D, (*ktask)->key, (*ktask)->key_size, &d);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Reading the ephemeral key from input.

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_E, (*ktask)->in, (*ktask)->in_size, &ke);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Reading Y from input (the masked cryptogram).

    (*ktask)->result = kryptos_pem_get_mp_data(KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Y, (*ktask)->in, (*ktask)->in_size, &y);

    if ((*ktask)->result != kKryptosSuccess) {
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Calculating p - d - 1, this will be used as an expoent.

    if ((p_d_1 = kryptos_assign_mp_value(&p_d_1, p)) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating (p - d - 1) exponent.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    if ((p_d_1 = kryptos_mp_sub(&p_d_1, d)) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating (p - d - 1) expoent.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    if ((p_d_1 = kryptos_mp_sub(&p_d_1, _1)) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating (p - d - 1) expoent.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Applying the Fermat's little theorem. Supported by his theorem we can avoid running
    //               the Extended Euclidean algorithm to get the inverse of the masking key.
    //               Fermat rocks!

    // TODO(Rafael): Using the Fermat's little theorem here allow us to eliminate the Beta from the private key buffer.
    //               Stop exporting it during the key pair generating phase. It became a useless piece of information.

    if ((km_inv = kryptos_mp_me_mod_n(ke, p_d_1, p)) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating km^-1.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Now un-masking the cryptogram.

    if ((y = kryptos_mp_mul(&y, km_inv)) == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose =  "Error while calculating x.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    if ((x = kryptos_mp_div(y, p, &x_mod)) == NULL || x_mod == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "Error while calculating x mod p.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    // INFO(Rafael): Re-assembling the original message.

    (*ktask)->out_size = x_mod->data_size * sizeof(kryptos_mp_digit_t);
    (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((*ktask)->out_size);

    if ((*ktask)->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "No memory to produce the output.";
        goto kryptos_elgamal_decrypt_epilogue;
    }

    memset((*ktask)->out, 0, (*ktask)->out_size);

    o = (*ktask)->out;
    o_size = (*ktask)->out_size;

    for (xd = x_mod->data_size - 1; xd >= 0; xd--, o += sizeof(kryptos_mp_digit_t), o_size -= sizeof(kryptos_mp_digit_t)) {
#ifdef KRYPTOS_MP_U32_DIGIT
        kryptos_cpy_u32_as_big_endian(o, o_size, x_mod->data[xd]);
#else
        *o = x_mod->data[xd];
#endif
    }

kryptos_elgamal_decrypt_epilogue:

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (x_mod != NULL) {
        kryptos_del_mp_value(x_mod);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (p_d_1 != NULL) {
        kryptos_del_mp_value(p_d_1);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (ke != NULL) {
        kryptos_del_mp_value(ke);
    }

    if (km_inv != NULL) {
        kryptos_del_mp_value(km_inv);
    }

    xd = o_size = 0;

    o = NULL;

    if ((*ktask)->result != kKryptosSuccess && (*ktask)->out != NULL) {
        kryptos_freeseg((*ktask)->out);
        (*ktask)->out = NULL;
        (*ktask)->out_size = 0;
    }
}
