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

    (*ktask)->out_size = m->data_size * sizeof(kryptos_mp_digit_t);
    (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((*ktask)->out_size);

    if ((*ktask)->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "No memory to produce the output.";
        goto kryptos_rsa_decrypt_epilogue;
    }

    memset((*ktask)->out, 0, (*ktask)->out_size);

    o = (*ktask)->out;
    o_size = (*ktask)->out_size;

    for (xd = m->data_size - 1; xd >= 0; xd--, o += sizeof(kryptos_mp_digit_t), o_size -= sizeof(kryptos_mp_digit_t)) {
#ifdef KRYPTOS_MP_U32_DIGIT
        kryptos_cpy_u32_as_big_endian(o, o_size, m->data[xd]);
#else
        *o = m->data[xd];
#endif
    }

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

kryptos_u8_t *kryptos_pss_encode(const kryptos_u8_t *buffer, size_t *buffer_size,
                                 const size_t k, const size_t salt_size,
                                 kryptos_hash_func hash_func, kryptos_hash_size_func hash_size_func) {

    kryptos_u8_t *em = NULL, *mp = NULL, *dest = NULL, *salt = NULL, *ps = NULL, *db = NULL, *dbmask = NULL,
                 *p = NULL, *p_end = NULL;
    size_t h_size = 0, mp_size = 0, ps_size = 0, db_size = 0, dbmask_size = 0;
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_hash_size_func hash_size = kryptos_sha1_hash_size;
    kryptos_task_ctx ht, *ktask = &ht;

    if (buffer == NULL || buffer_size == NULL) {
        return NULL;
    }

    if (hash_func != NULL) {
        hash = hash_func;
    }

    if (hash_size_func != NULL) {
        hash_size = hash_size_func;
    }

    h_size = hash_size();

    kryptos_task_init_as_null(ktask);

    // WARN(Rafael): Since any hash function limitation tends to be quite huge, I will let this verification out.

    if (*buffer_size < (h_size + salt_size + 2)) {
        // INFO(Rafael): 'Encoding error'.
        goto kryptos_apply_pss_padding_epilogue;
    }

    // INFO(Rafael): Computing 'mHash'.

    ktask->in = (kryptos_u8_t *)buffer;
    ktask->in_size = *buffer_size;

    hash(&ktask, 0);

    if (ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_apply_pss_padding_epilogue;
    }

    // INFO(Rafael): Now mHash is known as ktask->out. Let's build up M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt.

    mp_size = 8 + h_size + salt_size;

    mp = (kryptos_u8_t *) kryptos_newseg(mp_size);

    if (mp == NULL) {
        goto kryptos_apply_pss_padding_epilogue;
    }

    if (memset(mp, 0, mp_size) != mp) {
        goto kryptos_apply_pss_padding_epilogue;
    }

    dest = mp + 8;

    if (memcpy(dest, ktask->out, h_size) != dest) {
        goto kryptos_apply_pss_padding_epilogue;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    if (salt_size > 0) {
        if ((salt = kryptos_get_random_block(salt_size)) != NULL) {
            dest += h_size;

            if (memcpy(dest, salt, salt_size) != dest) {
                goto kryptos_apply_pss_padding_epilogue;
            }
        }
    }

    // INFO(Rafael): Now H = Hash(M') of hLen bytes.

    ktask->in = mp;
    ktask->in_size = mp_size;

    hash(&ktask, 0);

    if (ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_apply_pss_padding_epilogue;
    }

    // INFO(Rafael): H is now known as ktask->out and hLen ktask->out_size.
    //               Let's generate PS with *buffer_size - salt_size - h_size - 2 zeroed bytes.

    ps_size = *buffer_size - salt_size - h_size - 2;

    if (ps_size > 0) {
        ps = (kryptos_u8_t *) kryptos_newseg(ps_size);

        if (ps == NULL) {
            goto kryptos_apply_pss_padding_epilogue;
        }

        if (memset(ps, 0, ps_size) != ps) {
            goto kryptos_apply_pss_padding_epilogue;
        }
    }

    db_size = ps_size + salt_size + 1;
    db = (kryptos_u8_t *) kryptos_newseg(db_size);

    if (db == NULL) {
        goto kryptos_apply_pss_padding_epilogue;
    }

    dest = db;

    if (ps_size > 0) {
        if (memcpy(dest, ps, ps_size) != dest) {
            goto kryptos_apply_pss_padding_epilogue;
        }

        dest += ps_size;
    }

    *dest = 0x01;

    if (salt_size > 0) {
        dest += 1;

        if (memcpy(dest, salt, salt_size) != dest) {
            goto kryptos_apply_pss_padding_epilogue;
        }

        kryptos_freeseg(salt);
        salt = NULL;
    }

    dbmask = kryptos_padding_mgf(ktask->out, ktask->out_size, *buffer_size - h_size - 1, hash, &dbmask_size);

    if (dbmask == NULL) {
        goto kryptos_apply_pss_padding_epilogue;
    }

    // INFO(Rafael): maskedDB = DB ^ dbmask

    dest = db;

    p = dbmask;
    p_end = dbmask + dbmask_size + 1;

    while (p != p_end) {
        *p = (*p) ^ (*dest);
        p++;
        dest++;
    }

    // INFO(Rafael): 'Set the leftmost 8 * emLen - emBits bits to zero', i.e. the first byte of dbmask is always zero.

    if (ps_size > 0) {
        *dbmask = 0x00;
    }

    // INFO(Rafael): 'EM = maskeddb || H || 0xbc.'.

    *buffer_size = dbmask_size + h_size + 1;
    em = (kryptos_u8_t *) kryptos_newseg(*buffer_size);

    if (em == NULL) {
        goto kryptos_apply_pss_padding_epilogue;
    }

    dest = em;

    if (memcpy(dest, dbmask, dbmask_size) != dest) {
        kryptos_freeseg(em);
        em = NULL;
        goto kryptos_apply_pss_padding_epilogue;
    }

    dest += dbmask_size;

    if (memcpy(dest, ktask->out, h_size) != dest) {
        kryptos_freeseg(em);
        em = NULL;
        goto kryptos_apply_pss_padding_epilogue;
    }

    dest += h_size;

    *dest = 0xBC;

    // done!

kryptos_apply_pss_padding_epilogue:

    if (dbmask != NULL) {
        kryptos_freeseg(dbmask);
    }

    if (db != NULL) {
        kryptos_freeseg(db);
    }

    if (ps != NULL) {
        kryptos_freeseg(ps);
    }

    if (mp != NULL) {
        kryptos_freeseg(mp);
    }

    if (salt != NULL) {
        kryptos_freeseg(salt);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(ktask);

    hash = NULL;
    hash_size = NULL;

    h_size = 0;

    kryptos_task_init_as_null(ktask);

    dest = p = p_end = NULL;

    if (em == NULL) {
        *buffer_size = 0;
    }

    return em;
}

const kryptos_u8_t *kryptos_pss_verify(const kryptos_u8_t *m, const size_t m_size,
                                       const kryptos_u8_t *em, const size_t em_size,
                                       const size_t k, const size_t salt_size,
                                       kryptos_hash_func hash_func, kryptos_hash_size_func hash_size_func) {
    // WARN(Rafael): Since hash function limitation is quite long I will not check if m is greater than it.

    kryptos_task_ctx ht, *ktask = &ht;
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_hash_size_func hash_size = kryptos_sha1_hash_size;
    kryptos_u8_t *mp = NULL, *dbmask = NULL, *h = NULL, *dest = NULL, *db = NULL, *p = NULL, *p_end = NULL, *salt = NULL;
    size_t h_size = 0, dbmask_size = 0, db_size = 0, mp_size = 0, ps_size = 0;
    int inconsistent = 1;

    if (m == NULL || m_size == 0 || em == NULL || em_size == 0 || k == 0) {
        return NULL;
    }

    if (hash_func != NULL) {
        hash = hash_func;
    }

    if (hash_size_func != NULL) {
        hash_size = hash_size_func;
    }

    h_size = hash_size();

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): 'If emLen < hLen + sLen + 2' -> 'inconsistent'.

    if (em_size < (h_size + salt_size + 2)) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'If the rightmost octet of EM does not have 0xbc' -> 'inconsistent'.

    if (*(em + em_size - 1) != 0xBC) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'Let mHash = Hasm(M)'.

    ktask->in = (kryptos_u8_t *)m;
    ktask->in_size = m_size;

    hash(&ktask, 0);

    if (ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): Now mHash is known as ktask->out.

    // INFO(Rafael): 'Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be the next hLen octets'

    dbmask_size = em_size - h_size - 1;
    dbmask = (kryptos_u8_t *) kryptos_newseg(dbmask_size);

    if (dbmask == NULL) {
        goto kryptos_pss_verify_epilogue;
    }

    dest = dbmask;

    if (memcpy(dest, em, dbmask_size) != dest) {
        goto kryptos_pss_verify_epilogue;
    }

    h = (kryptos_u8_t *) kryptos_newseg(h_size);

    if (h == NULL) {
        goto kryptos_pss_verify_epilogue;
    }

    dest = h;

    if (memcpy(dest, em + dbmask_size, h_size) != dest) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'If the 8 * emLen - emBits of the leftmost octet in maskedDB are not all == 0' -> 'inconsistent'.
    //               Considering (8 * emLen - emBits) always 0.

    // WARN(Rafael): PS should have size zero and this fact, implicitly, must be taken in consideration during further
    //               verifications.
    ps_size = em_size - salt_size - h_size - 2;

    if (ps_size > 0 && *dbmask != 0x00) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'Let dbMask = MGF(H, emLen - hLen - 1)'.

    db = kryptos_padding_mgf(h, h_size, em_size - h_size - 1, hash, &db_size);

    if (db == NULL) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'Let DB = maskedDB ^ dbMask'.

    p = db;
    p_end = db + db_size + 1;
    dest = dbmask;

    while (p != p_end) {
        *p = (*p) ^ (*dest);
        p++;
        dest++;
    }

    // INFO(Rafael): 'Set the letfmost 8 * emLen - emBits of the leftmost octet in DB to zero'. I.e. -> db[0].

    if (ps_size > 0) {
        *db = 0x00;
    }

    // INFO(Rafael): 'If the octect at position emLen - hLen - sLen - 1 does not have 0x01' -> 'inconsistent'.
    if (*(db + em_size - h_size - salt_size - 2) != 0x01) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero' -> 'inconsistent'.

    p = db;
    p_end = db + (em_size - h_size - salt_size - 2);

    while (p != p_end) {
        if (*p != 0x00) {
            goto kryptos_pss_verify_epilogue;
        }
        p++;
    }

    // INFO(Rafael): 'Let salt be the last sLen octets of DB'.

    if (salt_size > 0) {
        salt = (kryptos_u8_t *) kryptos_newseg(salt_size);

        if (salt == NULL) {
            goto kryptos_pss_verify_epilogue;
        }

        p = db + (db_size - salt_size);

        dest = salt;

        if (memcpy(dest, p, salt_size) != dest) {
            goto kryptos_pss_verify_epilogue;
        }
    }

    // INFO(Rafael): 'Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt.
    //               Again, mHasm is still in ktask->out.

    mp_size = 8 + ktask->out_size + salt_size;
    mp = (kryptos_u8_t *) kryptos_newseg(mp_size);

    if (mp == NULL) {
        goto kryptos_pss_verify_epilogue;
    }

    dest = mp;

    if (memset(dest, 0, mp_size) != dest) {
        goto kryptos_pss_verify_epilogue;
    }

    dest += 8;

    if (memcpy(dest, ktask->out, ktask->out_size) != dest) {
        goto kryptos_pss_verify_epilogue;
    }

    dest += ktask->out_size;

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    if (salt != NULL) {
        if (memcpy(dest, salt, salt_size) != dest) {
            goto kryptos_pss_verify_epilogue;
        }
    }

    // INFO(Rafael): 'Let H' = Hash(M'), an octet of length hLen'.

    ktask->in = mp;
    ktask->in_size = mp_size;

    hash(&ktask, 0);

    if (ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): Now ktask->out is also known as H'. 'If H = H' ' -> 'consistent'. 'Otherwise' -> 'inconsistent'.

    inconsistent = (memcmp(h, ktask->out, h_size) != 0);

kryptos_pss_verify_epilogue:

    if (mp != NULL) {
        kryptos_freeseg(mp);
    }

    if (salt != NULL) {
        kryptos_freeseg(salt);
    }

    if (dbmask != NULL) {
        kryptos_freeseg(dbmask);
    }

    if (h != NULL) {
        kryptos_freeseg(h);
    }

    if (db != NULL) {
        kryptos_freeseg(db);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(ktask);

    dest = p = p_end = NULL;

    hash = NULL;

    hash_size = NULL;

    h_size = dbmask_size = db_size = mp_size = ps_size = 0;

    return (!inconsistent) ? m : NULL;
}
