/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_hkdf.h>
#include <kryptos.h>

kryptos_u8_t *kryptos_do_hkdf(kryptos_u8_t *ikm,
                              size_t ikm_size,
                              kryptos_hash_func h,
                              kryptos_hash_size_func h_input_size,
                              kryptos_hash_size_func h_size,
                              kryptos_u8_t *salt, const size_t salt_size,
                              const kryptos_u8_t *info, const size_t info_size,
                              const size_t intended_osize) {
    kryptos_u8_t *prk = NULL;
    size_t prk_size;
    kryptos_u8_t *lsalt = (salt == NULL) ? (kryptos_u8_t *)"" : salt;
    size_t lsalt_size = (salt == NULL) ? 0 : salt_size;
    kryptos_hash_func lh = (h == NULL) ? kryptos_sha256_hash : h;
    kryptos_hash_size_func lh_input_size = (h_input_size == NULL) ? kryptos_sha256_hash_input_size : h_input_size;
    kryptos_hash_size_func lh_size = (h_size == NULL) ? kryptos_sha256_hash_size : h_size;
    kryptos_u8_t sfx, *T = NULL;
    kryptos_u8_t *okm = NULL, *okm_h, *okm_t;
    size_t T_size;
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    if (ikm == NULL || (salt == NULL && salt_size > 0) || (info == NULL && info_size > 0) ||
        intended_osize == 0 || intended_osize > (255 * lh_size())) {
        goto kryptos_hkdf_epilogue;
    }

    // INFO(Rafael): Step 1 extract.

    ktask->action = kKryptosEncrypt;
    ktask->key = lsalt;
    ktask->key_size = lsalt_size;

    ktask->out = (kryptos_u8_t *)kryptos_newseg(ikm_size);

    if (ktask->out == NULL) {
        goto kryptos_hkdf_epilogue;
    }

    // WARN(Rafael): In kryptos HMACs were specially designed to be used together with a cipher.
    //               Thus the HMAC input (generating step, not verifying) is the output of a kryptos task.

    memcpy(ktask->out, ikm, ikm_size);
    ktask->out_size = ikm_size;

    kryptos_hmac(&ktask, lh, lh_input_size, lh_size);

    if (!kryptos_last_task_succeed(ktask)) {
        goto kryptos_hkdf_epilogue;
    }

    prk = ktask->out;
    prk_size = h_size();

    ktask->out = NULL;

    // INFO(Rafael): Step 2 expand.

    okm = (kryptos_u8_t *) kryptos_newseg(intended_osize);

    if (okm == NULL) {
        goto kryptos_hkdf_epilogue;
    }

    okm_h = okm;
    okm_t = okm_h + intended_osize;

    sfx = 0x1;
    T_size = 0;

    ktask->key = prk;
    ktask->key_size = prk_size;

    while (okm_h != okm_t) {
        ktask->out_size = T_size + info_size + 1;
        ktask->out = (kryptos_u8_t *) kryptos_newseg(ktask->out_size);

        if (T != NULL) {
            memcpy(ktask->out, T, T_size);
        }

        if (info != NULL && info_size > 0) {
            memcpy(ktask->out + T_size, info, info_size);
        }

        *(ktask->out + T_size + info_size) = sfx++;

        // INFO(Rafael): T(n) = HMAC-Hash(PRK, T(n - 1) | Info | n)

        kryptos_hmac(&ktask, lh, lh_input_size, lh_size);

        if (!kryptos_last_task_succeed(ktask)) {
            kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
            kryptos_freeseg(okm, intended_osize);
            okm = NULL;
            goto kryptos_hkdf_epilogue;
        }

        T_size = ((okm_t - okm_h) >= prk_size) ? prk_size : (okm_t - okm_h);

        memcpy(okm_h, ktask->out, T_size);

        okm_h += T_size;

        if (T != NULL) {
            kryptos_freeseg(T, 0);
        }

        T = ktask->out;
    }

kryptos_hkdf_epilogue:

    kryptos_task_init_as_null(ktask);

    okm_h = okm_t = NULL;

    lh_input_size = NULL;
    lh_size = NULL;
    lh = NULL;

    if (prk != NULL) {
        kryptos_freeseg(prk, prk_size + ikm_size);
        prk_size = 0;
    }

    if (T != NULL) {
        kryptos_freeseg(T, T_size);
    }

    lsalt_size = 0;

    return okm;
}
