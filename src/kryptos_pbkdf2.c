/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_pbkdf2.h>
#include <kryptos_memory.h>
#include <kryptos_hmac.h>
#include <kryptos.h>
#include <string.h>

static kryptos_u8_t *kryptos_pbkdf2_f(kryptos_u8_t *p, const size_t p_size,
                                      kryptos_u8_t *s, const size_t s_size,
                                      const size_t c, const kryptos_u32_t i,
                                      kryptos_task_ctx **io,
                                      kryptos_hash_func prf,
                                      kryptos_hash_size_func prf_input_size,
                                      kryptos_hash_size_func prf_size,
                                      size_t *osize);

kryptos_u8_t *kryptos_do_pbkdf2(kryptos_u8_t *password, const size_t password_size,
                                kryptos_hash_func prf,
                                kryptos_hash_size_func prf_input_size,
                                kryptos_hash_size_func prf_size,
                                kryptos_u8_t *salt, const size_t salt_size,
                                const size_t count, const size_t dklen) {
    kryptos_u8_t *dk = NULL, *dk_p, *dk_p_end;
    kryptos_u8_t *temp = NULL, *tp, *tp_end;
    kryptos_u32_t i;
    size_t temp_size = 0, hlen;
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    if (prf_size == NULL || dklen > (((kryptos_u64_t)1 << 32) - 1) * (hlen = prf_size())) {
        // INFO(Rafael): 'Derived key too long'.
        goto kryptos_pbkdf2_epilogue;
    }

    if ((dk = (kryptos_u8_t *) kryptos_newseg(dklen)) == NULL) {
        goto kryptos_pbkdf2_epilogue;
    }

    dk_p = dk;
    dk_p_end = dk_p + dklen;

    i = 1;

    while (dk_p != dk_p_end) {
        temp = kryptos_pbkdf2_f(password, password_size, salt, salt_size, count, i++,
                                &ktask, prf, prf_input_size, prf_size,
                                &temp_size);

        if (temp == NULL || !kryptos_last_task_succeed(ktask)) {
            kryptos_freeseg(dk, dklen);
            dk = NULL;
            goto kryptos_pbkdf2_epilogue;
        }

        // WARN(Rafael): HMAC in kryptos returns the 'MAC + input', thus, hlen denotes 'MAC - input'.

        tp = temp;
        tp_end = tp + hlen;

        while (dk_p != dk_p_end && tp != tp_end) {
            *dk_p = *tp;
            dk_p++;
            tp++;
        }

        kryptos_freeseg(temp, temp_size);
        temp = NULL;
    }

kryptos_pbkdf2_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN);

    if (temp != NULL) {
        kryptos_freeseg(temp, temp_size);
    }

    return dk;
}

static kryptos_u8_t *kryptos_pbkdf2_f(kryptos_u8_t *p, const size_t p_size,
                                      kryptos_u8_t *s, const size_t s_size,
                                      const size_t c, const kryptos_u32_t i,
                                      kryptos_task_ctx **io,
                                      kryptos_hash_func prf,
                                      kryptos_hash_size_func prf_input_size,
                                      kryptos_hash_size_func prf_size,
                                      size_t *osize) {
    size_t ct;

    kryptos_task_init_as_null(*io);

    (*io)->in_size = s_size + sizeof(kryptos_u32_t);


    if (((*io)->in = (kryptos_u8_t *) kryptos_newseg((*io)->in_size)) == NULL) {
        goto kryptos_pbkdf2_f_epilogue;
    }

    if (s != NULL && s_size > 0) {
        memcpy((*io)->in, s, s_size);
    }

    ((*io)->in + s_size)[0] = i >> 24;
    ((*io)->in + s_size)[1] = (i >> 16) & 0xFF;
    ((*io)->in + s_size)[2] = (i >>  8) & 0xFF;
    ((*io)->in + s_size)[3] = i & 0xFF;

    for (ct = 0; ct < c; ct++) {
        kryptos_hmac(io, prf, prf_input_size, prf_size);
        (*io)->in = (*io)->out;
        (*io)->in_size = (*io)->out_size;
        kryptos_task_free(*io, KRYPTOS_TASK_IN);
    }

kryptos_pbkdf2_f_epilogue:

    kryptos_task_free(*io, KRYPTOS_TASK_IN);

    if (kryptos_last_task_succeed(*io)) {
        *osize = (*io)->out_size;
        (*io)->out = NULL;
    }

    return (*io)->out;
}
