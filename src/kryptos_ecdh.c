/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_ecdh.h>
#include <kryptos_curves.h>
#include <kryptos_ec_utils.h>
#include <kryptos_pem.h>
#include <kryptos_memory.h>
#include <kryptos_mp.h>
#include <kryptos_random.h>

kryptos_task_result_t kryptos_ecdh_get_curve_from_params_buf(const kryptos_u8_t *params, const size_t params_size,
                                                             kryptos_curve_ctx **curve) {
    kryptos_task_result_t result = kKryptosProcessError;
    kryptos_u8_t *temp = NULL;
    size_t temp_size;

    if (params == NULL || params_size == 0 || curve == NULL) {
        return kKryptosInvalidParams;
    }

    *curve = NULL;

    *curve = (kryptos_curve_ctx *) kryptos_newseg(sizeof(kryptos_curve_ctx));

    if (*curve == NULL) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    (*curve)->ec = (kryptos_ec_t *) kryptos_newseg(sizeof(kryptos_ec_t));

    if ((*curve)->ec == NULL) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    (*curve)->ec->p = (*curve)->ec->a = (*curve)->ec->b = NULL;

    (*curve)->g = (kryptos_ec_pt_t *) kryptos_newseg(sizeof(kryptos_ec_pt_t));

    if ((*curve)->g == NULL) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    (*curve)->g->x = (*curve)->g->y = NULL;

    (*curve)->q = NULL;

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_P,
                                          params, params_size, &(*curve)->ec->p)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_A,
                                          params, params_size, &(*curve)->ec->a)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_B,
                                          params, params_size, &(*curve)->ec->b)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_GX,
                                          params, params_size, &(*curve)->g->x)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_GY,
                                          params, params_size, &(*curve)->g->y)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    if ((result = kryptos_pem_get_mp_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_Q,
                                          params, params_size, &(*curve)->q)) != kKryptosSuccess) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    result = kKryptosProcessError;

    temp = kryptos_pem_get_data(KRYPTOS_ECDH_PEM_HDR_PARAM_EC_BITS, params, params_size, &temp_size);

    if (temp == NULL) {
        goto kryptos_ecdh_get_curve_from_params_buf_epilogue;
    }

    (*curve)->bits = atoi((char *)temp);

    result = kKryptosSuccess;

kryptos_ecdh_get_curve_from_params_buf_epilogue:

    if (result != kKryptosSuccess && curve != NULL && (*curve) != NULL) {
        kryptos_del_curve_ctx(*curve);
        *curve = NULL;
    }

    if (temp != NULL) {
        kryptos_freeseg(temp, temp_size);
    }

    return result;
}

kryptos_task_result_t kryptos_ecdh_get_random_k(kryptos_mp_value_t **k, const kryptos_mp_value_t *q, const size_t bits) {
    kryptos_mp_value_t *_2 = NULL;
    kryptos_task_result_t result = kKryptosProcessError;
    kryptos_mp_digit_t mask = 0;
    size_t d;

    if (k == NULL || q == NULL) {
        goto kryptos_ecdh_get_random_k_epilogue;
    }

    if ((_2 = kryptos_hex_value_as_mp("2", 1)) == NULL) {
        goto kryptos_ecdh_get_random_k_epilogue;
    }

    (*k) = kryptos_new_mp_value((bits == 0 || kryptos_mp_bit2byte(bits) > q->data_size) ?
                                        kryptos_mp_byte2bit(q->data_size) : bits);

    if ((*k) == NULL) {
        goto kryptos_ecdh_get_random_k_epilogue;
    }

#ifndef KRYPTOS_MP_U32_DIGIT
    mask = 0xFF;
#else
    mask = 0xFFFFFFFF;
    if (bits < 32) {
        mask = mask >> (32 - bits);
    }
#endif

    do {
        for (d = 0; d < (*k)->data_size; d++) {
#ifndef KRYPTOS_MP_U32_DIGIT
            (*k)->data[d] = kryptos_get_random_byte();
#else
            (*k)->data[d] = (((kryptos_u32_t)kryptos_get_random_byte()) << 24 |
                             ((kryptos_u32_t)kryptos_get_random_byte()) << 16 |
                             ((kryptos_u32_t)kryptos_get_random_byte()) <<  8 |
                             ((kryptos_u32_t)kryptos_get_random_byte())) & mask;
#endif
        }
    } while (kryptos_mp_lt((*k), _2) || kryptos_mp_ge((*k), q));

    result = kKryptosSuccess;

kryptos_ecdh_get_random_k_epilogue:

    if (_2 != NULL) {
        kryptos_del_mp_value(_2);
    }

    return result;
}

void kryptos_ecdh_process_xchg(struct kryptos_ecdh_xchg_ctx **data) {
}
