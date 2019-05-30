/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_ECDH_H
#define KRYPTOS_KRYPTOS_ECDH_H 1

#include <kryptos_types.h>

#define KRYPTOS_ECDH_PEM_HDR_PARAM_EC_BITS "ECDH PARAM EC BITS"

#define KRYPTOS_ECDH_PEM_HDR_PARAM_EC_P    "ECDH PARAM EC P"

#define KRYPTOS_ECDH_PEM_HDR_PARAM_EC_A    "ECDH PARAM EC A"

#define KRYPTOS_ECDH_PEM_HDR_PARAM_EC_B    "ECDH PARAM EC B"

#define KRYPTOS_ECDH_PEM_HDR_PARAM_EC_GX   "ECDH PARAM EC G X"

#define KRYPTOS_ECDH_PEM_HDR_PARAM_EC_GY   "ECDH PARAM EC G Y"

#define KRYPTOS_ECDH_PEM_HDR_PARAM_EC_Q    "ECDH PARAM EC Q"

#define KRYPTOS_ECDH_PEM_HDR_PARAM_KPX     "ECDH PARAM KP X"

#define KRYPTOS_ECDH_PEM_HDR_PARAM_KPY     "ECDH PARAM KP Y"

struct kryptos_ecdh_xchg_ctx {
    kryptos_curve_ctx *curve;
    kryptos_u8_t *in, *out;
    size_t in_size, out_size;
    kryptos_mp_value_t *k;
    char *result_verbose;
    kryptos_task_result_t result;
};

#define kryptos_ecdh_init_xchg_ctx(c) {\
    (c)->curve = NULL;\
    (c)->in = (c)->out = NULL;\
    (c)->in_size = (c)->out_size = 0;\
    (c)->k = NULL;\
    (c)->result_verbose = NULL;\
    (c)->result = kKryptosSuccess;\
}

#ifdef __cplusplus
extern "C" {
#endif

kryptos_task_result_t kryptos_ecdh_get_curve_from_params_buf(const kryptos_u8_t *params, const size_t params_size,
                                                             kryptos_curve_ctx **curve);

kryptos_task_result_t kryptos_ecdh_get_random_k(kryptos_mp_value_t **k, const kryptos_mp_value_t *q, const size_t bits);

void kryptos_ecdh_process_xchg(struct kryptos_ecdh_xchg_ctx **data);

void kryptos_clear_ecdh_xchg_ctx(struct kryptos_ecdh_xchg_ctx *data);

#ifdef __cplusplus
}
#endif

#endif
