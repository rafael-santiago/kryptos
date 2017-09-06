/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_DH_H
#define KRYPTOS_KRYPTOS_DH_H 1

#include <kryptos_types.h>
#include <kryptos_mp.h>

#define KRYPTOS_DH_PEM_HDR_PARAM_P "DH PARAM P"

#define KRYPTOS_DH_PEM_HDR_PARAM_Q "DH PARAM Q"

#define KRYPTOS_DH_PEM_HDR_PARAM_G "DH PARAM G"

#define KRYPTOS_DH_PEM_HDR_PARAM_T "DH PARAM T"

#define KRYPTOS_DH_PEM_HDR_PARAM_S "DH PARAM S"

#define KRYPTOS_DH_PEM_HDR_PARAM_U "DH PARAM U"

typedef enum {
    kKryptosDHGroup1536 = 0,
    kKryptosDHGroup2048,
    kKryptosDHGroup3072,
    kKryptosDHGroup4096,
    kKryptosDHGroup6144,
    kKryptosDHGroup8192,
    kKryptosDHGroupNr
}kryptos_dh_modp_group_bits_t;

struct kryptos_dh_xchg_ctx {
    kryptos_mp_value_t *p, *g;
    kryptos_mp_value_t *t, *s, *k;
    size_t s_bits;
    kryptos_u8_t *in, *out;
    size_t in_size, out_size;
    kryptos_u8_t *result_verbose;
    kryptos_task_result_t result;
};

#define kryptos_dh_init_xchg_ctx(xc) {\
    (xc)->p = (xc)->g = (xc)->t = \
    (xc)->s = (xc)->k = NULL;\
    (xc)->s_bits = 0;\
    (xc)->in = (xc)->out = NULL;\
    (xc)->in_size = (xc)->out_size = 0;\
    (xc)->result_verbose = NULL;\
    (xc)->result = kKryptosSuccess;\
}


kryptos_task_result_t kryptos_dh_mk_domain_params(const size_t p_bits, const size_t q_bits,
                                                  kryptos_u8_t **params, size_t *params_size);

kryptos_task_result_t kryptos_dh_verify_domain_params(const kryptos_u8_t *params, const size_t params_size);

kryptos_task_result_t kryptos_dh_get_modp_from_params_buf(const kryptos_u8_t *params, const size_t params_size,
                                                          kryptos_mp_value_t **p, kryptos_mp_value_t **g);

kryptos_task_result_t kryptos_dh_get_modp(const kryptos_dh_modp_group_bits_t bits,
                                          kryptos_mp_value_t **p, kryptos_mp_value_t **g);

kryptos_task_result_t kryptos_dh_get_random_s(kryptos_mp_value_t **s, const kryptos_mp_value_t *p, const size_t s_bits);

kryptos_task_result_t kryptos_dh_eval_t(kryptos_mp_value_t **t,
                                        const kryptos_mp_value_t *g, const kryptos_mp_value_t *s, const kryptos_mp_value_t *p);

void kryptos_dh_process_stdxchg(struct kryptos_dh_xchg_ctx **data);

void kryptos_dh_mk_key_pair(kryptos_u8_t **k_pub, size_t *k_pub_size, kryptos_u8_t **k_priv, size_t *k_priv_size,
                            struct kryptos_dh_xchg_ctx **data);

void kryptos_dh_process_modxchg(struct kryptos_dh_xchg_ctx **data);

void kryptos_clear_dh_xchg_ctx(struct kryptos_dh_xchg_ctx *data);

#endif
