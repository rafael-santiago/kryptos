/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_DL_PARAMS_H
#define KRYPTOS_KRYPTOS_DL_PARAMS_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

kryptos_task_result_t kryptos_generate_dl_params(const size_t p_bits, const size_t q_bits,
                                                 kryptos_mp_value_t **p, kryptos_mp_value_t **q, kryptos_mp_value_t **g);

kryptos_task_result_t kryptos_verify_dl_params(const kryptos_mp_value_t *p,
                                               const kryptos_mp_value_t *q,
                                               const kryptos_mp_value_t *g);

#ifdef __cplusplus
}
#endif

#endif
