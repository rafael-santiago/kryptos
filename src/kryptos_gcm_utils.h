/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_GCM_UTILS_H
#define KRYPTOS_KRYPTOS_GCM_UTILS_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

void kryptos_gcm_gf_mul(const kryptos_u32_t *x, const kryptos_u32_t *y, kryptos_u32_t *z);

kryptos_task_result_t kryptos_gcm_auth(kryptos_u8_t **c, size_t *c_size,
                                       const size_t iv_size,
                                       const kryptos_u8_t *key, const size_t key_size,
                                       const kryptos_u8_t *a, const size_t a_size,
                                       kryptos_gcm_h_func h);

kryptos_task_result_t kryptos_gcm_verify(kryptos_u8_t **c, size_t *c_size,
                                         const size_t iv_size,
                                         const kryptos_u8_t *key, const size_t key_size,
                                         const kryptos_u8_t *a, const size_t a_size,
                                         kryptos_gcm_h_func h);

#ifdef __cplusplus
}
#endif

#endif
