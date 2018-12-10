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

#ifdef __cplusplus
}
#endif

#endif
