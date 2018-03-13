/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_IV_UTILS_H
#define KRYPTOS_KRYPTOS_IV_UTILS_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

kryptos_u8_t *kryptos_apply_iv(kryptos_u8_t *block, const kryptos_u8_t *iv, const size_t size);

void kryptos_iv_data_flush(kryptos_u8_t *iv, const kryptos_u8_t *y, const size_t size);

void kryptos_iv_inc_u32(kryptos_u8_t *iv, const size_t iv_size);

#ifdef __cplusplus
}
#endif

#endif
