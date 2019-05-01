/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_HEX_H
#define KRYPTOS_KRYPTOS_HEX_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

void kryptos_u32_to_hex(kryptos_u8_t *buf, const size_t buf_size, const kryptos_u32_t u32);

void kryptos_u64_to_hex(kryptos_u8_t *buf, const size_t buf_size, const kryptos_u64_t u64);

kryptos_u8_t *kryptos_u8_ptr_to_hex(const kryptos_u8_t *u8, const size_t u8_size, size_t *o_size);

#ifdef __cplusplus
}
#endif

#endif
