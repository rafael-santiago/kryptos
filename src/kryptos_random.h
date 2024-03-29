/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_RANDOM_H
#define KRYPTOS_KRYPTOS_RANDOM_H 1

#include <kryptos_types.h>
#include <kryptos_fortuna.h>

#ifdef __cplusplus
extern "C" {
#endif

void *kryptos_get_random_block(const size_t size_in_bytes);

kryptos_u8_t kryptos_get_random_byte(void);

void *kryptos_sys_get_random_block(const size_t size_in_bytes);

int kryptos_set_csprng(kryptos_csprng_t csprng);

kryptos_u8_t kryptos_unbiased_rand_mod_u8(const size_t n);

kryptos_u16_t kryptos_unbiased_rand_mod_u16(const size_t n);

kryptos_u32_t kryptos_unbiased_rand_mod_u32(const size_t n);

kryptos_u64_t kryptos_unbiased_rand_mod_u64(const size_t n);

#ifdef __cplusplus
}
#endif

#endif
