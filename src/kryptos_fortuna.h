/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_FORTUNA_H
#define KRYPTOS_KRYPTOS_FORTUNA_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct kryptos_fortuna_ctx {
    size_t K_size;
    size_t seed_size;
    int call_nr;
    kryptos_u32_t C;
    kryptos_u8_t K[32];
    kryptos_u8_t seed[32];
};

struct kryptos_fortuna_ctx *kryptos_fortuna_init(const int allocate);

void kryptos_fortuna_fini(struct kryptos_fortuna_ctx *fortuna);

int kryptos_fortuna_reseed(struct kryptos_fortuna_ctx *fortuna, const kryptos_u8_t *seed, const size_t seed_size);

void *kryptos_fortuna_get_random_block(struct kryptos_fortuna_ctx *fortuna, const size_t size_in_bytes);

kryptos_u8_t kryptos_fortuna_get_random_byte(struct kryptos_fortuna_ctx *fortuna);

#ifdef __cplusplus
}
#endif

#endif
