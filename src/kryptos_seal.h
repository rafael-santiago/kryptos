/*
 *                          Copyright (C) 2007, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SEAL_H
#define KRYPTOS_KRYPTOS_SEAL_H 1

#include <kryptos_types.h>

// INFO(Rafael): Until now these are the available versions.
typedef enum kryptos_sealknds {
    kKryptosSEAL20 = 2, kKryptosSEAL30
}kryptos_seal_version_t;

#ifdef __cplusplus
extern "C" {
#endif

void kryptos_seal_cipher(kryptos_task_ctx **ktask);

void kryptos_seal_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size,
                        kryptos_seal_version_t *algo_version, size_t *L, size_t *n);

#ifdef __cplusplus
}
#endif

#endif
