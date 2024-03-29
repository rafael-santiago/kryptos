/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SALSA20_H
#define KRYPTOS_KRYPTOS_SALSA20_H 1

#include <kryptos_types.h>

#define KRYPTOS_SALSA20_IVSIZE sizeof(kryptos_u64_t)

void kryptos_salsa20_cipher(kryptos_task_ctx **ktask);

void kryptos_salsa20_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size,
                           kryptos_u8_t *iv64);

#endif
