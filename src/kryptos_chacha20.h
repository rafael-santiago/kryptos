/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_CHACHA20_H
#define KRYPTOS_KRYPTOS_CHACHA20_H 1

#include <kryptos_types.h>

#define KRYPTOS_CHACHA20_IVSIZE 12

void kryptos_chacha20_cipher(kryptos_task_ctx **ktask);

void kryptos_chacha20_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size,
                            kryptos_u8_t *iv64);

#endif
