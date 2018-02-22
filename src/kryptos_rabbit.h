/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_RABBIT_H
#define KRYPTOS_KRYPTOS_RABBIT_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

void kryptos_rabbit_cipher(kryptos_task_ctx **ktask);

void kryptos_rabbit_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size, kryptos_u8_t *iv64);

#ifdef __cplusplus
}
#endif

#endif

