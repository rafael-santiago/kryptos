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

// INFO(Rafael): It seems quite weird since we are dealing with a stream cipher but each 'stream operation' will generate
//               128-bits at once. Moreover, this cipher can use an IV in order to change the key setup. The IV has the
//               size of a half block.

#define KRYPTOS_RABBIT_BLOCKSIZE 16

void kryptos_rabbit_cipher(kryptos_task_ctx **ktask);

void kryptos_rabbit_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size, kryptos_u8_t *iv64);

#ifdef __cplusplus
}
#endif

#endif

