/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_HMAC_H
#define KRYPTOS_KRYPTOS_HMAC_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

void kryptos_hmac(kryptos_task_ctx **ktask,
                  kryptos_hash_func h, kryptos_hash_size_func h_input_size, kryptos_hash_size_func h_size);

#ifdef __cplusplus
}
#endif

#endif
