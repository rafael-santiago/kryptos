/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_ARC4_H
#define KRYPTOS_KRYPTOS_ARC4_H 1

#include <kryptos_types.h>

void kryptos_arc4(kryptos_task_ctx **ktask);

void kryptos_arc4_set_key(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size);

#endif
