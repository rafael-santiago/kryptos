/*
 *                          Copyright (C) 2007, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_IDEA_H
#define KRYPTOS_KRYPTOS_IDEA_H 1

#include <kryptos_types.h>

#define KRYPTOS_IDEA_BLOCKSIZE 8

void kryptos_idea_cipher(kryptos_task_ctx **ktask);

void kryptos_idea_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size,
                        const kryptos_cipher_mode_t mode);

#endif
