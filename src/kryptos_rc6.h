/*
 *                          Copyright (C) 2006, 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_RC6_H
#define KRYPTOS_KRYPTOS_RC6_H 1

#include <kryptos_types.h>

#define KRYPTOS_RC6_BLOCKSIZE 8

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(rc6_128, ktask, int *rounds)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(rc6_128)

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(rc6_192, ktask, int *rounds)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(rc6_192)

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(rc6_256, ktask, int *rounds)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(rc6_256)

#endif
