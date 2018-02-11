/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_PRESENT_H
#define KRYPTOS_KRYPTOS_PRESENT_H 1

#include <kryptos_types.h>

#define KRYPTOS_PRESENT_BLOCKSIZE 8

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(present80)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(present80)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(present128)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(present128)

#endif
