/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TWOFISH_H
#define KRYPTOS_KRYPTOS_TWOFISH_H 1

#include <kryptos_types.h>

#define KRYPTOS_TWOFISH_BLOCKSIZE 16

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(twofish128)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(twofish128)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(twofish128)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(twofish192)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(twofish192)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(twofish192)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(twofish256)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(twofish256)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(twofish256)

#endif
