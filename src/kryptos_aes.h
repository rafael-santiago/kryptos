/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_AES_H
#define KRYPTOS_KRYPTOS_AES_H 1

#include <kryptos_types.h>

#define KRYPTOS_AES_BLOCKSIZE 16

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(aes128)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(aes128)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(aes192)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(aes192)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(aes256)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(aes256)

#endif
