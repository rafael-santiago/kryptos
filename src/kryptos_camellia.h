/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_CAMELLIA_H
#define KRYPTOS_KRYPTOS_CAMELLIA_H 1

#include <kryptos_types.h>

#define KRYPTOS_CAMELLIA_BLOCKSIZE 16

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(camellia128)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(camellia128)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(camellia192)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(camellia192)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(camellia256)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(camellia256)

#endif
