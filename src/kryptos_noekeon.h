/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_NOEKEON_H
#define KRYPTOS_KRYPTOS_NOEKEON_H 1

#include <kryptos_types.h>

#define KRYPTOS_NOEKEON_BLOCKSIZE 16

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(noekeon)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(noekeon)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(noekeon)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(noekeon_d)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(noekeon_d)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(noekeon_d)

#endif
