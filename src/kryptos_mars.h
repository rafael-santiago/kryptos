/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_MARS_H
#define KRYPTOS_KRYPTOS_MARS_H 1

#include <kryptos_types.h>

#define KRYPTOS_MARS_BLOCKSIZE 16

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(mars128)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(mars128)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(mars128)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(mars192)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(mars192)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(mars192)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(mars256)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(mars256)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(mars256)

#endif
