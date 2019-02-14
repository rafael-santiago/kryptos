/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SHACAL1_H
#define KRYPTOS_KRYPTOS_SHACAL1_H 1

#include <kryptos_types.h>

#define KRYPTOS_SHACAL1_BLOCKSIZE 20

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(shacal1)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(shacal1)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(shacal1)

#endif
