/*
 *                          Copyright (C) 2005, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TEA_H
#define KRYPTOS_KRYPTOS_TEA_H 1

#include <kryptos_types.h>

#define KRYPTOS_TEA_BLOCKSIZE 8

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(tea)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(tea)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(tea)

#endif
