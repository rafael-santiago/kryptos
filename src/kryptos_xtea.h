/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_XTEA_H
#define KRYPTOS_KRYPTOS_XTEA_H 1

#include <kryptos_types.h>

#define KRYPTOS_XTEA_BLOCKSIZE 8

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(xtea, ktask, int *rounds_nr)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(xtea)

#endif
