/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_RC2_H
#define KRYPTOS_KRYPTOS_RC2_H 1

#include <kryptos_types.h>

#define KRYPTOS_RC2_BLOCKSIZE 8

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(rc2, ktask, int *T1)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(rc2)

#endif

