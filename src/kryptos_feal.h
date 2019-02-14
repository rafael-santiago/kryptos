/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_FEAL_H
#define KRYPTOS_KRYPTOS_FEAL_H 1

#include <kryptos_types.h>

#define KRYPTOS_FEAL_BLOCKSIZE 8

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(feal, ktask, int *rounds)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(feal)

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_GCM_E(feal, void *rounds)

#endif
