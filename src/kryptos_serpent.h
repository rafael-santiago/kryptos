/*
 *                          Copyright (C) 2007, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SERPENT_H
#define KRYPTOS_KRYPTOS_SERPENT_H 1

#include <kryptos_types.h>

#define KRYPTOS_SERPENT_BLOCKSIZE 16

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(serpent)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(serpent)

#endif
