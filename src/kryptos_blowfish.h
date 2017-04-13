/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_BLOWFISH_H
#define KRYPTOS_KRYPTOS_BLOWFISH_H 1

#include <kryptos_types.h>

#define KRYPTOS_BLOWFISH_BLOCKSIZE 8

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(blowfish)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(blowfish)

#endif
