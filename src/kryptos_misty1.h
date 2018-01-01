/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_MISTY1_H
#define KRYPTOS_KRYPTOS_MISTY1_H 1

#include <kryptos_types.h>

#define KRYPTOS_MISTY1_BLOCKSIZE 8

// INFO(Rafael): According to the MISTY1 spec the 8-rounds is recommended even
//               being possible to set up a variable rounds total. Due to it,
//               here we will assume 'n' as eight fixed rounds.

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(misty1)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(misty1)

#endif
