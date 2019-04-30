/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_BLAKE2_H
#define KRYPTOS_KRYPTOS_BLAKE2_H 1

#include <kryptos_types.h>

KRYPTOS_DECL_HASH_PROCESSOR(blake2s256, ktask)

KRYPTOS_DECL_HASH_PROCESSOR(blake2b512, ktask)

KRYPTOS_DECL_HASH_PROCESSOR(blake2sN, ktask)

KRYPTOS_DECL_HASH_PROCESSOR(blake2bN, ktask)

KRYPTOS_DECL_HASH_SIZE(blake2s256)

KRYPTOS_DECL_HASH_SIZE(blake2b512)

KRYPTOS_DECL_HASH_INPUT_SIZE(blake2s256)

KRYPTOS_DECL_HASH_INPUT_SIZE(blake2b512)

#endif
