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

KRYPTOS_DECL_HASH_SIZE(blake2sN)

// WARN(Rafael): The hash_size functions for blake2sN and blake2bN are not defined nor implemented. The user must implement it
//               from outside. This situation can happen when using those variable length hash functions with some HMAC stuff.

#ifndef __cplusplus
extern KRYPTOS_DECL_HASH_SIZE(blake2sN)

extern KRYPTOS_DECL_HASH_SIZE(blake2bN)
#else
KRYPTOS_DECL_HASH_SIZE(blake2bN)

KRYPTOS_DECL_HASH_SIZE(blake2bN)
#endif

KRYPTOS_DECL_HASH_INPUT_SIZE(blake2s256)

KRYPTOS_DECL_HASH_INPUT_SIZE(blake2b512)

KRYPTOS_DECL_HASH_INPUT_SIZE(blake2sN)

KRYPTOS_DECL_HASH_INPUT_SIZE(blake2bN)

#endif
