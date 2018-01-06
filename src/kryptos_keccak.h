/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_KECCAK_H
#define KRYPTOS_KRYPTOS_KECCAK_H 1

#include <kryptos_types.h>

KRYPTOS_DECL_HASH_PROCESSOR(keccak224, ktask)
KRYPTOS_DECL_HASH_SIZE(keccak224)
KRYPTOS_DECL_HASH_INPUT_SIZE(keccak224)

KRYPTOS_DECL_HASH_PROCESSOR(keccak256, ktask)
KRYPTOS_DECL_HASH_SIZE(keccak256)
KRYPTOS_DECL_HASH_INPUT_SIZE(keccak256)

KRYPTOS_DECL_HASH_PROCESSOR(keccak384, ktask)
KRYPTOS_DECL_HASH_SIZE(keccak384)
KRYPTOS_DECL_HASH_INPUT_SIZE(keccak384)

KRYPTOS_DECL_HASH_PROCESSOR(keccak512, ktask)
KRYPTOS_DECL_HASH_SIZE(keccak512)
KRYPTOS_DECL_HASH_INPUT_SIZE(keccak512)

// INFO(Rafael): 'SHA-3' is only about some few changes into the keccak-1600.
//               Until now only keccak-1600 is implemented. SHA-3 is only a keccak's alias.

KRYPTOS_DECL_HASH_PROCESSOR(sha3_224, ktask)
KRYPTOS_DECL_HASH_SIZE(sha3_224)
KRYPTOS_DECL_HASH_INPUT_SIZE(sha3_224)

KRYPTOS_DECL_HASH_PROCESSOR(sha3_256, ktask)
KRYPTOS_DECL_HASH_SIZE(sha3_256)
KRYPTOS_DECL_HASH_INPUT_SIZE(sha3_256)

KRYPTOS_DECL_HASH_PROCESSOR(sha3_384, ktask)
KRYPTOS_DECL_HASH_SIZE(sha3_384)
KRYPTOS_DECL_HASH_INPUT_SIZE(sha3_384)

KRYPTOS_DECL_HASH_PROCESSOR(sha3_512, ktask)
KRYPTOS_DECL_HASH_SIZE(sha3_512)
KRYPTOS_DECL_HASH_INPUT_SIZE(sha3_512)

#endif
