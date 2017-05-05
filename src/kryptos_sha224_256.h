/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_SHA224_256_H
#define KRYPTOS_KRYPTOS_SHA224_256_H 1

#include <kryptos_types.h>

KRYPTOS_DECL_HASH_PROCESSOR(sha224, ktask)

KRYPTOS_DECL_HASH_PROCESSOR(sha256, ktask)

KRYPTOS_DECL_HASH_SIZE(sha224)

KRYPTOS_DECL_HASH_SIZE(sha256)

KRYPTOS_DECL_HASH_INPUT_SIZE(sha224)

KRYPTOS_DECL_HASH_INPUT_SIZE(sha256)

#endif
