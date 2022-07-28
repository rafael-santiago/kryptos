/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_BLAKE3_H
#define KRYPTOS_KRYPTOS_BLAKE3_H 1

#include <kryptos_types.h>

KRYPTOS_DECL_HASH_PROCESSOR(blake3, ktask)

KRYPTOS_DECL_HASH_PROCESSOR(blake3N, ktask)

KRYPTOS_DECL_HASH_SIZE(blake3)

#ifdef __cplusplus

extern KRYPTOS_DECL_HASH_SIZE(blake3N);

#endif

KRYPTOS_DECL_HASH_SIZE(blake3N);

// INFO(Rafael): This is the BLAKE3 key derivation routine. The hash routine is `kryptos_blake3_hash()`.
kryptos_u8_t *kryptos_blake3(kryptos_u8_t *ctx_string, const size_t ctx_string_size,
                             kryptos_u8_t *key, const size_t key_size, const size_t derived_size);


KRYPTOS_DECL_HASH_INPUT_SIZE(blake3)

KRYPTOS_DECL_HASH_INPUT_SIZE(blake3N)

#endif
