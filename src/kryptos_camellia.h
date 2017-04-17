/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_CAMELLIA_H
#define KRYPTOS_KRYPTOS_CAMELLIA_H 1

#include <kryptos_types.h>

#define KRYPTOS_CAMELLIA_BLOCKSIZE 16

typedef enum {
    kKryptosCAMELLIA128,
    kKryptosCAMELLIA192,
    kKryptosCAMELLIA256,
    kKryptosCamelliaKeySizeNr
}kryptos_camellia_keysize_t;

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(camellia, ktask, kryptos_camellia_keysize_t *keysize);

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(camellia)

#endif
