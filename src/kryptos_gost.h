/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_GOST_H
#define KRYPTOS_KRYPTOS_GOST_H 1

#include <kryptos_types.h>

#define KRYPTOS_GOST_BLOCKSIZE 8

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(gost_ds)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(gost_ds)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(gost_ds)

KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(gost, ktask, kryptos_u8_t *s1, kryptos_u8_t *s2, kryptos_u8_t *s3, kryptos_u8_t *s4,
                                                    kryptos_u8_t *s5, kryptos_u8_t *s6, kryptos_u8_t *s7, kryptos_u8_t *s8)

KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(gost)

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(gost)

#endif
