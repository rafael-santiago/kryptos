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

KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(blowfish)

#ifndef __cplusplus
kryptos_u8_t *kryptos_bcrypt(const int cost,
                             const kryptos_u8_t *salt, const size_t salt_size,
                             const kryptos_u8_t *password, const size_t password_size,
                             size_t *hash_size);

int kryptos_bcrypt_verify(const kryptos_u8_t *password, const size_t password_size,
                          const kryptos_u8_t *hash, const size_t hash_size);
#else
extern "C" kryptos_u8_t *kryptos_bcrypt(const int cost,
                                        const kryptos_u8_t *salt, const size_t salt_size,
                                        const kryptos_u8_t *password, const size_t password_size,
                                        size_t *hash_size);

extern "C" int kryptos_bcrypt_verify(const kryptos_u8_t *password, const size_t password_size,
                                     const kryptos_u8_t *hash, const size_t hash_size);


#endif

#endif
