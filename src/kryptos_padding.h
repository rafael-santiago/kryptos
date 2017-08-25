/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_PADDING_H
#define KRYPTOS_KRYPTOS_PADDING_H 1

#include <kryptos_types.h>

kryptos_u8_t *kryptos_ansi_x923_padding(const kryptos_u8_t *buffer, size_t *buffer_size,
                                        const size_t block_size_in_bytes, const int randomize);

kryptos_u8_t *kryptos_oaep_mgf(const kryptos_u8_t *seed, const size_t seed_size,
                               const size_t len,
                               kryptos_hash_func hash_func,
                               size_t *out_size);

#endif
