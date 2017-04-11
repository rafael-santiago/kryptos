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

#endif
