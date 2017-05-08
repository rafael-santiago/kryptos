/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_HUFFMAN_H
#define KRYPTOS_KRYPTOS_HUFFMAN_H 1

#include <kryptos_types.h>

kryptos_u8_t *kryptos_huffman_deflate(const kryptos_u8_t *in, const size_t in_size);

#endif
