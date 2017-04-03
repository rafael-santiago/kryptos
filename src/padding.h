/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_PADDING_H
#define KRYPTOS_PADDING_H 1

#include <stdlib.h>

unsigned char *kryptos_ansi_x923_padding(const unsigned char *buffer, size_t *buffer_size,
                                        const size_t block_size_in_bytes);

#endif
