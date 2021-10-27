/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_DJB2_H
#define KRYPTOS_DJB2_H 1

#include <kryptos_types.h>

kryptos_u64_t kryptos_djb2(const kryptos_u8_t *input, const size_t input_size);

#endif
