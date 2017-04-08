/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_ENDIANESS_UTILS_H
#define KRYPTOS_ENDIANESS_UTILS_H 1

#include <kryptos_types.h>

int kryptos_little_endian_cpu(void);

kryptos_u32_t kryptos_get_u32_as_big_endian(const kryptos_u8_t *data, const size_t data_size);

kryptos_u8_t *kryptos_cpy_u32_as_big_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u32_t value);

#endif
