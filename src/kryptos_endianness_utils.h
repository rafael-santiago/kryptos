/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_ENDIANNESS_UTILS_H
#define KRYPTOS_ENDIANNESS_UTILS_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define kryptos_u32_rev(w) ( ((w) << 24) | (((w) & 0x0000FF00) << 8) | (((w) & 0x00FF0000) >> 8) | ((w) >> 24) )

#define kryptos_u64_rev(w) ( ((w) << 56)                        |\
                             (((w) & 0x000000000000FF00) << 40) |\
                             (((w) & 0x0000000000FF0000) << 24) |\
                             (((w) & 0x00000000FF000000) <<  8) |\
                             (((w) & 0x000000FF00000000) >>  8) |\
                             (((w) & 0x0000FF0000000000) >> 24) |\
                             (((w) & 0x00FF000000000000) >> 40) |\
                             ((w) >> 56) )

int kryptos_little_endian_cpu(void);

kryptos_u32_t kryptos_get_u32_as_big_endian(const kryptos_u8_t *data, const size_t data_size);

kryptos_u32_t kryptos_get_u32_as_little_endian(const kryptos_u8_t *data, const size_t data_size);

kryptos_u64_t kryptos_get_u64_as_big_endian(const kryptos_u8_t *data, const size_t data_size);

kryptos_u8_t *kryptos_cpy_u32_as_big_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u32_t value);

kryptos_u8_t *kryptos_cpy_u32_as_little_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u32_t value);

kryptos_u16_t kryptos_get_u16_as_big_endian(const kryptos_u8_t *data, const size_t data_size);

kryptos_u8_t *kryptos_cpy_u16_as_big_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u16_t value);

kryptos_u8_t *kryptos_cpy_u64_as_big_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u64_t value);

kryptos_u64_t kryptos_get_u64_as_little_endian(const kryptos_u8_t *data, const size_t data_size);

#ifdef __cplusplus
}
#endif

#endif
