/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_MP_H
#define KRYPTOS_KRYPTOS_MP_H 1

#include <kryptos_types.h>

kryptos_mp_value_t *kryptos_new_mp_value(const size_t bitsize);

void kryptos_del_mp_value(kryptos_mp_value_t *mp);

kryptos_mp_value_t *kryptos_assign_mp_value(kryptos_mp_value_t **dest,
                                              const kryptos_mp_value_t *src);

kryptos_mp_value_t *kryptos_hex_value_as_mp(const kryptos_u8_t *value, const size_t value_size);

kryptos_u8_t *kryptos_mp_value_as_hex(const kryptos_mp_value_t *value, size_t *hex_size);

kryptos_mp_value_t *kryptos_mp_add(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src);

kryptos_mp_value_t *kryptos_mp_sub(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src);

kryptos_mp_value_t *kryptos_assign_hex_value_to_mp(kryptos_mp_value_t **dest,
                                                   const kryptos_u8_t *value, const size_t value_size);

kryptos_mp_value_t *kryptos_mp_mul(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src);

int kryptos_mp_eq(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

const kryptos_mp_value_t *kryptos_mp_get_gt(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

#define kryptos_mp_ne(a, b) ( kryptos_mp_eq((a), (b)) == 0 )

#define kryptos_mp_gt(a, b) ( kryptos_mp_ne((a), (b)) && kryptos_mp_get_gt((a), (b)) == (a) )

#define kryptos_mp_lt(a, b) ( kryptos_mp_gt((b), (a)) )

#define kryptos_mp_ge(a, b) ( kryptos_mp_eq((a), (b)) || kryptos_mp_get_gt((a), (b)) == (a) )

#define kryptos_mp_le(a, b) ( kryptos_mp_eq((a), (b)) || kryptos_mp_get_gt((a), (b)) == (b) )

kryptos_mp_value_t *kryptos_mp_div(kryptos_mp_value_t *dest, const kryptos_mp_value_t *src, kryptos_mp_value_t **remainder);

#endif
