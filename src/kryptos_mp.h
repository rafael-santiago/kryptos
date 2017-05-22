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

#define kryptos_mp_is_odd(a) ( ( (a)->data[0] & 1 ) )

#define kryptos_mp_is_even(a) ( kryptos_mp_is_odd(a) == 0 )

kryptos_mp_value_t *kryptos_mp_div(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **r);

kryptos_mp_value_t *kryptos_mp_exp(kryptos_mp_value_t *b, const kryptos_mp_value_t *e);

kryptos_mp_value_t *kryptos_mp_pow(kryptos_mp_value_t *b, const kryptos_mp_value_t *e);

kryptos_mp_value_t *kryptos_ge_mod_m(const kryptos_mp_value_t *g, const kryptos_mp_value_t *e, const kryptos_mp_value_t *m);

#endif
