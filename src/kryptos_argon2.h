/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_ARGON2_H
#define KRYPTOS_KRYPTOS_ARGON2_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <kryptos_types.h>

typedef enum kryptos_argon2_hash_type {
    kArgon2d = 0,
    kArgon2i,
    kArgon2id
}kryptos_argon2_hash_type_t;

kryptos_u8_t *kryptos_do_argon2(kryptos_u8_t *password, const size_t password_size,
                                kryptos_u8_t *salt, const size_t salt_size,
                                const kryptos_u32_t parallelism,
                                const kryptos_u32_t tag_size,
                                const kryptos_u32_t memory_size_kb, const kryptos_u32_t iterations,
                                kryptos_u8_t *key, const size_t key_size,
                                kryptos_u8_t *associated_data, const size_t associated_data_size,
                                const kryptos_argon2_hash_type_t htype);

// INFO(Rafael): When using those convenience macros you do not need to pass memory_size in kilobytes.
//               Just pass it as an integer amount and the macro will convert it to kbyte for you.

#define kryptos_argon2d(p, p_size, s, s_size, pl, t_size, m, i, k, k_size, a, a_size)\
    kryptos_do_argon2(p, p_size, s, s_size, pl, t_size, m, i, k, k_size, a, a_size, kArgon2d)

#define kryptos_argon2i(p, p_size, s, s_size, pl, t_size, m, i, k, k_size, a, a_size)\
    kryptos_do_argon2(p, p_size, s, s_size, pl, t_size, m, i, k, k_size, a, a_size, kArgon2i)

#define kryptos_argon2id(p, p_size, s, s_size, pl, t_size, m, i, k, k_size, a, a_size)\
    kryptos_do_argon2(p, p_size, s, s_size, pl, t_size, m, i, k, k_size, a, a_size, kArgon2id)

#ifdef __cplusplus
}
#endif

#endif
