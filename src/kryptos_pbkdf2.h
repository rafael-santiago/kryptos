/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_PBKDF2_H
#define KRYPTOS_KRYPTOS_PBKDF2_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <kryptos_types.h>

// INFO(Rafael): This implementation takes into consideration PRF as a Hash function used with HMAC.

kryptos_u8_t *kryptos_do_pbkdf2(kryptos_u8_t *password, const size_t password_size,
                                kryptos_hash_func prf,
                                kryptos_hash_size_func prf_input_size,
                                kryptos_hash_size_func prf_size,
                                kryptos_u8_t *salt, const size_t salt_size,
                                const size_t count, const size_t dklen);

#define kryptos_pbkdf2(p, p_size, hname, s, s_size, count, dklen)\
    kryptos_do_pbkdf2(p, p_size,\
                      kryptos_ ## hname ## _hash,\
                      kryptos_ ## hname ## _hash_input_size,\
                      kryptos_ ## hname ## _hash_size,\
                      s, s_size, count, dklen)

#ifdef __cplusplus
}
#endif

#endif
