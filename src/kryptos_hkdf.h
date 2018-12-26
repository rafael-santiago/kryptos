/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_HKDF_H
#define KRYPTOS_KRYPTOS_HKDF_H 1

#include <kryptos_types.h>

#ifdef __cplusplus
extern "C" {
#endif

kryptos_u8_t *kryptos_do_hkdf(kryptos_u8_t *ikm,
                              size_t ikm_size,
                              kryptos_hash_func h,
                              kryptos_hash_size_func h_input_size,
                              kryptos_hash_size_func h_size,
                              kryptos_u8_t *salt, const size_t salt_size,
                              const kryptos_u8_t *info, const size_t info_size,
                              const size_t intended_osize);

#define kryptos_hkdf(ikm, ikm_size, hash, salt, salt_size, info, info_size, intended_osize)\
    kryptos_do_hkdf(ikm, ikm_size,\
                    kryptos_ ## hash ## _hash,\
                    kryptos_ ## hash ## _hash_input_size,\
                    kryptos_ ## hash ## _hash_size,\
                    salt, salt_size,\
                    info, info_size,\
                    intended_osize)

#ifdef __cplusplus
}
#endif

#endif
