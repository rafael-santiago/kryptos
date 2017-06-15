/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_DH_H
#define KRYPTOS_KRYPTOS_DH_H 1

#include <kryptos_types.h>
#include <kryptos_mp.h>

typedef enum {
    kKryptosDHGroup1536 = 0,
    kKryptosDHGroup2048,
    kKryptosDHGroup3072,
    kKryptosDHGroup4096,
    kKryptosDHGroup6144,
    kKryptosDHGroup8192,
    kKryptosDHGroupNr
}kryptos_dh_modp_group_bits_t;

kryptos_task_result_t kryptos_dh_get_modp(const kryptos_dh_modp_group_bits_t bits,
                                          kryptos_mp_value_t **p, kryptos_mp_value_t **g);

kryptos_task_result_t kryptos_dh_get_random_s(kryptos_mp_value_t **s, const kryptos_mp_value_t *p);

kryptos_task_result_t kryptos_dh_eval_t(kryptos_mp_value_t **t,
                                        const kryptos_mp_value_t *g, const kryptos_mp_value_t *s, const kryptos_mp_value_t *p);

#endif