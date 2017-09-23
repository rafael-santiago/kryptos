/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_DSA_H
#define KRYPTOS_KRYPTOS_DSA_H 1

#include <kryptos_types.h>

#define KRYPTOS_DSA_PEM_HDR_PARAM_P "DSA P"

#define KRYPTOS_DSA_PEM_HDR_PARAM_G "DSA G"

#define KRYPTOS_DSA_PEM_HDR_PARAM_Q "DSA Q"

#define KRYPTOS_DSA_PEM_HDR_PARAM_E "DSA E"

#define KRYPTOS_DSA_PEM_HDR_PARAM_D "DSA D"

#define KRYPTOS_DSA_PEM_HDR_PARAM_R "DSA R"

#define KRYPTOS_DSA_PEM_HDR_PARAM_S "DSA S"

#define KRYPTOS_DSA_PEM_HDR_PARAM_X "DSA X"

kryptos_task_result_t kryptos_dsa_mk_key_pair(const size_t p_bits, const size_t q_bits,
                                              kryptos_u8_t **k_pub, size_t *k_pub_size,
                                              kryptos_u8_t **k_priv, size_t *k_priv_size);

void kryptos_dsa_sign(kryptos_task_ctx **ktask);

void kryptos_dsa_verify(kryptos_task_ctx **ktask);

void kryptos_dsa_digital_signature_setup(kryptos_task_ctx *ktask, kryptos_u8_t *in, size_t in_size,
                                         kryptos_u8_t *key, size_t key_size, kryptos_hash_func hash);

#endif
