/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_ELGAMAL_H
#define KRYPTOS_KRYPTOS_ELGAMAL_H 1

#include <kryptos_types.h>

#define KRYPTOS_ELGAMAL_PEM_HDR_PARAM_P "ELGAMAL PARAM P"

#define KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Q "ELGAMAL PARAM Q"

#define KRYPTOS_ELGAMAL_PEM_HDR_PARAM_G "ELGAMAL PARAM G"

#define KRYPTOS_ELGAMAL_PEM_HDR_PARAM_B "ELGAMAL PARAM B"

#define KRYPTOS_ELGAMAL_PEM_HDR_PARAM_E "ELGAMAL PARAM E"

#define KRYPTOS_ELGAMAL_PEM_HDR_PARAM_D "ELGAMAL PARAM D"

#define KRYPTOS_ELGAMAL_PEM_HDR_PARAM_Y "ELGAMAL PARAM Y"

#ifdef __cplusplus
extern "C" {
#endif

kryptos_task_result_t kryptos_elgamal_mk_key_pair(const size_t p_bits, const size_t q_bits,
                                                  kryptos_u8_t **k_pub, size_t *k_pub_size,
                                                  kryptos_u8_t **k_priv, size_t *k_priv_size);

kryptos_task_result_t kryptos_elgamal_verify_public_key(const kryptos_u8_t *k_pub, const size_t k_pub_size);

void kryptos_elgamal_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size);

void kryptos_elgamal_cipher(kryptos_task_ctx **ktask);

void kryptos_elgamal_oaep_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size,
                                kryptos_u8_t *label, size_t *label_size,
                                kryptos_hash_func hash,
                                kryptos_hash_size_func hash_size);

void kryptos_elgamal_oaep_cipher(kryptos_task_ctx **ktask);

#ifdef __cplusplus
}
#endif

#endif
