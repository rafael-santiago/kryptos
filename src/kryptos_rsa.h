/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_RSA_H
#define KRYPTOS_KRYPTOS_RSA_H 1

#include <kryptos_types.h>

#define KRYPTOS_RSA_PEM_HDR_PARAM_N "RSA PARAM N"

#define KRYPTOS_RSA_PEM_HDR_PARAM_E "RSA PARAM E"

#define KRYPTOS_RSA_PEM_HDR_PARAM_D "RSA PARAM D"

#define KRYPTOS_RSA_PEM_HDR_PARAM_C "RSA PARAM C"

#define KRYPTOS_RSA_PEM_HDR_PARAM_X "RSA PARAM X"

#define KRYPTOS_RSA_PEM_HDR_PARAM_S "RSA PARAM S"

#ifdef __cplusplus
extern "C" {
#endif

kryptos_task_result_t kryptos_rsa_mk_key_pair(const size_t bits, kryptos_u8_t **k_pub, size_t *k_pub_size,
                                              kryptos_u8_t **k_priv, size_t *k_priv_size);

void kryptos_rsa_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size);

void kryptos_rsa_cipher(kryptos_task_ctx **ktask);

void kryptos_rsa_oaep_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size,
                            kryptos_u8_t *label, size_t *label_size,
                            kryptos_hash_func hash,
                            kryptos_hash_size_func hash_size);

void kryptos_rsa_oaep_cipher(kryptos_task_ctx **ktask);

void kryptos_rsa_sign(kryptos_task_ctx **ktask);

void kryptos_rsa_verify(kryptos_task_ctx **ktask);

void kryptos_rsa_emsa_pss_sign(kryptos_task_ctx **ktask);

void kryptos_rsa_emsa_pss_verify(kryptos_task_ctx **ktask);

void kryptos_rsa_digital_signature_setup(kryptos_task_ctx *ktask, kryptos_u8_t *in, size_t in_size,
                                         kryptos_u8_t *key, size_t key_size);

void kryptos_rsa_emsa_pss_digital_signature_setup(kryptos_task_ctx *ktask, kryptos_u8_t *in, size_t in_size,
                                                  kryptos_u8_t *key, size_t key_size, size_t *salt_size,
                                                  kryptos_hash_func hash, kryptos_hash_size_func hash_size);

#ifdef __cplusplus
}
#endif

#endif
