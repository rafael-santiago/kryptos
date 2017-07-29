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

kryptos_task_result_t kryptos_rsa_mk_key_pair(const size_t bits, kryptos_u8_t **k_pub, size_t *k_pub_size,
                                              kryptos_u8_t **k_priv, size_t *k_priv_size);

void kryptos_rsa_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, size_t key_size);

void kryptos_rsa_cipher(kryptos_task_ctx **ktask);

#endif