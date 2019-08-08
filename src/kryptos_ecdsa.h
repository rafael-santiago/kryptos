/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_ECDSA_H
#define KRYPTOS_KRYPTOS_ECDSA_H 1

#include <kryptos_types.h>

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_P "ECDSA P"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_A "ECDSA A"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_B "ECDSA B"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_Q "ECDSA Q"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_AX "ECDSA A X"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_AY "ECDSA A Y"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_BX "ECDSA B X"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_BY "ECDSA B Y"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_D "ECDSA D"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_X "ECDSA X"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_R "ECDSA R"

#define KRYPTOS_ECDSA_PEM_HDR_PARAM_S "ECDSA S"

#ifdef __cplusplus
extern "C" {
#endif

kryptos_task_result_t kryptos_ecdsa_mk_key_pair(const kryptos_curve_ctx *e,
                                                kryptos_u8_t **k_pub, size_t *k_pub_size,
                                                kryptos_u8_t **k_priv, size_t *k_priv_size);

void kryptos_ecdsa_sign(kryptos_task_ctx **ktask);

void kryptos_ecdsa_verify(kryptos_task_ctx **ktask);

void kryptos_ecdsa_digital_signature_setup(kryptos_task_ctx *ktask, kryptos_u8_t *in, size_t in_size,
                                           kryptos_u8_t *key, size_t key_size,
                                           kryptos_hash_func hash, kryptos_hash_size_func hash_size);

#ifdef __cplusplus
}
#endif

#endif
