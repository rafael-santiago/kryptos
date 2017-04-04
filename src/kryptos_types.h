/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TYPES_H
#define KRYPTOS_KRYPTOS_TYPES_H 1

#include <stdlib.h>

#undef KRYPTOS_KERNEL_MODE
#define KRYPTOS_USER_MODE 1

typedef unsigned char kryptos_u8_t;

typedef unsigned short kryptos_u16_t;

typedef unsigned int kryptos_u32_t;

typedef unsigned long long kryptos_u64_t;

typedef enum {
    kKryptosECB = 0,
    kKryptosCBC,
    kKryptosCipherModeNr
}kryptos_cipher_mode_t;

typedef enum {
    kKryptosCipherARC4 = 0,
    kKryptosCipherSEAL,
    kKryptosCipherAES,
    kKryptosCipherNr
}kryptos_cipher_t;

typedef enum {
    kKryptosEncrypt = 0,
    kKryptosDecrypt,
    kKryptosActionNr
}kryptos_action_t;

typedef enum {
    kKryptosSuccess = 0,
    kKryptosKeyError,
    kKryptosProcessError,
    kKryptosInvalidParams,
    kKryptosInvalidCipher,
    kKryptosTaskResultNr
}kryptos_task_result_t;

typedef struct kryptos_task {
    kryptos_cipher_t cipher;
    kryptos_cipher_mode_t mode;

    kryptos_u8_t *key;
    size_t key_size;
    kryptos_u8_t *iv;
    size_t iv_size;

    kryptos_u8_t *in;
    size_t in_size;
    kryptos_u8_t *out;
    size_t out_size;

    kryptos_task_result_t result;
    char *result_verbose;
}kryptos_task_ctx;

#endif
