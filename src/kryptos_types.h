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

#ifndef NO_KRYPTOS_C99_SUPPORT
# ifdef __STDC_VERSION__
#  if __STDC_VERSION__ >= 19901L
#   define KRYPTOS_C99     1
#  endif // __STDC_VERSION__ >= 19901L
# endif // __STDC_VERSION__
#endif // NO_KRYPTOS_C99_SUPPORT

#ifndef KRYPTOS_KERNEL_MODE
# define KRYPTOS_USER_MODE 1
#endif // KRYPTOS_KERNEL_MODE

#define KRYPTOS_TASK_IN  1
#define KRYPTOS_TASK_OUT 2
#define KRYPTOS_TASK_KEY 4
#define KRYPTOS_TASK_IV  8

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
    kKryptosCipherDES,
    kKryptosCipher3DES,
    kKryptosCipherIDEA,
    kKryptosCipherRC2,
    kKryptosCipherFEAL,
    kKryptosCipherCAST5,
    kKryptosCipherCAMELLIA,
    kKryptosCipherSAFERK64,
    kKryptosCipherBLOWFISH,
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

#define KRYPTOS_KRYPTO_TASK_ARG_NR 10

typedef struct kryptos_task {
    kryptos_action_t action;
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

    void *arg[KRYPTOS_KRYPTO_TASK_ARG_NR];

    kryptos_task_result_t result;
    char *result_verbose;
}kryptos_task_ctx;

#define KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(cipher_name)\
void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                       kryptos_u8_t *key,\
                                       const size_t key_size,\
                                       const kryptos_cipher_mode_t mode);

#define KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(cipher_name, kCipher, cipher_block_size) \
void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                       kryptos_u8_t *key,\
                                       const size_t key_size,\
                                       const kryptos_cipher_mode_t mode) {\
    if (ktask == NULL) {\
        return;\
    }\
    ktask->cipher = kCipher;\
    ktask->mode = mode;\
    ktask->key = key;\
    ktask->key_size = key_size;\
    if (ktask->mode == kKryptosCBC && ktask->iv == NULL) {\
        ktask->iv = kryptos_get_random_block(cipher_block_size);\
        ktask->iv_size = cipher_block_size;\
    }\
}

#define KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(cipher_name, ktask, additional_args)\
void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                       kryptos_u8_t *key,\
                                       const size_t key_size,\
                                       const kryptos_cipher_mode_t mode, additional_args);

#define KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(cipher_name, ktask, kCipher, cipher_block_size, additional_args, additional_setup_stmt) \
void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                       kryptos_u8_t *key,\
                                       const size_t key_size,\
                                       const kryptos_cipher_mode_t mode,\
                                       additional_args) {\
    if (ktask == NULL) {\
        return;\
    }\
    ktask->cipher = kCipher;\
    ktask->mode = mode;\
    ktask->key = key;\
    ktask->key_size = key_size;\
    if (ktask->mode == kKryptosCBC && ktask->iv == NULL) {\
        ktask->iv = kryptos_get_random_block(cipher_block_size);\
        ktask->iv_size = cipher_block_size;\
    }\
    additional_setup_stmt;\
}

#define KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(cipher_name) void kryptos_## cipher_name ##_cipher(kryptos_task_ctx **);

#define KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(cipher_name,\
                                            ktask,\
                                            cipher_subkeys_struct,\
                                            cipher_subkeys_struct_var,\
                                            cipher_block_processor_t,\
                                            cipher_block_processor,\
                                            cipher_key_expansion_stmt,\
                                            cipher_block_encrypt,\
                                            cipher_additional_stmts_before_encrypting,\
                                            cipher_block_decrypt,\
                                            cipher_additional_stmts_before_decrypting,\
                                            cipher_block_size,\
                                            cipher_epilogue,\
                                            outblock,\
                                            cipher_block_processor_stmt)\
void kryptos_ ## cipher_name ## _cipher(kryptos_task_ctx **ktask) {\
    struct cipher_subkeys_struct cipher_subkeys_struct_var;\
    cipher_block_processor_t cipher_block_processor;\
    kryptos_u8_t *in_p, *in_end, *out_p;\
    kryptos_u8_t *outblock, *outblock_p, *inblock, *inblock_p;\
    size_t in_size;\
    if (kryptos_task_check(ktask) == 0) {\
        return;\
    }\
    cipher_key_expansion_stmt;\
    if ((*ktask)->action == kKryptosEncrypt) {\
        cipher_block_processor = cipher_block_encrypt;\
        cipher_additional_stmts_before_encrypting;\
    } else {\
        cipher_block_processor = cipher_block_decrypt;\
        cipher_additional_stmts_before_decrypting;\
    }\
    kryptos_meta_block_processing_prologue(cipher_block_size,\
                                           inblock, inblock_p,\
                                           outblock, outblock_p,\
                                           in_size, (*ktask)->in_size);\
    kryptos_meta_block_processing(cipher_block_size,\
                                  (*ktask)->action,\
                                  (*ktask)->mode,\
                                  (*ktask)->iv,\
                                  (*ktask)->in,\
                                  in_p, in_end,\
                                  &in_size,\
                                  (*ktask)->out, out_p,\
                                  &(*ktask)->out_size,\
                                  inblock_p,\
                                  outblock_p,\
                                  cipher_epilogue, cipher_block_processor_stmt);\
    kryptos_meta_block_processing_epilogue(cipher_epilogue,\
                                           inblock, inblock_p, in_p, in_end,\
                                           outblock, outblock_p, out_p,\
                                           in_size,\
                                           cipher_subkeys_struct_var, ktask);\
    cipher_block_processor = NULL;\
}

#endif
