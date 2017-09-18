/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef KRYPTOS_KRYPTOS_TYPES_H
#define KRYPTOS_KRYPTOS_TYPES_H 1

# ifndef KRYPTOS_KERNEL_MODE
#  include <stdlib.h>
#  include <stdint.h>
#  include <stddef.h>
# else
#  if defined(__FreeBSD__)
#   include <sys/cdefs.h>
#   include <sys/param.h>
#   include <sys/module.h>
#   include <sys/kernel.h>
#   include <sys/systm.h>
#   include <sys/malloc.h>
#   include <sys/libkern.h>
#  elif defined(__linux__)
#   include <bits/wordsize.h>
#   include <linux/init.h>
#   include <linux/module.h>
#   include <linux/slab.h>
#   include <linux/random.h>
typedef long intptr_t;
#  endif
# endif

#if defined(__FreeBSD__)
# ifndef KRYPTOS_KERNEL_MODE
#  include <unistd.h>
// TODO(Rafael): Find a better way of detecting c99 capabilities in FreeBSD.
#   if __ISO_C_VISIBLE >= 1999L
#    define __STDC_VERSION__ 19901L
#   endif
# endif
#endif

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

#define KRYPTOS_TASK_IN        0x01
#define KRYPTOS_TASK_OUT       0x02
#define KRYPTOS_TASK_KEY       0x04
#define KRYPTOS_TASK_IV        0x08
#define KRYPTOS_TASK_AUX_BUF0  0x10
#define KRYPTOS_TASK_AUX_BUF1  0x20

typedef unsigned char kryptos_u8_t;

typedef unsigned short kryptos_u16_t;

typedef unsigned int kryptos_u32_t;

#if __WORDSIZE == 32

typedef unsigned long long kryptos_u64_t;

#else

typedef unsigned long kryptos_u64_t;

#endif //  __WORDSIZE == 64

typedef enum {
    kKryptosECB = 0,
    kKryptosCBC,
    kKryptosOFB,
    kKryptosCipherModeNr
}kryptos_cipher_mode_t;

typedef enum {
    kKryptosCipherARC4 = 0,
    kKryptosCipherSEAL,
    kKryptosCipherAES,
    kKryptosCipherDES,
    kKryptosCipher3DES,
    kKryptosCipher3DESEDE,
    kKryptosCipherIDEA,
    kKryptosCipherRC2,
    kKryptosCipherFEAL,
    kKryptosCipherCAST5,
    kKryptosCipherCAMELLIA,
    kKryptosCipherSAFERK64,
    kKryptosCipherBLOWFISH,
    kKryptosCipherSERPENT,
    kKryptosCipherRSA,
    kKryptosCipherRSAOAEP,
    kKryptosCipherELGAMAL,
    kKryptosCipherELGAMALOAEP,
    kKryptosCipherRSAEMSAPSS,
    kKryptosCipherNr
}kryptos_cipher_t;

typedef enum {
    kKryptosEncodingBASE64,
    kKryptosEncodingUUENCODE,
    kKryptosEncodingNr
}kryptos_encoding_t;

typedef enum {
    kKryptosEncrypt = 0,
    kKryptosDecrypt,
    kKryptosEncode,
    kKryptosDecode,
    kKryptosActionNr
}kryptos_action_t;

typedef enum {
    kKryptosSuccess = 0,
    kKryptosKeyError,
    kKryptosProcessError,
    kKryptosInvalidParams,
    kKryptosInvalidCipher,
    kKryptosHMACError,
    kKryptosInvalidSignature,
    kKryptosTaskResultNr
}kryptos_task_result_t;

#define KRYPTOS_KRYPTO_TASK_ARG_NR 10

struct kryptos_task_aux_buffers_ctx {
    kryptos_u8_t *buf0, *buf1, *buf2, *buf3;
    size_t buf0_size, buf1_size, buf2_size, buf3_size;
};

typedef struct kryptos_task {
    kryptos_action_t action;
    kryptos_cipher_t cipher;
    kryptos_cipher_mode_t mode;

    kryptos_encoding_t encoder;

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

    struct kryptos_task *mirror_p;

    struct kryptos_task_aux_buffers_ctx aux_buffers;
}kryptos_task_ctx;

typedef void (*kryptos_hash_func)(kryptos_task_ctx **ktask, const int to_hex);

typedef size_t (*kryptos_hash_size_func)(void);

// WARN(Rafael): When this macro is undefined the multiprecision operations will become slower, since the radix base 2^8 will
//               be used. Anyway, if you want to use kryptos in a 8-bit processor, undefine the following macro
//               is the starting point.

#define KRYPTOS_MP_U32_DIGIT 1

#ifndef KRYPTOS_MP_U32_DIGIT
typedef kryptos_u8_t kryptos_mp_digit_t;
#else
typedef kryptos_u32_t kryptos_mp_digit_t;
#endif

typedef struct kryptos_mp_value {
    size_t data_size;
    kryptos_mp_digit_t *data;
}kryptos_mp_value_t;

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
    if ((ktask->mode == kKryptosCBC || ktask->mode == kKryptosOFB) && ktask->iv == NULL) {\
        ktask->iv = kryptos_get_random_block(cipher_block_size);\
        ktask->iv_size = cipher_block_size;\
    }\
}

#define KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(cipher_name, ktask, additional_args...)\
void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                       kryptos_u8_t *key,\
                                       const size_t key_size,\
                                       const kryptos_cipher_mode_t mode, additional_args);

#define KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(cipher_name, ktask, kCipher, cipher_block_size,\
                                                additional_arg, additional_setup_stmt)\
void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                       kryptos_u8_t *key,\
                                       const size_t key_size,\
                                       const kryptos_cipher_mode_t mode,\
                                       additional_arg) {\
    if (ktask == NULL) {\
        return;\
    }\
    ktask->cipher = kCipher;\
    ktask->mode = mode;\
    ktask->key = key;\
    ktask->key_size = key_size;\
    if ((ktask->mode == kKryptosCBC || ktask->mode == kKryptosOFB) && ktask->iv == NULL) {\
        ktask->iv = kryptos_get_random_block(cipher_block_size);\
        ktask->iv_size = cipher_block_size;\
    }\
    additional_setup_stmt;\
}

#define KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(cipher_name) void kryptos_## cipher_name ##_cipher(kryptos_task_ctx **);

#ifndef KRYPTOS_KERNEL_MODE

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
    kryptos_u8_t *in_p = NULL, *in_end = NULL, *out_p = NULL;\
    kryptos_u8_t *outblock = NULL, *outblock_p = NULL, *inblock = NULL, *inblock_p = NULL;\
    size_t in_size;\
    if (kryptos_task_check(ktask) == 0) {\
        return;\
    }\
    cipher_key_expansion_stmt;\
    if ((*ktask)->action == kKryptosEncrypt || (*ktask)->mode == kKryptosOFB) {\
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

#else

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
    static struct cipher_subkeys_struct cipher_subkeys_struct_var;\
    cipher_block_processor_t cipher_block_processor;\
    kryptos_u8_t *in_p = NULL, *in_end = NULL, *out_p = NULL;\
    kryptos_u8_t *outblock = NULL, *outblock_p = NULL, *inblock = NULL, *inblock_p = NULL;\
    size_t in_size;\
    if (kryptos_task_check(ktask) == 0) {\
        return;\
    }\
    cipher_key_expansion_stmt;\
    if ((*ktask)->action == kKryptosEncrypt || (*ktask)->mode == kKryptosOFB) {\
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

#define KRYPTOS_DECL_ENCODING_PROCESSOR(encoding_name, ktask)\
void kryptos_ ## encoding_name ## _processor(kryptos_task_ctx **ktask);

#define KRYPTOS_IMPL_ENCODING_PROCESSOR(encoding_name,\
                                        kEncoding,\
                                        ktask,\
                                        buffer_processor_t,\
                                        buffer_processor, buff_encoder, buff_decoder,\
                                        buffer_processor_stmt) \
void kryptos_ ## encoding_name ## _processor(kryptos_task_ctx **ktask) {\
    buffer_processor_t buffer_processor;\
    if ((*ktask)->encoder != kEncoding) {\
        (*ktask)->result = kKryptosInvalidParams;\
        (*ktask)->result_verbose = "Wrong encoder.";\
        goto kryptos_ ## encoding_name ## _processor_epilogue;\
    }\
    if ((*ktask)->in == NULL || (*ktask)->in_size == 0) {\
        (*ktask)->result = kKryptosInvalidParams;\
        (*ktask)->result_verbose = "Null input buffer.";\
        goto kryptos_ ## encoding_name ## _processor_epilogue;\
    }\
    if ((*ktask)->action != kKryptosEncode && (*ktask)->action != kKryptosDecode) {\
        (*ktask)->result = kKryptosInvalidParams;\
        (*ktask)->result_verbose = "Invalid action.";\
        goto kryptos_ ## encoding_name ## _processor_epilogue;\
    }\
    if ((*ktask)->action == kKryptosEncode) {\
        buffer_processor = buff_encoder;\
    } else {\
        buffer_processor = buff_decoder;\
    }\
    buffer_processor_stmt;\
    if ((*ktask)->out == NULL) {\
        (*ktask)->out_size = 0;\
        (*ktask)->result = kKryptosProcessError;\
        (*ktask)->result_verbose = "An error has occurred while processing.";\
        goto kryptos_ ## encoding_name ## _processor_epilogue;\
    }\
    (*ktask)->result = kKryptosSuccess;\
kryptos_ ## encoding_name ## _processor_epilogue:\
    buffer_processor = NULL;\
}

#define KRYPTOS_DECL_HASH_PROCESSOR(hash_name, ktask)\
void kryptos_ ## hash_name ## _hash(kryptos_task_ctx **ktask, const int to_hex);

#ifndef KRYPTOS_KERNEL_MODE

#define KRYPTOS_IMPL_HASH_PROCESSOR(hash_name,\
                                    ktask,\
                                    hash_ctx_struct, hash_ctx,\
                                    hash_epilogue,\
                                    hash_setup, hash_stmt,\
                                    to_raw_stmt, to_hex_stmt)\
void kryptos_ ## hash_name ## _hash(kryptos_task_ctx **ktask, const int to_hex) {\
    struct hash_ctx_struct hash_ctx;\
    if (ktask == NULL) {\
        return;\
    }\
    if ((*ktask)->in == NULL) {\
        (*ktask)->result = kKryptosInvalidParams;\
        (*ktask)->result_verbose = "No input was supplied.";\
        goto kryptos_ ## hash_epilogue;\
    }\
    hash_setup;\
    hash_stmt;\
    (*ktask)->result = kKryptosSuccess;\
    (*ktask)->result_verbose = NULL;\
    if (!to_hex) {\
        to_raw_stmt;\
    } else {\
        to_hex_stmt;\
    }\
kryptos_ ## hash_epilogue:\
    memset(&hash_ctx, 0, sizeof(hash_ctx));\
}

#else

#define KRYPTOS_IMPL_HASH_PROCESSOR(hash_name,\
                                    ktask,\
                                    hash_ctx_struct, hash_ctx,\
                                    hash_epilogue,\
                                    hash_setup, hash_stmt,\
                                    to_raw_stmt, to_hex_stmt)\
void kryptos_ ## hash_name ## _hash(kryptos_task_ctx **ktask, const int to_hex) {\
    static struct hash_ctx_struct hash_ctx;\
    if (ktask == NULL) {\
        return;\
    }\
    if ((*ktask)->in == NULL) {\
        (*ktask)->result = kKryptosInvalidParams;\
        (*ktask)->result_verbose = "No input was supplied.";\
        goto kryptos_ ## hash_epilogue;\
    }\
    hash_setup;\
    hash_stmt;\
    (*ktask)->result = kKryptosSuccess;\
    (*ktask)->result_verbose = NULL;\
    if (!to_hex) {\
        to_raw_stmt;\
    } else {\
        to_hex_stmt;\
    }\
kryptos_ ## hash_epilogue:\
    memset(&hash_ctx, 0, sizeof(hash_ctx));\
}

#endif

#define KRYPTOS_DECL_HASH_MESSAGE_PROCESSOR(hash_name, struct_name, struct_var)\
static void kryptos_ ## hash_name ## _process_message(struct struct_name *struct_var);

#ifndef KRYPTOS_KERNEL_MODE

#define KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR(hash_name,\
                                            struct_name, struct_var,\
                                            buffer_size, input_block_size, bits_per_block,\
                                            hash_init_stmt, hash_do_block_stmt, block_index_decision_table)\
static void kryptos_ ## hash_name ## _process_message(struct struct_name *struct_var) {\
    kryptos_u64_t i, l = ctx->total_len >> 3;\
    kryptos_u8_t buffer[buffer_size];\
    hash_init_stmt;\
    ctx->curr_len = 0;\
    if (l > 0) {\
        memset(buffer, 0, sizeof(buffer));\
        for (i = 0; i <= l; i++) {\
            if (ctx->curr_len < buffer_size && i != l) {\
                buffer[ctx->curr_len++] = ctx->message[i];\
            } else {\
                kryptos_hash_ld_u8buf_as_u ## bits_per_block  ## _blocks(buffer, ctx->curr_len,\
                                                    ctx->input.block, input_block_size,\
                                                    block_index_decision_table);\
                hash_do_block_stmt;\
                ctx->curr_len = 0;\
                memset(buffer, 0, sizeof(buffer));\
                if (i != l) {\
                    buffer[ctx->curr_len++] = ctx->message[i];\
                }\
            }\
        }\
        i = l = 0;\
    } else {\
        kryptos_hash_ld_u8buf_as_u ## bits_per_block ## _blocks("", 0,\
                                            ctx->input.block, input_block_size,\
                                            block_index_decision_table);\
        hash_do_block_stmt;\
    }\
}\

#else

#define KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR(hash_name,\
                                            struct_name, struct_var,\
                                            buffer_size, input_block_size, bits_per_block,\
                                            hash_init_stmt, hash_do_block_stmt, block_index_decision_table)\
static void kryptos_ ## hash_name ## _process_message(struct struct_name *struct_var) {\
    kryptos_u64_t i, l = ctx->total_len >> 3;\
    static kryptos_u8_t buffer[buffer_size];\
    hash_init_stmt;\
    ctx->curr_len = 0;\
    if (l > 0) {\
        memset(buffer, 0, sizeof(buffer));\
        for (i = 0; i <= l; i++) {\
            if (ctx->curr_len < buffer_size && i != l) {\
                buffer[ctx->curr_len++] = ctx->message[i];\
            } else {\
                kryptos_hash_ld_u8buf_as_u ## bits_per_block  ## _blocks(buffer, ctx->curr_len,\
                                                    ctx->input.block, input_block_size,\
                                                    block_index_decision_table);\
                hash_do_block_stmt;\
                ctx->curr_len = 0;\
                memset(buffer, 0, sizeof(buffer));\
                if (i != l) {\
                    buffer[ctx->curr_len++] = ctx->message[i];\
                }\
            }\
        }\
        i = l = 0;\
    } else {\
        kryptos_hash_ld_u8buf_as_u ## bits_per_block ## _blocks("", 0,\
                                            ctx->input.block, input_block_size,\
                                            block_index_decision_table);\
        hash_do_block_stmt;\
    }\
}\

#endif

#define KRYPTOS_DECL_HASH_SIZE(hash_name)\
size_t kryptos_ ## hash_name ## _hash_size(void);

#define KRYPTOS_IMPL_HASH_SIZE(hash_name, size)\
size_t kryptos_ ## hash_name ## _hash_size(void) {\
    return size;\
}

#define KRYPTOS_DECL_HASH_INPUT_SIZE(hash_name)\
size_t kryptos_  ## hash_name ## _hash_input_size(void);

#define KRYPTOS_IMPL_HASH_INPUT_SIZE(hash_name, size)\
size_t kryptos_ ## hash_name ## _hash_input_size(void) {\
    return size;\
}

#endif
