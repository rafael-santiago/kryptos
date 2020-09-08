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
#  if defined(__FreeBSD__) || defined(__NetBSD__)
#   include <sys/cdefs.h>
#   include <sys/param.h>
#   include <sys/module.h>
#   include <sys/kernel.h>
#   include <sys/systm.h>
#   include <sys/malloc.h>
#    if defined(__FreeBSD__)
#     include <sys/libkern.h>
#    else
#     include <lib/libkern/libkern.h>
#     include <sys/cprng.h>
#    endif
#  elif defined(__linux__)
#   include <linux/init.h>
#   include <linux/module.h>
#   include <linux/slab.h>
#   include <linux/random.h>
    typedef long intptr_t;
#  endif
# endif

#if defined(_WIN32)
# include <windows.h>
# include <sdkddkver.h>
# include <sys/types.h>
# if (_WIN32_WINNT >= 0x0600)
#  include <bcrypt.h>
# else
#  include <wincrypt.h>
# endif
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
# ifndef KRYPTOS_KERNEL_MODE
#  include <unistd.h>
// TODO(Rafael): Find a better way of detecting c99 capabilities in FreeBSD.
#   if __ISO_C_VISIBLE >= 1999L && !defined(__STDC_VERSION__)
#    define __STDC_VERSION__ 199901L
#   endif
# endif
#endif

#ifndef NO_KRYPTOS_C99_SUPPORT
# ifdef __STDC_VERSION__
#  if __STDC_VERSION__ >= 199901L
#   define KRYPTOS_C99     1
#  endif // __STDC_VERSION__ >= 199901L
# else
#  ifdef __cplusplus
#   define KRYPTOS_C99     1
#  endif
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

// WARN(Rafael): When 'bits/wordsize.h' is lacking...

#if defined(__unix__) && !defined(KRYPTOS_KERNEL_MODE)
# include <sys/param.h>
# if defined(BSD)
#  include <sys/types.h>
#  include <unistd.h>
#  include <sys/endian.h>
# endif
# if !defined(__WORDSIZE)
// INFO(Rafael): OpenBSD branches to this if clause.
#  if defined(__amd64__) || defined(__x86_64__)
#   define __WORDSIZE 64
#  else
#   define __WORDSIZE 32
#  endif
# endif
#elif !defined(__WORDSIZE) && defined(KRYPTOS_KERNEL_MODE)
// INFO(Rafael): Until now it is only for NetBSD.
# if defined(__x86_64__) || defined(__amd64__)
#  define __WORDSIZE 64
# else
#  define __WORDSIZE 32
# endif
#endif

#if defined(_WIN64) && !defined(__WORDSIZE)
# define __WORDSIZE 64
#elif defined(_WIN32)&& !defined(__WORDSIZE)
# define __WORDSIZE 32
#elif !defined(__WORDSIZE)
# error I cannot guess the word size of this machine.
#endif

#if __WORDSIZE == 32
 typedef unsigned long long kryptos_u64_t;
#else
 typedef unsigned long kryptos_u64_t;
#endif //  __WORDSIZE == 64

typedef enum {
    kKryptosECB = 0,
    kKryptosCBC,
    kKryptosOFB,
    kKryptosCTR,
    kKryptosGCM,
    kKryptosCipherModeNr
}kryptos_cipher_mode_t;

typedef enum {
    // INFO(Rafael): Stream ciphers.
    kKryptosCipherARC4 = 0,
    kKryptosCipherSEAL,
    kKryptosCipherRABBIT,
    // INFO(Rafael): Block ciphers.
    kKryptosCipherAES128,
    kKryptosCipherAES192,
    kKryptosCipherAES256,
    kKryptosCipherDES,
    kKryptosCipher3DES,
    kKryptosCipher3DESEDE,
    kKryptosCipherIDEA,
    kKryptosCipherRC2,
    kKryptosCipherRC5,
    kKryptosCipherRC6128,
    kKryptosCipherRC6192,
    kKryptosCipherRC6256,
    kKryptosCipherFEAL,
    kKryptosCipherCAST5,
    kKryptosCipherCAMELLIA,
    kKryptosCipherSAFERK64,
    kKryptosCipherBLOWFISH,
    kKryptosCipherSERPENT,
    kKryptosCipherTEA,
    kKryptosCipherXTEA,
    kKryptosCipherMISTY1,
    kKryptosCipherMARS128,
    kKryptosCipherMARS192,
    kKryptosCipherMARS256,
    kKryptosCipherPRESENT,
    kKryptosCipherSHACAL1,
    kKryptosCipherSHACAL2,
    kKryptosCipherNOEKEON,
    kKryptosCipherNOEKEOND,
    kKryptosCipherGOSTDS,
    kKryptosCipherGOST,
    // INFO(Rafael): PK algorithms.
    kKryptosCipherRSA,
    kKryptosCipherRSAOAEP,
    kKryptosCipherELGAMAL,
    kKryptosCipherELGAMALOAEP,
    kKryptosCipherRSAEMSAPSS,
    kKryptosCipherDSA,
    kKryptosCipherECDSA,
    kKryptosCipherNr
}kryptos_cipher_t;

typedef enum {
    kKryptosEncodingBASE64 = 0,
    kKryptosEncodingUUENCODE,
    kKryptosEncodingNr
}kryptos_encoding_t;

typedef enum {
    kKryptosEncrypt = 0,
    kKryptosDecrypt,
    kKryptosEncode,
    kKryptosDecode,
    kKryptosEncryptWithoutRandomPad,
    kKryptosActionNr
}kryptos_action_t;

typedef enum {
    kKryptosSuccess = 0,
    kKryptosKeyError,
    kKryptosProcessError,
    kKryptosInvalidParams,
    kKryptosInvalidCipher,
    kKryptosHMACError,
    kKryptosGMACError,
    kKryptosInvalidSignature,
    kKryptosNoSupport,
    kKryptosTaskResultNr
}kryptos_task_result_t;

typedef enum {
    kKryptosCSPRNGSystem,
    kKryptosCSPRNGFortuna
}kryptos_csprng_t;

#define KRYPTOS_KRYPTO_TASK_ARG_NR 10

struct kryptos_task_aux_buffers_ctx {
    size_t buf0_size, buf1_size, buf2_size, buf3_size;
    kryptos_u8_t *buf0, *buf1, *buf2, *buf3;
};

typedef struct kryptos_task {
    struct kryptos_task_aux_buffers_ctx aux_buffers;

    size_t key_size;
    size_t iv_size;
    size_t in_size;
    size_t out_size;

    kryptos_task_result_t result;
    kryptos_action_t action;
    kryptos_cipher_t cipher;
    kryptos_cipher_mode_t mode;
    kryptos_encoding_t encoder;

    struct kryptos_task *mirror_p;
    kryptos_u8_t *key;
    kryptos_u8_t *iv;
    kryptos_u32_t *ctr;
    kryptos_u8_t *in;
    kryptos_u8_t *out;

    void *arg[KRYPTOS_KRYPTO_TASK_ARG_NR];

    char *result_verbose;
}kryptos_task_ctx;

typedef void (*kryptos_hash_func)(kryptos_task_ctx **ktask, const int to_hex);

typedef size_t (*kryptos_hash_size_func)(void);

typedef kryptos_task_result_t (*kryptos_gcm_e_func)(kryptos_u8_t **h, size_t *h_size,
                                                    kryptos_u8_t *key, size_t key_size, void *additional_arg);

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
    kryptos_u8_t neg;
}kryptos_mp_value_t;

typedef struct kryptos_ec {
    kryptos_mp_value_t *a, *b, *p;
}kryptos_ec_t;

typedef struct kryptos_ec_pt {
    kryptos_mp_value_t *x, *y;
}kryptos_ec_pt_t;

typedef enum {
    kBrainPoolP160R1,
    kBrainPoolP160T1,
    kBrainPoolP192R1,
    kBrainPoolP192T1,
    kBrainPoolP224R1,
    kBrainPoolP224T1,
    kBrainPoolP256R1,
    kBrainPoolP256T1,
    kBrainPoolP320R1,
    kBrainPoolP320T1,
    kBrainPoolP384R1,
    kBrainPoolP384T1,
    kBrainPoolP512R1,
    kBrainPoolP512T1
}kryptos_curve_id_t;

struct kryptos_std_curve_ctx {
    size_t bits;
    kryptos_curve_id_t id;
    char *p, *a, *b, *x, *y, *q;
};

typedef struct kryptos_curve {
    size_t bits;
    kryptos_ec_t *ec;
    kryptos_mp_value_t *q;
    kryptos_ec_pt_t *g;
}kryptos_curve_ctx;

#ifndef __cplusplus
#define KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(cipher_name)\
void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                       kryptos_u8_t *key,\
                                       const size_t key_size,\
                                       const kryptos_cipher_mode_t mode);

#else
#define KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_SETUP(cipher_name)\
extern "C" void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                                  kryptos_u8_t *key,\
                                                  const size_t key_size,\
                                                  const kryptos_cipher_mode_t mode);
#endif

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
    if ((ktask->mode == kKryptosCBC || ktask->mode == kKryptosOFB || ktask->mode == kKryptosCTR || ktask->mode == kKryptosGCM)\
        && ktask->iv == NULL) {\
        ktask->iv = kryptos_get_random_block(cipher_block_size);\
        ktask->iv_size = cipher_block_size;\
    }\
    if (ktask->mode == kKryptosCTR && ktask->ctr != NULL) {\
        ktask->iv[cipher_block_size - 4] = (*ktask->ctr) >> 24;\
        ktask->iv[cipher_block_size - 3] = ((*ktask->ctr) & 0xFF0000) >> 16;\
        ktask->iv[cipher_block_size - 2] = ((*ktask->ctr) & 0xFF00) >> 8;\
        ktask->iv[cipher_block_size - 1] = (*ktask->ctr) & 0xFF;\
    }\
}

#ifndef __cplusplus
#define KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(cipher_name, ktask, additional_args...)\
void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                       kryptos_u8_t *key,\
                                       const size_t key_size,\
                                       const kryptos_cipher_mode_t mode, additional_args);
#else
#define KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_SETUP(cipher_name, ktask, additional_args...)\
extern "C" void kryptos_ ## cipher_name ## _setup(kryptos_task_ctx *ktask,\
                                                  kryptos_u8_t *key,\
                                                  const size_t key_size,\
                                                  const kryptos_cipher_mode_t mode, additional_args);

#endif

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
    if ((ktask->mode == kKryptosCBC || ktask->mode == kKryptosOFB || ktask->mode == kKryptosCTR || ktask->mode == kKryptosGCM)\
        && ktask->iv == NULL) {\
        ktask->iv = kryptos_get_random_block(cipher_block_size);\
        ktask->iv_size = cipher_block_size;\
    }\
    if (ktask->mode == kKryptosCTR && ktask->ctr != NULL) {\
        ktask->iv[cipher_block_size - 4] = (*ktask->ctr) >> 24;\
        ktask->iv[cipher_block_size - 3] = ((*ktask->ctr) & 0xFF0000) >> 16;\
        ktask->iv[cipher_block_size - 2] = ((*ktask->ctr) & 0xFF00) >> 8;\
        ktask->iv[cipher_block_size - 1] = (*ktask->ctr) & 0xFF;\
    }\
    additional_setup_stmt;\
}

#ifndef __cplusplus
#define KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(cipher_name) void kryptos_## cipher_name ##_cipher(kryptos_task_ctx **);
#else
#define KRYPTOS_DECL_BLOCK_CIPHER_PROCESSOR(cipher_name) extern "C" void kryptos_## cipher_name ##_cipher(kryptos_task_ctx **);
#endif

#ifndef __cplusplus
#define KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(cipher_name)\
    kryptos_task_result_t kryptos_## cipher_name ##_e(kryptos_u8_t **h, size_t *h_size,\
                                                      kryptos_u8_t *key, size_t key_size, void *additional_arg);
#else
#define KRYPTOS_DECL_STANDARD_BLOCK_CIPHER_GCM_E(cipher_name)\
    extern "C" kryptos_task_result_t kryptos_## cipher_name ##_e(kryptos_u8_t **h,\
                                                                 size_t *h_size,\
                                                                 kryptos_u8_t *key,\
                                                                 size_t key_size, void *additional_arg);

#endif

#define KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E(cipher_name)\
kryptos_task_result_t kryptos_## cipher_name ##_e(kryptos_u8_t **h, size_t *h_size,\
                                                  kryptos_u8_t *key, size_t key_size, void *additional_arg) {\
    kryptos_task_ctx t, *ktask = &t;\
    kryptos_task_result_t result = kKryptosProcessError;\
    kryptos_task_init_as_null(ktask);\
    kryptos_## cipher_name ##_setup(ktask, key, key_size, kKryptosECB);\
    if (*h == NULL) {\
        if ((ktask->in = (kryptos_u8_t *) kryptos_newseg(16)) == NULL) {\
            goto kryptos_## cipher_name ##_e_epilogue;\
        }\
        ktask->in[ 0] = ktask->in[ 1] = ktask->in[ 2] = ktask->in[ 3] =\
        ktask->in[ 4] = ktask->in[ 5] = ktask->in[ 6] = ktask->in[ 7] =\
        ktask->in[ 8] = ktask->in[ 9] = ktask->in[10] = ktask->in[11] =\
        ktask->in[12] = ktask->in[13] = ktask->in[14] = ktask->in[15] = 0;\
        ktask->in_size = 16;\
        *h = ktask->in;\
        *h_size = 16;\
    } else {\
        ktask->in = *h;\
        ktask->in_size = *h_size;\
    }\
    kryptos_task_set_encrypt_action(ktask);\
    kryptos_## cipher_name ##_cipher(&ktask);\
    if (kryptos_last_task_succeed(ktask)) {\
        kryptos_freeseg(*h, *h_size);\
        *h = ktask->out;\
        *h_size = 16;\
        result = kKryptosSuccess;\
    }\
kryptos_## cipher_name ##_e_epilogue:\
    return result;\
}

#define KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(cipher_name)\
kryptos_task_result_t kryptos_## cipher_name ##_e(kryptos_u8_t **h, size_t *h_size,\
                                                  kryptos_u8_t *key, size_t key_size, void *additional_arg) {\
    return kKryptosNoSupport;\
}

#ifndef __cplusplus
#define KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_GCM_E(cipher_name, additional_args...)\
    kryptos_task_result_t kryptos_## cipher_name ##_e(kryptos_u8_t **h, size_t *h_size,\
                                                      kryptos_u8_t *key, size_t key_size, additional_args);
#else
#define KRYPTOS_DECL_CUSTOM_BLOCK_CIPHER_GCM_E(cipher_name, additional_args...)\
    extern "C" kryptos_task_result_t kryptos_## cipher_name ##_e(kryptos_u8_t **h, size_t *h_size,\
                                                                 kryptos_u8_t *key, size_t key_size, additional_args);
#endif

#define KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_GCM_E(cipher_name, key, key_size, additional_arg, ktask, setup_stmt)\
kryptos_task_result_t kryptos_## cipher_name ##_e(kryptos_u8_t **h, size_t *h_size,\
                                                  kryptos_u8_t *key, size_t key_size, additional_arg) {\
    kryptos_task_ctx t, *ktask = &t;\
    kryptos_task_result_t result = kKryptosProcessError;\
    kryptos_task_init_as_null(ktask);\
    setup_stmt;\
    if (*h == NULL) {\
        if ((ktask->in = (kryptos_u8_t *) kryptos_newseg(16)) == NULL) {\
            goto kryptos_## cipher_name ##_e_epilogue;\
        }\
        ktask->in[ 0] = ktask->in[ 1] = ktask->in[ 2] = ktask->in[ 3] =\
        ktask->in[ 4] = ktask->in[ 5] = ktask->in[ 6] = ktask->in[ 7] =\
        ktask->in[ 8] = ktask->in[ 9] = ktask->in[10] = ktask->in[11] =\
        ktask->in[12] = ktask->in[13] = ktask->in[14] = ktask->in[15] = 0;\
        ktask->in_size = 16;\
        *h = ktask->in;\
        *h_size = 16;\
    } else {\
        ktask->in = *h;\
        ktask->in_size = *h_size;\
    }\
    ktask->action = kKryptosEncryptWithoutRandomPad;\
    kryptos_## cipher_name ##_cipher(&ktask);\
    if (kryptos_last_task_succeed(ktask)) {\
        kryptos_freeseg(*h, *h_size);\
        *h = ktask->out;\
        *h_size = 16;\
        result = kKryptosSuccess;\
    }\
kryptos_## cipher_name ##_e_epilogue:\
    return result;\
}

#define KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_GCM_E_NO_SUPPORT(cipher_name, additional_arg)\
kryptos_task_result_t kryptos_## cipher_name ##_e(kryptos_u8_t **h, size_t *h_size,\
                                                  kryptos_u8_t *key, size_t key_size, additional_arg) {\
    return kKryptosNoSupport;\
}

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
                                            cipher_block_processor_stmt,\
                                            e_arg)\
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
    if ((*ktask)->action == kKryptosEncrypt || (*ktask)->mode == kKryptosOFB ||\
                                               (*ktask)->mode == kKryptosCTR ||\
                                               (*ktask)->mode == kKryptosGCM) {\
        cipher_block_processor = cipher_block_encrypt;\
        cipher_additional_stmts_before_encrypting;\
    } else {\
        cipher_block_processor = cipher_block_decrypt;\
        cipher_additional_stmts_before_decrypting;\
    }\
    if ((*ktask)->mode == kKryptosGCM && (*ktask)->action == kKryptosDecrypt) {\
        (*ktask)->result = kryptos_gcm_verify(&(*ktask)->in, &(*ktask)->in_size, (*ktask)->iv_size,\
                                              (*ktask)->key, (*ktask)->key_size,\
                                              (*ktask)->aux_buffers.buf1,\
                                              ((*ktask)->aux_buffers.buf1 != NULL) ? (*ktask)->aux_buffers.buf1_size : 0,\
                                              kryptos_ ## cipher_name ## _e, e_arg);\
        if ((*ktask)->result != kKryptosSuccess) {\
            if ((*ktask)->result == kKryptosGMACError) {\
                (*ktask)->result_verbose = "Corrupted data.";\
            }\
            goto kryptos_ ## cipher_epilogue;\
        }\
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
                                  &(*ktask)->aux_buffers, (*ktask)->ctr,\
                                  cipher_epilogue, cipher_block_processor_stmt);\
    if ((*ktask)->action == kKryptosEncrypt && (*ktask)->result == kKryptosSuccess && (*ktask)->mode == kKryptosGCM) {\
        (*ktask)->result = kryptos_gcm_auth(&(*ktask)->out, &(*ktask)->out_size, (*ktask)->iv_size,\
                                            (*ktask)->key, (*ktask)->key_size,\
                                            (*ktask)->aux_buffers.buf1,\
                                            ((*ktask)->aux_buffers.buf1 != NULL) ? (*ktask)->aux_buffers.buf1_size : 0,\
                                            kryptos_ ## cipher_name ## _e, e_arg);\
        if ((*ktask)->result != kKryptosSuccess) {\
            kryptos_freeseg((*ktask)->out, (*ktask)->out_size);\
            (*ktask)->out = NULL;\
            (*ktask)->out_size = 0;\
        }\
    }\
    kryptos_meta_block_processing_epilogue(cipher_epilogue,\
                                           inblock, inblock_p, in_p, in_end,\
                                           outblock, outblock_p, out_p,\
                                           in_size, cipher_block_size,\
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
                                            cipher_block_processor_stmt,\
                                            e_arg)\
void kryptos_ ## cipher_name ## _cipher(kryptos_task_ctx **ktask) {\
    static struct cipher_subkeys_struct cipher_subkeys_struct_var, cipher_subkeys_struct_var ## _cpy;\
    cipher_block_processor_t cipher_block_processor;\
    kryptos_u8_t *in_p = NULL, *in_end = NULL, *out_p = NULL;\
    kryptos_u8_t *outblock = NULL, *outblock_p = NULL, *inblock = NULL, *inblock_p = NULL;\
    size_t in_size;\
    if (kryptos_task_check(ktask) == 0) {\
        return;\
    }\
    cipher_key_expansion_stmt;\
    if ((*ktask)->action == kKryptosEncrypt || (*ktask)->mode == kKryptosOFB ||\
                                               (*ktask)->mode == kKryptosCTR ||\
                                               (*ktask)->mode == kKryptosGCM) {\
        cipher_block_processor = cipher_block_encrypt;\
        cipher_additional_stmts_before_encrypting;\
    } else {\
        cipher_block_processor = cipher_block_decrypt;\
        cipher_additional_stmts_before_decrypting;\
    }\
    if ((*ktask)->mode == kKryptosGCM && (*ktask)->action == kKryptosDecrypt) {\
        /*WARN(Rafael): This data swapping is necessary. Because the cipher\
                        context is static in order to save heap memory when in kernel mode*/\
        memcpy(&cipher_subkeys_struct_var ## _cpy, &(cipher_subkeys_struct_var), sizeof(cipher_subkeys_struct_var));\
        (*ktask)->result = kryptos_gcm_verify(&(*ktask)->in, &(*ktask)->in_size, (*ktask)->iv_size,\
                                              (*ktask)->key, (*ktask)->key_size,\
                                              (*ktask)->aux_buffers.buf1,\
                                              ((*ktask)->aux_buffers.buf1 != NULL) ? (*ktask)->aux_buffers.buf1_size : 0,\
                                              kryptos_ ## cipher_name ## _e, e_arg);\
        if ((*ktask)->result != kKryptosSuccess) {\
            if ((*ktask)->result == kKryptosGMACError) {\
                (*ktask)->result_verbose = "Corrupted data.";\
            }\
            goto kryptos_ ## cipher_epilogue;\
        }\
        memcpy(&(cipher_subkeys_struct_var), &cipher_subkeys_struct_var ## _cpy, sizeof(cipher_subkeys_struct_var ## _cpy));\
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
                                  &(*ktask)->aux_buffers, (*ktask)->ctr,\
                                  cipher_epilogue, cipher_block_processor_stmt);\
    if ((*ktask)->action == kKryptosEncrypt && (*ktask)->result == kKryptosSuccess && (*ktask)->mode == kKryptosGCM) {\
        /*WARN(Rafael): This data swapping is necessary. Because the cipher\
                        context is static in order to save heap memory when in kernel mode*/\
        memcpy(&cipher_subkeys_struct_var ## _cpy, &(cipher_subkeys_struct_var), sizeof(cipher_subkeys_struct_var));\
        (*ktask)->result = kryptos_gcm_auth(&(*ktask)->out, &(*ktask)->out_size, (*ktask)->iv_size,\
                                            (*ktask)->key, (*ktask)->key_size,\
                                            (*ktask)->aux_buffers.buf1,\
                                            ((*ktask)->aux_buffers.buf1 != NULL) ? (*ktask)->aux_buffers.buf1_size : 0,\
                                            kryptos_ ## cipher_name ## _e, e_arg);\
        if ((*ktask)->result != kKryptosSuccess) {\
            kryptos_freeseg((*ktask)->out, (*ktask)->out_size);\
            (*ktask)->out = NULL;\
            (*ktask)->out_size = 0;\
        }\
        memcpy(&(cipher_subkeys_struct_var), &cipher_subkeys_struct_var ## _cpy, sizeof(cipher_subkeys_struct_var ## _cpy));\
    }\
    kryptos_meta_block_processing_epilogue(cipher_epilogue,\
                                           inblock, inblock_p, in_p, in_end,\
                                           outblock, outblock_p, out_p,\
                                           in_size, cipher_block_size,\
                                           cipher_subkeys_struct_var, ktask);\
    cipher_block_processor = NULL;\
}

#endif

#ifndef __cplusplus
#define KRYPTOS_DECL_ENCODING_SETUP(encoding_name, ktask)\
void kryptos_ ## encoding_name ## _setup(kryptos_task_ctx *ktask);
#else
#define KRYPTOS_DECL_ENCODING_SETUP(encoding_name, ktask)\
extern "C" void kryptos_ ## encoding_name ## _setup(kryptos_task_ctx *ktask);
#endif

#define KRYPTOS_IMPL_ENCODING_SETUP(encoding_name, ktask, kEncoder)\
void kryptos_ ## encoding_name ## _setup(kryptos_task_ctx *ktask) {\
    if ((ktask) == NULL) {\
        return;\
    }\
    (ktask)->encoder = kEncoder;\
}

#ifndef __cplusplus
#define KRYPTOS_DECL_ENCODING_PROCESSOR(encoding_name, ktask)\
void kryptos_ ## encoding_name ## _processor(kryptos_task_ctx **ktask);
#else
#define KRYPTOS_DECL_ENCODING_PROCESSOR(encoding_name, ktask)\
extern "C" void kryptos_ ## encoding_name ## _processor(kryptos_task_ctx **ktask);
#endif

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

#ifndef __cplusplus
#define KRYPTOS_DECL_HASH_PROCESSOR(hash_name, ktask)\
void kryptos_ ## hash_name ## _hash(kryptos_task_ctx **ktask, const int to_hex);
#else
#define KRYPTOS_DECL_HASH_PROCESSOR(hash_name, ktask)\
extern "C" void kryptos_ ## hash_name ## _hash(kryptos_task_ctx **ktask, const int to_hex);
#endif

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
    kryptos_u64_t i, l = struct_var->total_len >> 3;\
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
        kryptos_hash_ld_u8buf_as_u ## bits_per_block ## _blocks((kryptos_u8_t *)"", 0,\
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
    kryptos_u64_t i, l = struct_var->total_len >> 3;\
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
        kryptos_hash_ld_u8buf_as_u ## bits_per_block ## _blocks((kryptos_u8_t *)"", 0,\
                                            ctx->input.block, input_block_size,\
                                            block_index_decision_table);\
        hash_do_block_stmt;\
    }\
}\

#endif

#ifndef __cplusplus
#define KRYPTOS_DECL_HASH_SIZE(hash_name)\
size_t kryptos_ ## hash_name ## _hash_size(void);
#else
#define KRYPTOS_DECL_HASH_SIZE(hash_name)\
extern "C" size_t kryptos_ ## hash_name ## _hash_size(void);
#endif

#define KRYPTOS_IMPL_HASH_SIZE(hash_name, size)\
size_t kryptos_ ## hash_name ## _hash_size(void) {\
    return size;\
}

#ifndef __cplusplus
#define KRYPTOS_DECL_HASH_INPUT_SIZE(hash_name)\
size_t kryptos_  ## hash_name ## _hash_input_size(void);
#else
#define KRYPTOS_DECL_HASH_INPUT_SIZE(hash_name)\
extern "C" size_t kryptos_  ## hash_name ## _hash_input_size(void);
#endif

#define KRYPTOS_IMPL_HASH_INPUT_SIZE(hash_name, size)\
size_t kryptos_ ## hash_name ## _hash_input_size(void) {\
    return size;\
}

#endif
