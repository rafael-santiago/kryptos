/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_keccak.h>
#include <kryptos_memory.h>
#include <kryptos_hex.h>
#include <kryptos_endianness_utils.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// WARN(Rafael): This code module implements only the KECCAK-1600. With few changes would be
//               possible get a KECCAK-N implementation but I am not interested in doing it.

// TODO(Rafael): Try to eliminate the usage of modulus five.

#define keccak_rot(a, r) ( ( (a) << (r) ) | ( (a) >> (64 - (r) ) ) )

#define keccak_rot_off(o) ( kryptos_keccak_rot_offset[(o)] )

#define keccak_pad(d, t, mp) {\
    if ((d) == 1) {\
        *(mp) = ((t) == kKryptosKeccakPaddingKECCAK) ? 0x81 : 0x86;\
    } else {\
        *(mp) = ((t) == kKryptosKeccakPaddingKECCAK) ? 0x01 : 0x06;\
        memset((mp) + 1, 0, d - 2);\
        *((mp) + d - 1) = 0x80;\
    }\
}

#define kryptos_keccak_clear_ctx(ctx) {\
    if ((ctx)->message != NULL) {\
        (ctx)->message = NULL;\
    }\
    (ctx)->message_size = 0;\
    (ctx)->r = (ctx)->c = 0;\
    (ctx)->padtype = 0;\
    memset((ctx)->state, 0, sizeof(kryptos_u64_t) * 25);\
}

#define KRYPTOS_KECCAK_1600_ROUNDS_NR 24

#define KRYPTOS_KECCAK_224_HASH_SIZE 28

#define KRYPTOS_KECCAK_224_BYTES_PER_BLOCK 144

#define KRYPTOS_KECCAK_256_HASH_SIZE 32

#define KRYPTOS_KECCAK_256_BYTES_PER_BLOCK 136

#define KRYPTOS_KECCAK_384_HASH_SIZE 48

#define KRYPTOS_KECCAK_384_BYTES_PER_BLOCK 104

#define KRYPTOS_KECCAK_512_HASH_SIZE 64

#define KRYPTOS_KECCAK_512_BYTES_PER_BLOCK 72

#define KRYPTOS_SHA3_224_HASH_SIZE KRYPTOS_KECCAK_224_HASH_SIZE

#define KRYPTOS_SHA3_224_BYTES_PER_BLOCK KRYPTOS_KECCAK_224_BYTES_PER_BLOCK

#define KRYPTOS_SHA3_256_HASH_SIZE KRYPTOS_KECCAK_256_HASH_SIZE

#define KRYPTOS_SHA3_256_BYTES_PER_BLOCK KRYPTOS_KECCAK_256_BYTES_PER_BLOCK

#define KRYPTOS_SHA3_384_HASH_SIZE KRYPTOS_KECCAK_384_HASH_SIZE

#define KRYPTOS_SHA3_384_BYTES_PER_BLOCK KRYPTOS_KECCAK_384_BYTES_PER_BLOCK

#define KRYPTOS_SHA3_512_HASH_SIZE KRYPTOS_KECCAK_512_HASH_SIZE

#define KRYPTOS_SHA3_512_BYTES_PER_BLOCK KRYPTOS_KECCAK_512_BYTES_PER_BLOCK

// CLUE(Rafael): If for some reason you want to use KECCAK with a non-standard bit-size.
//               You also must make possible the wanted bit-size passing (hashes entry points).
//               This is not allowed by design.

#undef KRYPTOS_KECCAK_ARBITRARY_OUTPUT

static kryptos_u8_t kryptos_keccak_rot_offset[24] = {  1,  3,  6, 10, 15,
                                                      21, 28, 36, 45, 55,
                                                       2, 14, 27, 41, 56,
                                                       8, 25, 43, 62, 18,
                                                      39, 61, 20, 44 };

static kryptos_u64_t kryptos_keccak_rc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

typedef enum {
    kKryptosKeccakPaddingKECCAK = 0,
    kKryptosKeccakPaddingSHA3
}kryptos_keccak_padding_t;

struct kryptos_keccak_ctx {
    kryptos_u64_t state[5][5];
    kryptos_u8_t *message;
    size_t message_size;
    size_t r, c;
    kryptos_keccak_padding_t padtype;
    kryptos_u8_t *z;
    size_t z_size;
};

static void kryptos_keccak_sponge_1600(struct kryptos_keccak_ctx *ctx);

static void kryptos_keccak_r1600(kryptos_u64_t state[5][5]);

KRYPTOS_IMPL_HASH_SIZE(keccak224, KRYPTOS_KECCAK_224_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(keccak224, KRYPTOS_KECCAK_224_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(keccak224, ktask, kryptos_keccak_ctx, ctx, keccak_224_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.message_size = (*ktask)->in_size;
                                ctx.padtype = kKryptosKeccakPaddingKECCAK;
                                ctx.r = 1152;
                                ctx.c = 448;
                            },
                            kryptos_keccak_sponge_1600(&ctx),
                            {
                                if (ctx.z == NULL || ctx.z_size != KRYPTOS_KECCAK_224_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_keccak_224_epilogue;
                                }
                                (*ktask)->out_size = ctx.z_size;
                                (*ktask)->out = ctx.z;
                                ctx.z = NULL;
                            },
                            {
                                if (ctx.z == NULL || ctx.z_size == 0) {
                                    goto kryptos_keccak_224_no_memory;
                                }
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_KECCAK_224_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_keccak_224_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_keccak_224_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_KECCAK_224_HASH_SIZE << 1;
                                kryptos_u64_to_hex((*ktask)->out, 57,      ((kryptos_u64_t)ctx.z[ 0]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 1]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[ 2]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[ 3]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[ 4]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[ 5]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[ 6]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[ 7]);
                                kryptos_u64_to_hex((*ktask)->out + 16, 41, ((kryptos_u64_t)ctx.z[ 8]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 9]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[10]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[11]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[12]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[13]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[14]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[15]);
                                kryptos_u64_to_hex((*ktask)->out + 32, 25, ((kryptos_u64_t)ctx.z[16]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[17]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[18]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[19]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[20]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[21]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[22]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[23]);
                                kryptos_u32_to_hex((*ktask)->out + 48,  9, ((kryptos_u32_t)ctx.z[24]) << 24 |
                                                                           ((kryptos_u32_t)ctx.z[25]) << 16 |
                                                                           ((kryptos_u32_t)ctx.z[26]) <<  8 |
                                                                            (kryptos_u32_t)ctx.z[27]);
                                kryptos_freeseg(ctx.z);
                                ctx.z_size = 0;
                            })

KRYPTOS_IMPL_HASH_SIZE(keccak256, KRYPTOS_KECCAK_256_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(keccak256, KRYPTOS_KECCAK_256_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(keccak256, ktask, kryptos_keccak_ctx, ctx, keccak_256_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.message_size = (*ktask)->in_size;
                                ctx.padtype = kKryptosKeccakPaddingKECCAK;
                                ctx.r = 1088;
                                ctx.c = 512;
                            },
                            kryptos_keccak_sponge_1600(&ctx),
                            {
                                if (ctx.z == NULL || ctx.z_size != KRYPTOS_KECCAK_256_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_keccak_256_epilogue;
                                }
                                (*ktask)->out_size = ctx.z_size;
                                (*ktask)->out = ctx.z;
                                ctx.z = NULL;
                            },
                            {
                                if (ctx.z == NULL || ctx.z_size == 0) {
                                    goto kryptos_keccak_256_no_memory;
                                }
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_KECCAK_256_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_keccak_256_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_keccak_256_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_KECCAK_256_HASH_SIZE << 1;
                                kryptos_u64_to_hex((*ktask)->out, 65,      ((kryptos_u64_t)ctx.z[ 0]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 1]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[ 2]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[ 3]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[ 4]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[ 5]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[ 6]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[ 7]);
                                kryptos_u64_to_hex((*ktask)->out + 16, 49, ((kryptos_u64_t)ctx.z[ 8]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 9]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[10]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[11]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[12]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[13]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[14]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[15]);
                                kryptos_u64_to_hex((*ktask)->out + 32, 33, ((kryptos_u64_t)ctx.z[16]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[17]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[18]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[19]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[20]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[21]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[22]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[23]);
                                kryptos_u64_to_hex((*ktask)->out + 48, 17, ((kryptos_u64_t)ctx.z[24]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[25]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[26]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[27]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[28]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[29]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[30]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[31]);
                                kryptos_freeseg(ctx.z);
                                ctx.z_size = 0;
                            })

KRYPTOS_IMPL_HASH_SIZE(keccak384, KRYPTOS_KECCAK_384_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(keccak384, KRYPTOS_KECCAK_384_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(keccak384, ktask, kryptos_keccak_ctx, ctx, keccak_384_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.message_size = (*ktask)->in_size;
                                ctx.padtype = kKryptosKeccakPaddingKECCAK;
                                ctx.r = 832;
                                ctx.c = 768;
                            },
                            kryptos_keccak_sponge_1600(&ctx),
                            {
                                if (ctx.z == NULL || ctx.z_size != KRYPTOS_KECCAK_384_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_keccak_384_epilogue;
                                }
                                (*ktask)->out_size = ctx.z_size;
                                (*ktask)->out = ctx.z;
                                ctx.z = NULL;
                            },
                            {
                                if (ctx.z == NULL || ctx.z_size == 0) {
                                    goto kryptos_keccak_384_no_memory;
                                }
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_KECCAK_384_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_keccak_384_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_keccak_384_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_KECCAK_384_HASH_SIZE << 1;
                                kryptos_u64_to_hex((*ktask)->out, 97,      ((kryptos_u64_t)ctx.z[ 0]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 1]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[ 2]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[ 3]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[ 4]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[ 5]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[ 6]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[ 7]);
                                kryptos_u64_to_hex((*ktask)->out + 16, 81, ((kryptos_u64_t)ctx.z[ 8]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 9]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[10]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[11]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[12]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[13]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[14]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[15]);
                                kryptos_u64_to_hex((*ktask)->out + 32, 65, ((kryptos_u64_t)ctx.z[16]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[17]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[18]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[19]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[20]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[21]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[22]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[23]);
                                kryptos_u64_to_hex((*ktask)->out + 48, 49, ((kryptos_u64_t)ctx.z[24]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[25]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[26]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[27]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[28]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[29]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[30]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[31]);
                                kryptos_u64_to_hex((*ktask)->out + 64, 33, ((kryptos_u64_t)ctx.z[32]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[33]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[34]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[35]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[36]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[37]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[38]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[39]);
                                kryptos_u64_to_hex((*ktask)->out + 80, 17, ((kryptos_u64_t)ctx.z[40]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[41]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[42]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[43]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[44]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[45]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[46]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[47]);
                                kryptos_freeseg(ctx.z);
                                ctx.z_size = 0;
                            })

KRYPTOS_IMPL_HASH_SIZE(keccak512, KRYPTOS_KECCAK_512_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(keccak512, KRYPTOS_KECCAK_512_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(keccak512, ktask, kryptos_keccak_ctx, ctx, keccak_512_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.message_size = (*ktask)->in_size;
                                ctx.padtype = kKryptosKeccakPaddingKECCAK;
                                ctx.r = 576;
                                ctx.c = 1024;
                            },
                            kryptos_keccak_sponge_1600(&ctx),
                            {
                                if (ctx.z == NULL || ctx.z_size != KRYPTOS_KECCAK_512_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_keccak_512_epilogue;
                                }
                                (*ktask)->out_size = ctx.z_size;
                                (*ktask)->out = ctx.z;
                                ctx.z = NULL;
                            },
                            {
                                if (ctx.z == NULL || ctx.z_size == 0) {
                                    goto kryptos_keccak_512_no_memory;
                                }
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_KECCAK_512_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_keccak_512_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_keccak_512_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_KECCAK_512_HASH_SIZE << 1;
                                kryptos_u64_to_hex((*ktask)->out, 129,       ((kryptos_u64_t)ctx.z[ 0]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[ 1]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[ 2]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[ 3]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[ 4]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[ 5]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[ 6]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[ 7]);
                                kryptos_u64_to_hex((*ktask)->out +  16, 113, ((kryptos_u64_t)ctx.z[ 8]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[ 9]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[10]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[11]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[12]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[13]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[14]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[15]);
                                kryptos_u64_to_hex((*ktask)->out +  32,  97, ((kryptos_u64_t)ctx.z[16]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[17]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[18]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[19]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[20]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[21]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[22]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[23]);
                                kryptos_u64_to_hex((*ktask)->out +  48,  81, ((kryptos_u64_t)ctx.z[24]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[25]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[26]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[27]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[28]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[29]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[30]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[31]);
                                kryptos_u64_to_hex((*ktask)->out +  64,  65, ((kryptos_u64_t)ctx.z[32]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[33]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[34]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[35]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[36]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[37]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[38]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[39]);
                                kryptos_u64_to_hex((*ktask)->out +  80,  49, ((kryptos_u64_t)ctx.z[40]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[41]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[42]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[43]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[44]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[45]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[46]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[47]);
                                kryptos_u64_to_hex((*ktask)->out +  96,  33, ((kryptos_u64_t)ctx.z[48]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[49]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[50]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[51]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[52]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[53]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[54]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[55]);
                                kryptos_u64_to_hex((*ktask)->out + 112,  17, ((kryptos_u64_t)ctx.z[56]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[57]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[58]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[59]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[60]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[61]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[62]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[63]);
                                kryptos_freeseg(ctx.z);
                                ctx.z_size = 0;
                            })

// TIP(Rafael): The SHA3-N stuff is almost the same code of KECCAK-N, having only one difference: the padtype value.
//
//              Even being the same code I have decided keep the SHA3 separated from KECCAK. So, please,
//              do not create a function to call the KECCAK's processors it would make SHA3-N's performance be
//              different of KECCAK-N's performance. It would be really awesome, sparkling and cute from some
//              pointview of some sacrum Software Engineering's Gospel but not so wise when considering the
//              life in practice. Due to it, let's call functions only when is necessary, okay?
//
//              Well, now you can use the holy hand grenade. ;)

KRYPTOS_IMPL_HASH_SIZE(sha3_224, KRYPTOS_SHA3_224_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(sha3_224, KRYPTOS_SHA3_224_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(sha3_224, ktask, kryptos_keccak_ctx, ctx, sha3_224_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.message_size = (*ktask)->in_size;
                                ctx.padtype = kKryptosKeccakPaddingSHA3;
                                ctx.r = 1152;
                                ctx.c = 448;
                            },
                            kryptos_keccak_sponge_1600(&ctx),
                            {
                                if (ctx.z == NULL || ctx.z_size != KRYPTOS_SHA3_224_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha3_224_epilogue;
                                }
                                (*ktask)->out_size = ctx.z_size;
                                (*ktask)->out = ctx.z;
                                ctx.z = NULL;
                            },
                            {
                                if (ctx.z == NULL || ctx.z_size == 0) {
                                    goto kryptos_sha3_224_no_memory;
                                }
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_SHA3_224_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_sha3_224_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_sha3_224_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA3_224_HASH_SIZE << 1;
                                kryptos_u64_to_hex((*ktask)->out, 57,      ((kryptos_u64_t)ctx.z[ 0]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 1]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[ 2]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[ 3]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[ 4]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[ 5]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[ 6]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[ 7]);
                                kryptos_u64_to_hex((*ktask)->out + 16, 41, ((kryptos_u64_t)ctx.z[ 8]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 9]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[10]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[11]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[12]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[13]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[14]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[15]);
                                kryptos_u64_to_hex((*ktask)->out + 32, 25, ((kryptos_u64_t)ctx.z[16]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[17]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[18]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[19]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[20]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[21]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[22]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[23]);
                                kryptos_u32_to_hex((*ktask)->out + 48,  9, ((kryptos_u32_t)ctx.z[24]) << 24 |
                                                                           ((kryptos_u32_t)ctx.z[25]) << 16 |
                                                                           ((kryptos_u32_t)ctx.z[26]) <<  8 |
                                                                            (kryptos_u32_t)ctx.z[27]);
                                kryptos_freeseg(ctx.z);
                                ctx.z_size = 0;
                            })

KRYPTOS_IMPL_HASH_SIZE(sha3_256, KRYPTOS_SHA3_256_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(sha3_256, KRYPTOS_SHA3_256_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(sha3_256, ktask, kryptos_keccak_ctx, ctx, sha3_256_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.message_size = (*ktask)->in_size;
                                ctx.padtype = kKryptosKeccakPaddingSHA3;
                                ctx.r = 1088;
                                ctx.c = 512;
                            },
                            kryptos_keccak_sponge_1600(&ctx),
                            {
                                if (ctx.z == NULL || ctx.z_size != KRYPTOS_SHA3_256_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha3_256_epilogue;
                                }
                                (*ktask)->out_size = ctx.z_size;
                                (*ktask)->out = ctx.z;
                                ctx.z = NULL;
                            },
                            {
                                if (ctx.z == NULL || ctx.z_size == 0) {
                                    goto kryptos_sha3_256_no_memory;
                                }
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_SHA3_256_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_sha3_256_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_sha3_256_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA3_256_HASH_SIZE << 1;
                                kryptos_u64_to_hex((*ktask)->out, 65,      ((kryptos_u64_t)ctx.z[ 0]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 1]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[ 2]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[ 3]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[ 4]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[ 5]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[ 6]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[ 7]);
                                kryptos_u64_to_hex((*ktask)->out + 16, 49, ((kryptos_u64_t)ctx.z[ 8]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 9]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[10]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[11]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[12]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[13]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[14]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[15]);
                                kryptos_u64_to_hex((*ktask)->out + 32, 33, ((kryptos_u64_t)ctx.z[16]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[17]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[18]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[19]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[20]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[21]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[22]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[23]);
                                kryptos_u64_to_hex((*ktask)->out + 48, 17, ((kryptos_u64_t)ctx.z[24]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[25]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[26]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[27]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[28]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[29]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[30]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[31]);
                                kryptos_freeseg(ctx.z);
                                ctx.z_size = 0;
                            })

KRYPTOS_IMPL_HASH_SIZE(sha3_384, KRYPTOS_SHA3_384_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(sha3_384, KRYPTOS_SHA3_384_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(sha3_384, ktask, kryptos_keccak_ctx, ctx, sha3_384_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.message_size = (*ktask)->in_size;
                                ctx.padtype = kKryptosKeccakPaddingSHA3;
                                ctx.r = 832;
                                ctx.c = 768;
                            },
                            kryptos_keccak_sponge_1600(&ctx),
                            {
                                if (ctx.z == NULL || ctx.z_size != KRYPTOS_SHA3_384_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha3_384_epilogue;
                                }
                                (*ktask)->out_size = ctx.z_size;
                                (*ktask)->out = ctx.z;
                                ctx.z = NULL;
                            },
                            {
                                if (ctx.z == NULL || ctx.z_size == 0) {
                                    goto kryptos_sha3_384_no_memory;
                                }
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_SHA3_384_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_sha3_384_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_sha3_384_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA3_384_HASH_SIZE << 1;
                                kryptos_u64_to_hex((*ktask)->out, 97,      ((kryptos_u64_t)ctx.z[ 0]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 1]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[ 2]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[ 3]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[ 4]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[ 5]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[ 6]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[ 7]);
                                kryptos_u64_to_hex((*ktask)->out + 16, 81, ((kryptos_u64_t)ctx.z[ 8]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[ 9]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[10]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[11]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[12]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[13]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[14]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[15]);
                                kryptos_u64_to_hex((*ktask)->out + 32, 65, ((kryptos_u64_t)ctx.z[16]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[17]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[18]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[19]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[20]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[21]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[22]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[23]);
                                kryptos_u64_to_hex((*ktask)->out + 48, 49, ((kryptos_u64_t)ctx.z[24]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[25]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[26]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[27]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[28]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[29]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[30]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[31]);
                                kryptos_u64_to_hex((*ktask)->out + 64, 33, ((kryptos_u64_t)ctx.z[32]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[33]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[34]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[35]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[36]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[37]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[38]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[39]);
                                kryptos_u64_to_hex((*ktask)->out + 80, 17, ((kryptos_u64_t)ctx.z[40]) << 56 |
                                                                           ((kryptos_u64_t)ctx.z[41]) << 48 |
                                                                           ((kryptos_u64_t)ctx.z[42]) << 40 |
                                                                           ((kryptos_u64_t)ctx.z[43]) << 32 |
                                                                           ((kryptos_u64_t)ctx.z[44]) << 24 |
                                                                           ((kryptos_u64_t)ctx.z[45]) << 16 |
                                                                           ((kryptos_u64_t)ctx.z[46]) <<  8 |
                                                                            (kryptos_u64_t)ctx.z[47]);
                                kryptos_freeseg(ctx.z);
                                ctx.z_size = 0;
                            })

KRYPTOS_IMPL_HASH_SIZE(sha3_512, KRYPTOS_SHA3_512_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(sha3_512, KRYPTOS_SHA3_512_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(sha3_512, ktask, kryptos_keccak_ctx, ctx, sha3_512_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.message_size = (*ktask)->in_size;
                                ctx.padtype = kKryptosKeccakPaddingSHA3;
                                ctx.r = 576;
                                ctx.c = 1024;
                            },
                            kryptos_keccak_sponge_1600(&ctx),
                            {
                                if (ctx.z == NULL || ctx.z_size != KRYPTOS_SHA3_512_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha3_512_epilogue;
                                }
                                (*ktask)->out_size = ctx.z_size;
                                (*ktask)->out = ctx.z;
                                ctx.z = NULL;
                            },
                            {
                                if (ctx.z == NULL || ctx.z_size == 0) {
                                    goto kryptos_sha3_512_no_memory;
                                }
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_SHA3_512_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_sha3_512_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_sha3_512_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA3_512_HASH_SIZE << 1;
                                kryptos_u64_to_hex((*ktask)->out, 129,       ((kryptos_u64_t)ctx.z[ 0]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[ 1]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[ 2]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[ 3]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[ 4]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[ 5]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[ 6]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[ 7]);
                                kryptos_u64_to_hex((*ktask)->out +  16, 113, ((kryptos_u64_t)ctx.z[ 8]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[ 9]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[10]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[11]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[12]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[13]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[14]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[15]);
                                kryptos_u64_to_hex((*ktask)->out +  32,  97, ((kryptos_u64_t)ctx.z[16]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[17]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[18]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[19]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[20]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[21]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[22]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[23]);
                                kryptos_u64_to_hex((*ktask)->out +  48,  81, ((kryptos_u64_t)ctx.z[24]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[25]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[26]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[27]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[28]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[29]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[30]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[31]);
                                kryptos_u64_to_hex((*ktask)->out +  64,  65, ((kryptos_u64_t)ctx.z[32]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[33]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[34]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[35]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[36]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[37]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[38]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[39]);
                                kryptos_u64_to_hex((*ktask)->out +  80,  49, ((kryptos_u64_t)ctx.z[40]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[41]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[42]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[43]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[44]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[45]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[46]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[47]);
                                kryptos_u64_to_hex((*ktask)->out +  96,  33, ((kryptos_u64_t)ctx.z[48]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[49]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[50]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[51]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[52]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[53]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[54]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[55]);
                                kryptos_u64_to_hex((*ktask)->out + 112,  17, ((kryptos_u64_t)ctx.z[56]) << 56 |
                                                                             ((kryptos_u64_t)ctx.z[57]) << 48 |
                                                                             ((kryptos_u64_t)ctx.z[58]) << 40 |
                                                                             ((kryptos_u64_t)ctx.z[59]) << 32 |
                                                                             ((kryptos_u64_t)ctx.z[60]) << 24 |
                                                                             ((kryptos_u64_t)ctx.z[61]) << 16 |
                                                                             ((kryptos_u64_t)ctx.z[62]) <<  8 |
                                                                              (kryptos_u64_t)ctx.z[63]);
                                kryptos_freeseg(ctx.z);
                                ctx.z_size = 0;
                            })

static void kryptos_keccak_sponge_1600(struct kryptos_keccak_ctx *ctx) {
    size_t x, y;
    size_t d;
    kryptos_u8_t *m, *mp, *mp_end, *zp;
#ifdef KRYPTOS_KECCAK_ARBITRARY_OUTPUT
    kryptos_u8_t *zp_end;
#endif
    size_t m_size, b_size, rw, m_off;
    kryptos_u64_t m_chunk;

    ctx->z_size = 0;
    ctx->z = NULL;

    memset(ctx->state, 0, sizeof(kryptos_u64_t) * 25);

    d = (ctx->r >> 3) - (ctx->message_size % (ctx->r >> 3));
    m_size = ctx->message_size + d;

    m = (kryptos_u8_t *) kryptos_newseg(m_size);

    if (m == NULL) {
        goto kryptos_keccak_sponge_1600_epilogue;
    }

    memcpy(m, ctx->message, ctx->message_size);
    keccak_pad(d, ctx->padtype, (m + ctx->message_size));

    mp = m;
    mp_end = mp + m_size;

    b_size = ((ctx->r >> 6) << 3);
    rw = ctx->r >> 6;

    // INFO(Rafael): Absorving phase.

    while (mp < mp_end) {
        for (m_off = 0; m_off < rw; m_off++) {
            m_chunk = ( (kryptos_u64_t)(*(mp + (m_off << 3) + 7)) << 56 ) |
                      ( (kryptos_u64_t)(*(mp + (m_off << 3) + 6)) << 48 ) |
                      ( (kryptos_u64_t)(*(mp + (m_off << 3) + 5)) << 40 ) |
                      ( (kryptos_u64_t)(*(mp + (m_off << 3) + 4)) << 32 ) |
                      ( (kryptos_u64_t)(*(mp + (m_off << 3) + 3)) << 24 ) |
                      ( (kryptos_u64_t)(*(mp + (m_off << 3) + 2)) << 16 ) |
                      ( (kryptos_u64_t)(*(mp + (m_off << 3) + 1)) <<  8 ) |
                        (kryptos_u64_t)(*(mp + (m_off << 3)));
            x = m_off % 5;
            y = m_off / 5;
            ctx->state[x][y] ^= m_chunk;
        }
        kryptos_keccak_r1600(ctx->state);
        mp += b_size;
    }

    // INFO(Rafael): Squeezing phase.

    ctx->z_size = ((ctx->c >> 1) >> 3);
    ctx->z = (kryptos_u8_t *) kryptos_newseg(ctx->z_size);

    if (ctx->z == NULL) {
        goto kryptos_keccak_sponge_1600_epilogue;
    }

    memset(ctx->z, 0, ctx->z_size);

    zp = ctx->z;

    switch (ctx->z_size) {
        case KRYPTOS_KECCAK_224_HASH_SIZE:
                zp[ 0] =  ctx->state[0][0]        & 0xFF;
                zp[ 1] = (ctx->state[0][0] >>  8) & 0xFF;
                zp[ 2] = (ctx->state[0][0] >> 16) & 0xFF;
                zp[ 3] = (ctx->state[0][0] >> 24) & 0xFF;
                zp[ 4] = (ctx->state[0][0] >> 32) & 0xFF;
                zp[ 5] = (ctx->state[0][0] >> 40) & 0xFF;
                zp[ 6] = (ctx->state[0][0] >> 48) & 0xFF;
                zp[ 7] = (ctx->state[0][0] >> 56) & 0xFF;
                zp[ 8] =  ctx->state[1][0]        & 0xFF;
                zp[ 9] = (ctx->state[1][0] >>  8) & 0xFF;
                zp[10] = (ctx->state[1][0] >> 16) & 0xFF;
                zp[11] = (ctx->state[1][0] >> 24) & 0xFF;
                zp[12] = (ctx->state[1][0] >> 32) & 0xFF;
                zp[13] = (ctx->state[1][0] >> 40) & 0xFF;
                zp[14] = (ctx->state[1][0] >> 48) & 0xFF;
                zp[15] = (ctx->state[1][0] >> 56) & 0xFF;
                zp[16] =  ctx->state[2][0]        & 0xFF;
                zp[17] = (ctx->state[2][0] >>  8) & 0xFF;
                zp[18] = (ctx->state[2][0] >> 16) & 0xFF;
                zp[19] = (ctx->state[2][0] >> 24) & 0xFF;
                zp[20] = (ctx->state[2][0] >> 32) & 0xFF;
                zp[21] = (ctx->state[2][0] >> 40) & 0xFF;
                zp[22] = (ctx->state[2][0] >> 48) & 0xFF;
                zp[23] = (ctx->state[2][0] >> 56) & 0xFF;
                zp[24] =  ctx->state[3][0]        & 0xFF;
                zp[25] = (ctx->state[3][0] >>  8) & 0xFF;
                zp[26] = (ctx->state[3][0] >> 16) & 0xFF;
                zp[27] = (ctx->state[3][0] >> 24) & 0xFF;
            break;

        case KRYPTOS_KECCAK_256_HASH_SIZE:
                zp[ 0] =  ctx->state[0][0]        & 0xFF;
                zp[ 1] = (ctx->state[0][0] >>  8) & 0xFF;
                zp[ 2] = (ctx->state[0][0] >> 16) & 0xFF;
                zp[ 3] = (ctx->state[0][0] >> 24) & 0xFF;
                zp[ 4] = (ctx->state[0][0] >> 32) & 0xFF;
                zp[ 5] = (ctx->state[0][0] >> 40) & 0xFF;
                zp[ 6] = (ctx->state[0][0] >> 48) & 0xFF;
                zp[ 7] = (ctx->state[0][0] >> 56) & 0xFF;
                zp[ 8] =  ctx->state[1][0]        & 0xFF;
                zp[ 9] = (ctx->state[1][0] >>  8) & 0xFF;
                zp[10] = (ctx->state[1][0] >> 16) & 0xFF;
                zp[11] = (ctx->state[1][0] >> 24) & 0xFF;
                zp[12] = (ctx->state[1][0] >> 32) & 0xFF;
                zp[13] = (ctx->state[1][0] >> 40) & 0xFF;
                zp[14] = (ctx->state[1][0] >> 48) & 0xFF;
                zp[15] = (ctx->state[1][0] >> 56) & 0xFF;
                zp[16] =  ctx->state[2][0]        & 0xFF;
                zp[17] = (ctx->state[2][0] >>  8) & 0xFF;
                zp[18] = (ctx->state[2][0] >> 16) & 0xFF;
                zp[19] = (ctx->state[2][0] >> 24) & 0xFF;
                zp[20] = (ctx->state[2][0] >> 32) & 0xFF;
                zp[21] = (ctx->state[2][0] >> 40) & 0xFF;
                zp[22] = (ctx->state[2][0] >> 48) & 0xFF;
                zp[23] = (ctx->state[2][0] >> 56) & 0xFF;
                zp[24] =  ctx->state[3][0]        & 0xFF;
                zp[25] = (ctx->state[3][0] >>  8) & 0xFF;
                zp[26] = (ctx->state[3][0] >> 16) & 0xFF;
                zp[27] = (ctx->state[3][0] >> 24) & 0xFF;
                zp[28] = (ctx->state[3][0] >> 32) & 0xFF;
                zp[29] = (ctx->state[3][0] >> 40) & 0xFF;
                zp[30] = (ctx->state[3][0] >> 48) & 0xFF;
                zp[31] = (ctx->state[3][0] >> 56) & 0xFF;
            break;

        case KRYPTOS_KECCAK_384_HASH_SIZE:
                zp[ 0] =  ctx->state[0][0]        & 0xFF;
                zp[ 1] = (ctx->state[0][0] >>  8) & 0xFF;
                zp[ 2] = (ctx->state[0][0] >> 16) & 0xFF;
                zp[ 3] = (ctx->state[0][0] >> 24) & 0xFF;
                zp[ 4] = (ctx->state[0][0] >> 32) & 0xFF;
                zp[ 5] = (ctx->state[0][0] >> 40) & 0xFF;
                zp[ 6] = (ctx->state[0][0] >> 48) & 0xFF;
                zp[ 7] = (ctx->state[0][0] >> 56) & 0xFF;
                zp[ 8] =  ctx->state[1][0]        & 0xFF;
                zp[ 9] = (ctx->state[1][0] >>  8) & 0xFF;
                zp[10] = (ctx->state[1][0] >> 16) & 0xFF;
                zp[11] = (ctx->state[1][0] >> 24) & 0xFF;
                zp[12] = (ctx->state[1][0] >> 32) & 0xFF;
                zp[13] = (ctx->state[1][0] >> 40) & 0xFF;
                zp[14] = (ctx->state[1][0] >> 48) & 0xFF;
                zp[15] = (ctx->state[1][0] >> 56) & 0xFF;
                zp[16] =  ctx->state[2][0]        & 0xFF;
                zp[17] = (ctx->state[2][0] >>  8) & 0xFF;
                zp[18] = (ctx->state[2][0] >> 16) & 0xFF;
                zp[19] = (ctx->state[2][0] >> 24) & 0xFF;
                zp[20] = (ctx->state[2][0] >> 32) & 0xFF;
                zp[21] = (ctx->state[2][0] >> 40) & 0xFF;
                zp[22] = (ctx->state[2][0] >> 48) & 0xFF;
                zp[23] = (ctx->state[2][0] >> 56) & 0xFF;
                zp[24] =  ctx->state[3][0]        & 0xFF;
                zp[25] = (ctx->state[3][0] >>  8) & 0xFF;
                zp[26] = (ctx->state[3][0] >> 16) & 0xFF;
                zp[27] = (ctx->state[3][0] >> 24) & 0xFF;
                zp[28] = (ctx->state[3][0] >> 32) & 0xFF;
                zp[29] = (ctx->state[3][0] >> 40) & 0xFF;
                zp[30] = (ctx->state[3][0] >> 48) & 0xFF;
                zp[31] = (ctx->state[3][0] >> 56) & 0xFF;
                zp[32] =  ctx->state[4][0]        & 0xFF;
                zp[33] = (ctx->state[4][0] >>  8) & 0xFF;
                zp[34] = (ctx->state[4][0] >> 16) & 0xFF;
                zp[35] = (ctx->state[4][0] >> 24) & 0xFF;
                zp[36] = (ctx->state[4][0] >> 32) & 0xFF;
                zp[37] = (ctx->state[4][0] >> 40) & 0xFF;
                zp[38] = (ctx->state[4][0] >> 48) & 0xFF;
                zp[39] = (ctx->state[4][0] >> 56) & 0xFF;
                zp[40] =  ctx->state[0][1]        & 0xFF;
                zp[41] = (ctx->state[0][1] >>  8) & 0xFF;
                zp[42] = (ctx->state[0][1] >> 16) & 0xFF;
                zp[43] = (ctx->state[0][1] >> 24) & 0xFF;
                zp[44] = (ctx->state[0][1] >> 32) & 0xFF;
                zp[45] = (ctx->state[0][1] >> 40) & 0xFF;
                zp[46] = (ctx->state[0][1] >> 48) & 0xFF;
                zp[47] = (ctx->state[0][1] >> 56) & 0xFF;
            break;

        case KRYPTOS_KECCAK_512_HASH_SIZE:
                zp[ 0] =  ctx->state[0][0]        & 0xFF;
                zp[ 1] = (ctx->state[0][0] >>  8) & 0xFF;
                zp[ 2] = (ctx->state[0][0] >> 16) & 0xFF;
                zp[ 3] = (ctx->state[0][0] >> 24) & 0xFF;
                zp[ 4] = (ctx->state[0][0] >> 32) & 0xFF;
                zp[ 5] = (ctx->state[0][0] >> 40) & 0xFF;
                zp[ 6] = (ctx->state[0][0] >> 48) & 0xFF;
                zp[ 7] = (ctx->state[0][0] >> 56) & 0xFF;
                zp[ 8] =  ctx->state[1][0]        & 0xFF;
                zp[ 9] = (ctx->state[1][0] >>  8) & 0xFF;
                zp[10] = (ctx->state[1][0] >> 16) & 0xFF;
                zp[11] = (ctx->state[1][0] >> 24) & 0xFF;
                zp[12] = (ctx->state[1][0] >> 32) & 0xFF;
                zp[13] = (ctx->state[1][0] >> 40) & 0xFF;
                zp[14] = (ctx->state[1][0] >> 48) & 0xFF;
                zp[15] = (ctx->state[1][0] >> 56) & 0xFF;
                zp[16] =  ctx->state[2][0]        & 0xFF;
                zp[17] = (ctx->state[2][0] >>  8) & 0xFF;
                zp[18] = (ctx->state[2][0] >> 16) & 0xFF;
                zp[19] = (ctx->state[2][0] >> 24) & 0xFF;
                zp[20] = (ctx->state[2][0] >> 32) & 0xFF;
                zp[21] = (ctx->state[2][0] >> 40) & 0xFF;
                zp[22] = (ctx->state[2][0] >> 48) & 0xFF;
                zp[23] = (ctx->state[2][0] >> 56) & 0xFF;
                zp[24] =  ctx->state[3][0]        & 0xFF;
                zp[25] = (ctx->state[3][0] >>  8) & 0xFF;
                zp[26] = (ctx->state[3][0] >> 16) & 0xFF;
                zp[27] = (ctx->state[3][0] >> 24) & 0xFF;
                zp[28] = (ctx->state[3][0] >> 32) & 0xFF;
                zp[29] = (ctx->state[3][0] >> 40) & 0xFF;
                zp[30] = (ctx->state[3][0] >> 48) & 0xFF;
                zp[31] = (ctx->state[3][0] >> 56) & 0xFF;
                zp[32] =  ctx->state[4][0]        & 0xFF;
                zp[33] = (ctx->state[4][0] >>  8) & 0xFF;
                zp[34] = (ctx->state[4][0] >> 16) & 0xFF;
                zp[35] = (ctx->state[4][0] >> 24) & 0xFF;
                zp[36] = (ctx->state[4][0] >> 32) & 0xFF;
                zp[37] = (ctx->state[4][0] >> 40) & 0xFF;
                zp[38] = (ctx->state[4][0] >> 48) & 0xFF;
                zp[39] = (ctx->state[4][0] >> 56) & 0xFF;
                zp[40] =  ctx->state[0][1]        & 0xFF;
                zp[41] = (ctx->state[0][1] >>  8) & 0xFF;
                zp[42] = (ctx->state[0][1] >> 16) & 0xFF;
                zp[43] = (ctx->state[0][1] >> 24) & 0xFF;
                zp[44] = (ctx->state[0][1] >> 32) & 0xFF;
                zp[45] = (ctx->state[0][1] >> 40) & 0xFF;
                zp[46] = (ctx->state[0][1] >> 48) & 0xFF;
                zp[47] = (ctx->state[0][1] >> 56) & 0xFF;
                zp[48] =  ctx->state[1][1]        & 0xFF;
                zp[49] = (ctx->state[1][1] >>  8) & 0xFF;
                zp[50] = (ctx->state[1][1] >> 16) & 0xFF;
                zp[51] = (ctx->state[1][1] >> 24) & 0xFF;
                zp[52] = (ctx->state[1][1] >> 32) & 0xFF;
                zp[53] = (ctx->state[1][1] >> 40) & 0xFF;
                zp[54] = (ctx->state[1][1] >> 48) & 0xFF;
                zp[55] = (ctx->state[1][1] >> 56) & 0xFF;
                zp[56] =  ctx->state[2][1]        & 0xFF;
                zp[57] = (ctx->state[2][1] >>  8) & 0xFF;
                zp[58] = (ctx->state[2][1] >> 16) & 0xFF;
                zp[59] = (ctx->state[2][1] >> 24) & 0xFF;
                zp[60] = (ctx->state[2][1] >> 32) & 0xFF;
                zp[61] = (ctx->state[2][1] >> 40) & 0xFF;
                zp[62] = (ctx->state[2][1] >> 48) & 0xFF;
                zp[63] = (ctx->state[2][1] >> 56) & 0xFF;
            break;

        default:
#ifdef KRYPTOS_KECCAK_ARBITRARY_OUTPUT
            // WARN(Rafael): This is a inefficient way of implementing the squeezing phase. However, this default
            //               loop stuff for 'non-standard' bit-sizes makes easier sponge's extensions. Anyway, if
            //               a new standard output size show up it may be processed outside this default case.
            //
            //               In practice this is a dead code since none hash function implemented within this module
            //               support a custom bit-size output passing.

            zp_end = zp + ctx->z_size; // INFO(Rafael): I prefer ascertaing it.

            mp = m;
            mp_end = mp + m_size;

            while (mp < mp_end && zp < zp_end) {
                for (m_off = 0; m_off < rw && zp < zp_end; m_off++) {
                    x = m_off % 5;
                    y = m_off / 5;
                    kryptos_cpy_u32_as_little_endian(zp, zp_end - zp, ctx->state[x][y] & 0xFFFFFFFF);
                    if ((zp + 4) == zp_end) {
                        goto kryptos_keccak_sponge_1600_epilogue;
                    }
                    kryptos_cpy_u32_as_little_endian(zp + 4, zp_end - zp, ctx->state[x][y] >> 32);
                    zp += 8;
                }
                kryptos_keccak_r1600(ctx->state);
                mp += b_size;
            }
#endif
            break;
    }

kryptos_keccak_sponge_1600_epilogue:

    m_chunk = 0;
    x = y = d = 0;
    if (m != NULL) {
        kryptos_freeseg(m);
    }
    m_size = 0;
    kryptos_keccak_clear_ctx(ctx);
}

static void kryptos_keccak_r1600(kryptos_u64_t state[5][5]) {
    kryptos_u64_t D[5], C[5];
    size_t r;
    size_t x, y, r_off, x_t, y_t;
    kryptos_u64_t s_chunk, s_chunk_swp;

    for (r = 0; r < KRYPTOS_KECCAK_1600_ROUNDS_NR; r++) {
        // INFO(Rafael): Step 1 (a.k.a 'Theta').
        for (x = 0; x < 5; x++) {
            C[x] = state[x][0];
            for (y = 1; y < 5; y++) {
                C[x] ^= state[x][y];
            }
        }

        for (x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ keccak_rot(C[(x + 1) % 5], 1);
            for (y = 0; y < 5; y++) {
                state[x][y] ^=  D[x];
            }
        }

        // INFO(Rafael): Step 2 (a.k.a 'Pi').
        x = 1, y = 0;

        s_chunk = state[x][y];

        for (r_off = 0; r_off < 24; r_off++) {
            x_t = y, y_t = ((x << 1) + 3 * y) % 5;
            s_chunk_swp = state[x_t][y_t];
            state[x_t][y_t] = keccak_rot(s_chunk, keccak_rot_off(r_off));
            s_chunk = s_chunk_swp;
            x = x_t, y = y_t;
        }
        // INFO(Rafael): Step 3 (a.k.a 'Chi').
        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++) {
                C[x] = state[x][y];
            }

            for (x = 0; x < 5; x++) {
                state[x][y] = C[x] ^ ((~C[(x + 1) % 5]) & C[(x + 2) % 5]);
            }
        }

        // INFO(Rafael): Step 4 (a.k.a 'Iota').
        state[0][0] ^= kryptos_keccak_rc[r];
    }

    C[0] = C[1] = C[2] = C[3] = C[4] =
    D[0] = D[1] = D[2] = D[3] = D[4] = 0;

    s_chunk = s_chunk_swp = 0;
}

#undef keccak_rot

#undef keccak_rot_off

#undef keccak_pad

#undef kryptos_keccak_clear_ctx

#undef KRYPTOS_KECCAK_1600_ROUNDS_NR

#undef KRYPTOS_KECCAK_224_HASH_SIZE

#undef KRYPTOS_KECCAK_224_BYTES_PER_BLOCK

#undef KRYPTOS_KECCAK_256_HASH_SIZE

#undef KRYPTOS_KECCAK_256_BYTES_PER_BLOCK

#undef KRYPTOS_KECCAK_384_HASH_SIZE

#undef KRYPTOS_KECCAK_384_BYTES_PER_BLOCK

#undef KRYPTOS_KECCAK_512_HASH_SIZE

#undef KRYPTOS_KECCAK_512_BYTES_PER_BLOCK

#undef KRYPTOS_SHA3_224_HASH_SIZE

#undef KRYPTOS_SHA3_224_BYTES_PER_BLOCK

#undef KRYPTOS_SHA3_256_HASH_SIZE

#undef KRYPTOS_SHA3_256_BYTES_PER_BLOCK

#undef KRYPTOS_SHA3_384_HASH_SIZE

#undef KRYPTOS_SHA3_384_BYTES_PER_BLOCK

#undef KRYPTOS_SHA3_512_HASH_SIZE

#undef KRYPTOS_SHA3_512_BYTES_PER_BLOCK

#ifdef KRYPTOS_KECCAK_ARBITRARY_OUTPUT
# undef KRYPTOS_KECCAK_ARBITRARY_OUPUT
#endif
