/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_sha1.h>
#include <kryptos_hash_common.h>
#include <kryptos_memory.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_hex.h>
#include <string.h>

#define kryptos_sha1_Sn(x, n) ( (x) << (n) | (x) >> ((sizeof((x)) << 3) - (n)) )

#define kryptos_sha1_F(Fx, t, B, C, D){\
    if ((t) >= 0 && (t) <= 19) {\
        Fx = ((B) & (C)) | ((~(B)) & (D));\
    } else if (((t) >= 20 && (t) <= 39) || ((t) >= 60 && (t) <= 79)) {\
        Fx = (B) ^ (C) ^ (D);\
    } else if ((t) >= 40 && (t) <= 59) {\
        Fx = ((B) & (C)) | ((B) & (D)) | ((C) & (D));\
    }\
}

#define kryptos_sha1_K(Kx, t){\
    if ((t) >= 0 && (t) <= 19) {\
        Kx = 0x5A827999;\
    } else if ((t) >= 20 && (t) <= 39) {\
        Kx = 0x6ED9EBA1;\
    } else if ((t) >= 40 && (t) <= 59) {\
        Kx = 0x8F1BBCDC;\
    } else if ((t) >= 60 && (t) <= 79) {\
        Kx = 0xCA62C1D6;\
    }\
}

#define KRYPTOS_SHA1_BYTES_PER_BLOCK 64

#define KRYPTOS_SHA1_LEN_BLOCK_OFFSET 56

#define KRYPTOS_SHA1_HASH_SIZE 20

struct kryptos_sha1_input_message {
    kryptos_u32_t block[16];
};

struct kryptos_sha1_ctx {
    kryptos_u32_t state[5];
    struct kryptos_sha1_input_message input;
    kryptos_u8_t *message;
    kryptos_u64_t curr_len;
    kryptos_u64_t total_len;
    int paddin2times;
};

static size_t kryptos_sha1_block_index_decision_table[64] = {
     0,  0,  0,  0,
     1,  1,  1,  1,
     2,  2,  2,  2,
     3,  3,  3,  3,
     4,  4,  4,  4,
     5,  5,  5,  5,
     6,  6,  6,  6,
     7,  7,  7,  7,
     8,  8,  8,  8,
     9,  9,  9,  9,
    10, 10, 10, 10,
    11, 11, 11, 11,
    12, 12, 12, 12,
    13, 13, 13, 13,
    14, 14, 14, 14,
    15, 15, 15, 15,
};

static void kryptos_sha1_init(struct kryptos_sha1_ctx *ctx);

static void kryptos_sha1_do_block(struct kryptos_sha1_ctx *ctx);

KRYPTOS_DECL_HASH_MESSAGE_PROCESSOR(sha1, kryptos_sha1_ctx, ctx)

KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR(sha1, kryptos_sha1_ctx, ctx,
                                    KRYPTOS_SHA1_BYTES_PER_BLOCK,
                                    16, 32,
                                    kryptos_sha1_init(ctx),
                                    kryptos_sha1_do_block(ctx),
                                    kryptos_sha1_block_index_decision_table)

KRYPTOS_IMPL_HASH_SIZE(sha1, KRYPTOS_SHA1_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(sha1, KRYPTOS_SHA1_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(sha1, ktask, kryptos_sha1_ctx, ctx, sha1_hash_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3; // INFO(Rafael): Should be expressed in bits.
                            },
                            kryptos_sha1_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(KRYPTOS_SHA1_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha1_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA1_HASH_SIZE;
                                kryptos_cpy_u32_as_big_endian(     (*ktask)->out, 20, ctx.state[0]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  4, 16, ctx.state[1]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  8, 12, ctx.state[2]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 12,  8, ctx.state[3]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 16,  4, ctx.state[4]);
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_SHA1_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha1_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA1_HASH_SIZE << 1;
                                kryptos_u32_to_hex(     (*ktask)->out, 41, ctx.state[0]);
                                kryptos_u32_to_hex((*ktask)->out  + 8, 33, ctx.state[1]);
                                kryptos_u32_to_hex((*ktask)->out + 16, 25, ctx.state[2]);
                                kryptos_u32_to_hex((*ktask)->out + 24, 17, ctx.state[3]);
                                kryptos_u32_to_hex((*ktask)->out + 32,  9, ctx.state[4]);
                            })

static void kryptos_sha1_init(struct kryptos_sha1_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->paddin2times = 0;
}

static void kryptos_sha1_do_block(struct kryptos_sha1_ctx *ctx) {
    kryptos_u32_t A, B, C, D, E, TEMP, Fx, Kx;
    kryptos_u32_t W[80];
    size_t t;

    if (ctx->curr_len < 64) {
        kryptos_hash_apply_pad_on_u32_block(ctx->input.block, 16,
                                            kryptos_sha1_block_index_decision_table,
                                            ctx->curr_len, ctx->total_len, &ctx->paddin2times,
                                            KRYPTOS_SHA1_LEN_BLOCK_OFFSET);
    }

    W[ 0] = ctx->input.block[ 0];
    W[ 1] = ctx->input.block[ 1];
    W[ 2] = ctx->input.block[ 2];
    W[ 3] = ctx->input.block[ 3];
    W[ 4] = ctx->input.block[ 4];
    W[ 5] = ctx->input.block[ 5];
    W[ 6] = ctx->input.block[ 6];
    W[ 7] = ctx->input.block[ 7];
    W[ 8] = ctx->input.block[ 8];
    W[ 9] = ctx->input.block[ 9];
    W[10] = ctx->input.block[10];
    W[11] = ctx->input.block[11];
    W[12] = ctx->input.block[12];
    W[13] = ctx->input.block[13];
    W[14] = ctx->input.block[14];
    W[15] = ctx->input.block[15];

    for (t = 16; t < 80; t++) {
        W[t] = kryptos_sha1_Sn((W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]), 1);
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

    for (t = 0; t < 80; t++) {
        kryptos_sha1_F(Fx, t, B, C, D);
        kryptos_sha1_K(Kx, t);
        TEMP = kryptos_sha1_Sn(A, 5) + Fx + E + W[t] + Kx;
        E = D;
        D = C;
        C = kryptos_sha1_Sn(B, 30);
        B = A;
        A = TEMP;
    }

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;

    A = B = C = D = E = TEMP = Fx = Kx = 0;
    memset(W, 0, sizeof(W));
    t = 0;

    if (ctx->paddin2times) {
        kryptos_hash_ld_u8buf_as_u32_blocks("", 0, ctx->input.block, 16, kryptos_sha1_block_index_decision_table);
        kryptos_sha1_do_block(ctx);
    }
}

#undef kryptos_sha1_Sn

#undef kryptos_sha1_F

#undef kryptos_sha1_K

#undef KRYPTOS_SHA1_LEN_BLOCK_OFFSET
