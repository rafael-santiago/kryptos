/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_ripemd128_160.h>
#include <kryptos_hash_common.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_memory.h>
#include <kryptos_hex.h>
#include <string.h>

#define kryptos_ripemd_f0(x, y, z) ( (x) ^ (y) ^ (z) )

#define kryptos_ripemd_f1(x, y, z) ( ( (x) & (y) ) | ( (~(x)) & (z) ) )

#define kryptos_ripemd_f2(x, y, z) ( ( (x) | (~(y)) ) ^ (z) )

#define kryptos_ripemd_f3(x, y, z) ( ( (x) & (z) ) | ( (y) & (~(z)) ) )

#define kryptos_ripemd_f4(x, y, z) ( (x) ^ ( (y) | (~(z)) ) )

#define kryptos_ripemd_u32_rev(x) ( ((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24) )

#define KRYPTOS_RIPEMD_K0 0x00000000
#define KRYPTOS_RIPEMD_K1 0x5A827999
#define KRYPTOS_RIPEMD_K2 0x6ED9EBA1
#define KRYPTOS_RIPEMD_K3 0x8F1BBCDC
#define KRYPTOS_RIPEMD_K4 0xA953FD4E

#define KRYPTOS_RIPEMD_K0_ 0x50A28BE6
#define KRYPTOS_RIPEMD_K1_ 0x5C4DD124
#define KRYPTOS_RIPEMD_K2_ 0x6D703Ef3
#define KRYPTOS_RIPEMD_K3_ 0x7A6D76E9
#define KRYPTOS_RIPEMD_K4_ 0x00000000

#define kryptos_ripemd_rol(x, n) ( ( (x) << (n) ) | ( (x) >>  ( (sizeof(x) << 3) - (n) ) ) )

#define kryptos_ripemd160_line_proc(a, b, c, d, f, x, k, s, e)\
 ( (a) =  kryptos_ripemd_rol(a + f(b, c, d) + x + k, s) + e, c = kryptos_ripemd_rol(c, 10) )

#define kryptos_ripemd128_line_proc(a, b, c, d, f, x, k, s)\
 ( (a) =  kryptos_ripemd_rol(a + f(b, c, d) + x + k, s) )

#define KRYPTOS_RIPEMD_BYTES_PER_BLOCK 64

#define KRYPTOS_RIPEMD_LEN_BLOCK_OFFSET 56

#define KRYPTOS_RIPEMD128_HASH_SIZE 16

#define KRYPTOS_RIPEMD160_HASH_SIZE 20

struct kryptos_ripemd_input {
    kryptos_u32_t block[16];
};

typedef enum {
    kRIPEMD128Bits = 0,
    kRIPEMD160Bits,
    kRIPEMDBitsNr
}kryptos_ripemd_bitsize_t;

struct kryptos_ripemd_ctx {
    kryptos_ripemd_bitsize_t bits;
    kryptos_u32_t state[5];
    struct kryptos_ripemd_input input;
    kryptos_u8_t *message;
    kryptos_u64_t total_len, curr_len;
    int paddin2times;
};

static size_t kryptos_ripemd_block_index_decision_table[] = {
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
    15, 15, 15, 15
};

typedef void (*kryptos_ripemd_do_block_func)(struct kryptos_ripemd_ctx *ctx);

static void kryptos_ripemd_init(struct kryptos_ripemd_ctx *ctx);

static void kryptos_ripemd128_do_block(struct kryptos_ripemd_ctx *ctx);

static void kryptos_ripemd160_do_block(struct kryptos_ripemd_ctx *ctx);

static kryptos_ripemd_do_block_func kryptos_ripemd_do_block[kRIPEMDBitsNr] = {
    kryptos_ripemd128_do_block, kryptos_ripemd160_do_block
};

KRYPTOS_DECL_HASH_MESSAGE_PROCESSOR(ripemd, kryptos_ripemd_ctx, ctx);

KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR(ripemd, kryptos_ripemd_ctx, ctx, KRYPTOS_RIPEMD_BYTES_PER_BLOCK, 16, 32,
                                    kryptos_ripemd_init(ctx),
                                    kryptos_ripemd_do_block[ctx->bits](ctx),
                                    kryptos_ripemd_block_index_decision_table)

KRYPTOS_IMPL_HASH_SIZE(ripemd128, KRYPTOS_RIPEMD128_HASH_SIZE)

KRYPTOS_IMPL_HASH_PROCESSOR(ripemd128, ktask, kryptos_ripemd_ctx, ctx, ripemd128_hash_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3;
                                ctx.bits = kRIPEMD128Bits;
                            },
                            kryptos_ripemd_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(KRYPTOS_RIPEMD128_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_ripemd128_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_RIPEMD128_HASH_SIZE;
                                kryptos_cpy_u32_as_big_endian(     (*ktask)->out, 16, kryptos_ripemd_u32_rev(ctx.state[0]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  4, 12, kryptos_ripemd_u32_rev(ctx.state[1]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  8,  8, kryptos_ripemd_u32_rev(ctx.state[2]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 12,  4, kryptos_ripemd_u32_rev(ctx.state[3]));
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_RIPEMD128_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_ripemd128_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_RIPEMD128_HASH_SIZE << 1;
                                kryptos_u32_to_hex(     (*ktask)->out, 33, kryptos_ripemd_u32_rev(ctx.state[0]));
                                kryptos_u32_to_hex((*ktask)->out +  8, 25, kryptos_ripemd_u32_rev(ctx.state[1]));
                                kryptos_u32_to_hex((*ktask)->out + 16, 17, kryptos_ripemd_u32_rev(ctx.state[2]));
                                kryptos_u32_to_hex((*ktask)->out + 24,  9, kryptos_ripemd_u32_rev(ctx.state[3]));
                            })

KRYPTOS_IMPL_HASH_SIZE(ripemd160, KRYPTOS_RIPEMD160_HASH_SIZE)

KRYPTOS_IMPL_HASH_PROCESSOR(ripemd160, ktask, kryptos_ripemd_ctx, ctx, ripemd160_hash_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3;
                                ctx.bits = kRIPEMD160Bits;
                            },
                            kryptos_ripemd_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(KRYPTOS_RIPEMD160_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_ripemd160_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_RIPEMD160_HASH_SIZE;
                                kryptos_cpy_u32_as_big_endian(     (*ktask)->out, 20, kryptos_ripemd_u32_rev(ctx.state[0]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  4, 16, kryptos_ripemd_u32_rev(ctx.state[1]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  8, 12, kryptos_ripemd_u32_rev(ctx.state[2]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 12,  8, kryptos_ripemd_u32_rev(ctx.state[3]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 16,  4, kryptos_ripemd_u32_rev(ctx.state[4]));
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_RIPEMD160_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_ripemd160_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_RIPEMD160_HASH_SIZE << 1;
                                kryptos_u32_to_hex(     (*ktask)->out, 41, kryptos_ripemd_u32_rev(ctx.state[0]));
                                kryptos_u32_to_hex((*ktask)->out  + 8, 33, kryptos_ripemd_u32_rev(ctx.state[1]));
                                kryptos_u32_to_hex((*ktask)->out + 16, 25, kryptos_ripemd_u32_rev(ctx.state[2]));
                                kryptos_u32_to_hex((*ktask)->out + 24, 17, kryptos_ripemd_u32_rev(ctx.state[3]));
                                kryptos_u32_to_hex((*ktask)->out + 32,  9, kryptos_ripemd_u32_rev(ctx.state[4]));
                            })

static void kryptos_ripemd_init(struct kryptos_ripemd_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;

    if(ctx->bits == kRIPEMD160Bits) {
        ctx->state[4] = 0xC3D2E1F0;
    }

    ctx->paddin2times = 0;
}

static void kryptos_ripemd128_do_block(struct kryptos_ripemd_ctx *ctx) {
    kryptos_u32_t A, A_, B, B_, C, C_, D, D_, T;

    if (ctx->curr_len < KRYPTOS_RIPEMD_BYTES_PER_BLOCK) {
        kryptos_hash_apply_pad_on_u32_block(ctx->input.block, 16,
                                            kryptos_ripemd_block_index_decision_table,
                                            ctx->curr_len, ctx->total_len, &ctx->paddin2times,
                                            KRYPTOS_RIPEMD_LEN_BLOCK_OFFSET);
        if (!ctx->paddin2times) {
            A = ctx->input.block[14];
            ctx->input.block[14] = kryptos_ripemd_u32_rev(ctx->input.block[15]);
            ctx->input.block[15] = kryptos_ripemd_u32_rev(A);
        }
    }

    A = A_ = ctx->state[0];
    B = B_ = ctx->state[1];
    C = C_ = ctx->state[2];
    D = D_ = ctx->state[3];

    ctx->input.block[ 0] = kryptos_ripemd_u32_rev(ctx->input.block[ 0]);
    ctx->input.block[ 1] = kryptos_ripemd_u32_rev(ctx->input.block[ 1]);
    ctx->input.block[ 2] = kryptos_ripemd_u32_rev(ctx->input.block[ 2]);
    ctx->input.block[ 3] = kryptos_ripemd_u32_rev(ctx->input.block[ 3]);
    ctx->input.block[ 4] = kryptos_ripemd_u32_rev(ctx->input.block[ 4]);
    ctx->input.block[ 5] = kryptos_ripemd_u32_rev(ctx->input.block[ 5]);
    ctx->input.block[ 6] = kryptos_ripemd_u32_rev(ctx->input.block[ 6]);
    ctx->input.block[ 7] = kryptos_ripemd_u32_rev(ctx->input.block[ 7]);
    ctx->input.block[ 8] = kryptos_ripemd_u32_rev(ctx->input.block[ 8]);
    ctx->input.block[ 9] = kryptos_ripemd_u32_rev(ctx->input.block[ 9]);
    ctx->input.block[10] = kryptos_ripemd_u32_rev(ctx->input.block[10]);
    ctx->input.block[11] = kryptos_ripemd_u32_rev(ctx->input.block[11]);
    ctx->input.block[12] = kryptos_ripemd_u32_rev(ctx->input.block[12]);
    ctx->input.block[13] = kryptos_ripemd_u32_rev(ctx->input.block[13]);
    ctx->input.block[14] = kryptos_ripemd_u32_rev(ctx->input.block[14]);
    ctx->input.block[15] = kryptos_ripemd_u32_rev(ctx->input.block[15]);

    // INFO(Rafael): Well, take a breath :)

    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f0, ctx->input.block[ 0], KRYPTOS_RIPEMD_K0, 11);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f0, ctx->input.block[ 1], KRYPTOS_RIPEMD_K0, 14);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f0, ctx->input.block[ 2], KRYPTOS_RIPEMD_K0, 15);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f0, ctx->input.block[ 3], KRYPTOS_RIPEMD_K0, 12);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f0, ctx->input.block[ 4], KRYPTOS_RIPEMD_K0,  5);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f0, ctx->input.block[ 5], KRYPTOS_RIPEMD_K0,  8);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f0, ctx->input.block[ 6], KRYPTOS_RIPEMD_K0,  7);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f0, ctx->input.block[ 7], KRYPTOS_RIPEMD_K0,  9);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f0, ctx->input.block[ 8], KRYPTOS_RIPEMD_K0, 11);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f0, ctx->input.block[ 9], KRYPTOS_RIPEMD_K0, 13);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f0, ctx->input.block[10], KRYPTOS_RIPEMD_K0, 14);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f0, ctx->input.block[11], KRYPTOS_RIPEMD_K0, 15);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f0, ctx->input.block[12], KRYPTOS_RIPEMD_K0,  6);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f0, ctx->input.block[13], KRYPTOS_RIPEMD_K0,  7);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f0, ctx->input.block[14], KRYPTOS_RIPEMD_K0,  9);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f0, ctx->input.block[15], KRYPTOS_RIPEMD_K0,  8);

    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f3, ctx->input.block[ 5], KRYPTOS_RIPEMD_K0_,  8);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f3, ctx->input.block[14], KRYPTOS_RIPEMD_K0_,  9);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f3, ctx->input.block[ 7], KRYPTOS_RIPEMD_K0_,  9);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f3, ctx->input.block[ 0], KRYPTOS_RIPEMD_K0_, 11);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f3, ctx->input.block[ 9], KRYPTOS_RIPEMD_K0_, 13);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f3, ctx->input.block[ 2], KRYPTOS_RIPEMD_K0_, 15);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f3, ctx->input.block[11], KRYPTOS_RIPEMD_K0_, 15);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f3, ctx->input.block[ 4], KRYPTOS_RIPEMD_K0_,  5);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f3, ctx->input.block[13], KRYPTOS_RIPEMD_K0_,  7);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f3, ctx->input.block[ 6], KRYPTOS_RIPEMD_K0_,  7);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f3, ctx->input.block[15], KRYPTOS_RIPEMD_K0_,  8);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f3, ctx->input.block[ 8], KRYPTOS_RIPEMD_K0_, 11);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f3, ctx->input.block[ 1], KRYPTOS_RIPEMD_K0_, 14);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f3, ctx->input.block[10], KRYPTOS_RIPEMD_K0_, 14);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f3, ctx->input.block[ 3], KRYPTOS_RIPEMD_K0_, 12);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f3, ctx->input.block[12], KRYPTOS_RIPEMD_K0_,  6);

    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f1, ctx->input.block[ 7], KRYPTOS_RIPEMD_K1,  7);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f1, ctx->input.block[ 4], KRYPTOS_RIPEMD_K1,  6);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f1, ctx->input.block[13], KRYPTOS_RIPEMD_K1,  8);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f1, ctx->input.block[ 1], KRYPTOS_RIPEMD_K1, 13);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f1, ctx->input.block[10], KRYPTOS_RIPEMD_K1, 11);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f1, ctx->input.block[ 6], KRYPTOS_RIPEMD_K1,  9);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f1, ctx->input.block[15], KRYPTOS_RIPEMD_K1,  7);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f1, ctx->input.block[ 3], KRYPTOS_RIPEMD_K1, 15);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f1, ctx->input.block[12], KRYPTOS_RIPEMD_K1,  7);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f1, ctx->input.block[ 0], KRYPTOS_RIPEMD_K1, 12);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f1, ctx->input.block[ 9], KRYPTOS_RIPEMD_K1, 15);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f1, ctx->input.block[ 5], KRYPTOS_RIPEMD_K1,  9);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f1, ctx->input.block[ 2], KRYPTOS_RIPEMD_K1, 11);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f1, ctx->input.block[14], KRYPTOS_RIPEMD_K1,  7);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f1, ctx->input.block[11], KRYPTOS_RIPEMD_K1, 13);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f1, ctx->input.block[ 8], KRYPTOS_RIPEMD_K1, 12);

    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f2, ctx->input.block[ 6], KRYPTOS_RIPEMD_K1_,  9);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f2, ctx->input.block[11], KRYPTOS_RIPEMD_K1_, 13);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f2, ctx->input.block[ 3], KRYPTOS_RIPEMD_K1_, 15);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f2, ctx->input.block[ 7], KRYPTOS_RIPEMD_K1_,  7);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f2, ctx->input.block[ 0], KRYPTOS_RIPEMD_K1_, 12);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f2, ctx->input.block[13], KRYPTOS_RIPEMD_K1_,  8);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f2, ctx->input.block[ 5], KRYPTOS_RIPEMD_K1_,  9);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f2, ctx->input.block[10], KRYPTOS_RIPEMD_K1_, 11);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f2, ctx->input.block[14], KRYPTOS_RIPEMD_K1_,  7);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f2, ctx->input.block[15], KRYPTOS_RIPEMD_K1_,  7);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f2, ctx->input.block[ 8], KRYPTOS_RIPEMD_K1_, 12);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f2, ctx->input.block[12], KRYPTOS_RIPEMD_K1_,  7);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f2, ctx->input.block[ 4], KRYPTOS_RIPEMD_K1_,  6);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f2, ctx->input.block[ 9], KRYPTOS_RIPEMD_K1_, 15);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f2, ctx->input.block[ 1], KRYPTOS_RIPEMD_K1_, 13);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f2, ctx->input.block[ 2], KRYPTOS_RIPEMD_K1_, 11);

    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f2, ctx->input.block[ 3], KRYPTOS_RIPEMD_K2, 11);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f2, ctx->input.block[10], KRYPTOS_RIPEMD_K2, 13);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f2, ctx->input.block[14], KRYPTOS_RIPEMD_K2,  6);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f2, ctx->input.block[ 4], KRYPTOS_RIPEMD_K2,  7);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f2, ctx->input.block[ 9], KRYPTOS_RIPEMD_K2, 14);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f2, ctx->input.block[15], KRYPTOS_RIPEMD_K2,  9);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f2, ctx->input.block[ 8], KRYPTOS_RIPEMD_K2, 13);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f2, ctx->input.block[ 1], KRYPTOS_RIPEMD_K2, 15);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f2, ctx->input.block[ 2], KRYPTOS_RIPEMD_K2, 14);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f2, ctx->input.block[ 7], KRYPTOS_RIPEMD_K2,  8);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f2, ctx->input.block[ 0], KRYPTOS_RIPEMD_K2, 13);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f2, ctx->input.block[ 6], KRYPTOS_RIPEMD_K2,  6);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f2, ctx->input.block[13], KRYPTOS_RIPEMD_K2,  5);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f2, ctx->input.block[11], KRYPTOS_RIPEMD_K2, 12);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f2, ctx->input.block[ 5], KRYPTOS_RIPEMD_K2,  7);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f2, ctx->input.block[12], KRYPTOS_RIPEMD_K2,  5);

    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f1, ctx->input.block[15], KRYPTOS_RIPEMD_K2_,  9);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f1, ctx->input.block[ 5], KRYPTOS_RIPEMD_K2_,  7);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f1, ctx->input.block[ 1], KRYPTOS_RIPEMD_K2_, 15);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f1, ctx->input.block[ 3], KRYPTOS_RIPEMD_K2_, 11);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f1, ctx->input.block[ 7], KRYPTOS_RIPEMD_K2_,  8);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f1, ctx->input.block[14], KRYPTOS_RIPEMD_K2_,  6);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f1, ctx->input.block[ 6], KRYPTOS_RIPEMD_K2_,  6);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f1, ctx->input.block[ 9], KRYPTOS_RIPEMD_K2_, 14);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f1, ctx->input.block[11], KRYPTOS_RIPEMD_K2_, 12);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f1, ctx->input.block[ 8], KRYPTOS_RIPEMD_K2_, 13);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f1, ctx->input.block[12], KRYPTOS_RIPEMD_K2_,  5);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f1, ctx->input.block[ 2], KRYPTOS_RIPEMD_K2_, 14);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f1, ctx->input.block[10], KRYPTOS_RIPEMD_K2_, 13);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f1, ctx->input.block[ 0], KRYPTOS_RIPEMD_K2_, 13);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f1, ctx->input.block[ 4], KRYPTOS_RIPEMD_K2_,  7);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f1, ctx->input.block[13], KRYPTOS_RIPEMD_K2_,  5);

    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f3, ctx->input.block[ 1], KRYPTOS_RIPEMD_K3, 11);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f3, ctx->input.block[ 9], KRYPTOS_RIPEMD_K3, 12);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f3, ctx->input.block[11], KRYPTOS_RIPEMD_K3, 14);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f3, ctx->input.block[10], KRYPTOS_RIPEMD_K3, 15);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f3, ctx->input.block[ 0], KRYPTOS_RIPEMD_K3, 14);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f3, ctx->input.block[ 8], KRYPTOS_RIPEMD_K3, 15);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f3, ctx->input.block[12], KRYPTOS_RIPEMD_K3,  9);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f3, ctx->input.block[ 4], KRYPTOS_RIPEMD_K3,  8);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f3, ctx->input.block[13], KRYPTOS_RIPEMD_K3,  9);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f3, ctx->input.block[ 3], KRYPTOS_RIPEMD_K3, 14);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f3, ctx->input.block[ 7], KRYPTOS_RIPEMD_K3,  5);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f3, ctx->input.block[15], KRYPTOS_RIPEMD_K3,  6);
    kryptos_ripemd128_line_proc(A, B, C, D, kryptos_ripemd_f3, ctx->input.block[14], KRYPTOS_RIPEMD_K3,  8);
    kryptos_ripemd128_line_proc(D, A, B, C, kryptos_ripemd_f3, ctx->input.block[ 5], KRYPTOS_RIPEMD_K3,  6);
    kryptos_ripemd128_line_proc(C, D, A, B, kryptos_ripemd_f3, ctx->input.block[ 6], KRYPTOS_RIPEMD_K3,  5);
    kryptos_ripemd128_line_proc(B, C, D, A, kryptos_ripemd_f3, ctx->input.block[ 2], KRYPTOS_RIPEMD_K3, 12);

    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f0, ctx->input.block[ 8], KRYPTOS_RIPEMD_K4_, 15);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f0, ctx->input.block[ 6], KRYPTOS_RIPEMD_K4_,  5);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f0, ctx->input.block[ 4], KRYPTOS_RIPEMD_K4_,  8);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f0, ctx->input.block[ 1], KRYPTOS_RIPEMD_K4_, 11);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f0, ctx->input.block[ 3], KRYPTOS_RIPEMD_K4_, 14);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f0, ctx->input.block[11], KRYPTOS_RIPEMD_K4_, 14);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f0, ctx->input.block[15], KRYPTOS_RIPEMD_K4_,  6);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f0, ctx->input.block[ 0], KRYPTOS_RIPEMD_K4_, 14);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f0, ctx->input.block[ 5], KRYPTOS_RIPEMD_K4_,  6);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f0, ctx->input.block[12], KRYPTOS_RIPEMD_K4_,  9);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f0, ctx->input.block[ 2], KRYPTOS_RIPEMD_K4_, 12);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f0, ctx->input.block[13], KRYPTOS_RIPEMD_K4_,  9);
    kryptos_ripemd128_line_proc(A_, B_, C_, D_, kryptos_ripemd_f0, ctx->input.block[ 9], KRYPTOS_RIPEMD_K4_, 12);
    kryptos_ripemd128_line_proc(D_, A_, B_, C_, kryptos_ripemd_f0, ctx->input.block[ 7], KRYPTOS_RIPEMD_K4_,  5);
    kryptos_ripemd128_line_proc(C_, D_, A_, B_, kryptos_ripemd_f0, ctx->input.block[10], KRYPTOS_RIPEMD_K4_, 15);
    kryptos_ripemd128_line_proc(B_, C_, D_, A_, kryptos_ripemd_f0, ctx->input.block[14], KRYPTOS_RIPEMD_K4_,  8);

    T = ctx->state[1] + D_ + C;
    ctx->state[1] = ctx->state[2] + A_ + D;
    ctx->state[2] = ctx->state[3] + B_ + A;
    ctx->state[3] = ctx->state[0] + C_ + B;
    ctx->state[0] = T;

    T = A = A_ = B = B_ = C = C_ = D = D_ = 0;

    if (ctx->paddin2times) {
        kryptos_hash_ld_u8buf_as_u32_blocks("", 0, ctx->input.block, 16, kryptos_ripemd_block_index_decision_table);
        kryptos_ripemd128_do_block(ctx);
    }
}

static void kryptos_ripemd160_do_block(struct kryptos_ripemd_ctx *ctx) {
    kryptos_u32_t A, A_, B, B_, C, C_, D, D_, E, E_, T;

    if (ctx->curr_len < KRYPTOS_RIPEMD_BYTES_PER_BLOCK) {
        kryptos_hash_apply_pad_on_u32_block(ctx->input.block, 16,
                                            kryptos_ripemd_block_index_decision_table,
                                            ctx->curr_len, ctx->total_len, &ctx->paddin2times,
                                            KRYPTOS_RIPEMD_LEN_BLOCK_OFFSET);
        if (!ctx->paddin2times) {
            A = ctx->input.block[14];
            ctx->input.block[14] = kryptos_ripemd_u32_rev(ctx->input.block[15]);
            ctx->input.block[15] = kryptos_ripemd_u32_rev(A);
        }
    }

    A = A_ = ctx->state[0];
    B = B_ = ctx->state[1];
    C = C_ = ctx->state[2];
    D = D_ = ctx->state[3];
    E = E_ = ctx->state[4];

    ctx->input.block[ 0] = kryptos_ripemd_u32_rev(ctx->input.block[ 0]);
    ctx->input.block[ 1] = kryptos_ripemd_u32_rev(ctx->input.block[ 1]);
    ctx->input.block[ 2] = kryptos_ripemd_u32_rev(ctx->input.block[ 2]);
    ctx->input.block[ 3] = kryptos_ripemd_u32_rev(ctx->input.block[ 3]);
    ctx->input.block[ 4] = kryptos_ripemd_u32_rev(ctx->input.block[ 4]);
    ctx->input.block[ 5] = kryptos_ripemd_u32_rev(ctx->input.block[ 5]);
    ctx->input.block[ 6] = kryptos_ripemd_u32_rev(ctx->input.block[ 6]);
    ctx->input.block[ 7] = kryptos_ripemd_u32_rev(ctx->input.block[ 7]);
    ctx->input.block[ 8] = kryptos_ripemd_u32_rev(ctx->input.block[ 8]);
    ctx->input.block[ 9] = kryptos_ripemd_u32_rev(ctx->input.block[ 9]);
    ctx->input.block[10] = kryptos_ripemd_u32_rev(ctx->input.block[10]);
    ctx->input.block[11] = kryptos_ripemd_u32_rev(ctx->input.block[11]);
    ctx->input.block[12] = kryptos_ripemd_u32_rev(ctx->input.block[12]);
    ctx->input.block[13] = kryptos_ripemd_u32_rev(ctx->input.block[13]);
    ctx->input.block[14] = kryptos_ripemd_u32_rev(ctx->input.block[14]);
    ctx->input.block[15] = kryptos_ripemd_u32_rev(ctx->input.block[15]);

    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f0, ctx->input.block[ 0], KRYPTOS_RIPEMD_K0, 11, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f0, ctx->input.block[ 1], KRYPTOS_RIPEMD_K0, 14, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f0, ctx->input.block[ 2], KRYPTOS_RIPEMD_K0, 15, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f0, ctx->input.block[ 3], KRYPTOS_RIPEMD_K0, 12, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f0, ctx->input.block[ 4], KRYPTOS_RIPEMD_K0,  5, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f0, ctx->input.block[ 5], KRYPTOS_RIPEMD_K0,  8, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f0, ctx->input.block[ 6], KRYPTOS_RIPEMD_K0,  7, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f0, ctx->input.block[ 7], KRYPTOS_RIPEMD_K0,  9, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f0, ctx->input.block[ 8], KRYPTOS_RIPEMD_K0, 11, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f0, ctx->input.block[ 9], KRYPTOS_RIPEMD_K0, 13, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f0, ctx->input.block[10], KRYPTOS_RIPEMD_K0, 14, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f0, ctx->input.block[11], KRYPTOS_RIPEMD_K0, 15, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f0, ctx->input.block[12], KRYPTOS_RIPEMD_K0,  6, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f0, ctx->input.block[13], KRYPTOS_RIPEMD_K0,  7, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f0, ctx->input.block[14], KRYPTOS_RIPEMD_K0,  9, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f0, ctx->input.block[15], KRYPTOS_RIPEMD_K0,  8, E);

    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f4, ctx->input.block[ 5], KRYPTOS_RIPEMD_K0_,  8, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f4, ctx->input.block[14], KRYPTOS_RIPEMD_K0_,  9, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f4, ctx->input.block[ 7], KRYPTOS_RIPEMD_K0_,  9, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f4, ctx->input.block[ 0], KRYPTOS_RIPEMD_K0_, 11, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f4, ctx->input.block[ 9], KRYPTOS_RIPEMD_K0_, 13, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f4, ctx->input.block[ 2], KRYPTOS_RIPEMD_K0_, 15, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f4, ctx->input.block[11], KRYPTOS_RIPEMD_K0_, 15, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f4, ctx->input.block[ 4], KRYPTOS_RIPEMD_K0_,  5, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f4, ctx->input.block[13], KRYPTOS_RIPEMD_K0_,  7, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f4, ctx->input.block[ 6], KRYPTOS_RIPEMD_K0_,  7, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f4, ctx->input.block[15], KRYPTOS_RIPEMD_K0_,  8, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f4, ctx->input.block[ 8], KRYPTOS_RIPEMD_K0_, 11, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f4, ctx->input.block[ 1], KRYPTOS_RIPEMD_K0_, 14, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f4, ctx->input.block[10], KRYPTOS_RIPEMD_K0_, 14, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f4, ctx->input.block[ 3], KRYPTOS_RIPEMD_K0_, 12, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f4, ctx->input.block[12], KRYPTOS_RIPEMD_K0_,  6, E_);

    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f1, ctx->input.block[ 7], KRYPTOS_RIPEMD_K1,  7, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f1, ctx->input.block[ 4], KRYPTOS_RIPEMD_K1,  6, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f1, ctx->input.block[13], KRYPTOS_RIPEMD_K1,  8, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f1, ctx->input.block[ 1], KRYPTOS_RIPEMD_K1, 13, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f1, ctx->input.block[10], KRYPTOS_RIPEMD_K1, 11, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f1, ctx->input.block[ 6], KRYPTOS_RIPEMD_K1,  9, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f1, ctx->input.block[15], KRYPTOS_RIPEMD_K1,  7, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f1, ctx->input.block[ 3], KRYPTOS_RIPEMD_K1, 15, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f1, ctx->input.block[12], KRYPTOS_RIPEMD_K1,  7, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f1, ctx->input.block[ 0], KRYPTOS_RIPEMD_K1, 12, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f1, ctx->input.block[ 9], KRYPTOS_RIPEMD_K1, 15, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f1, ctx->input.block[ 5], KRYPTOS_RIPEMD_K1,  9, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f1, ctx->input.block[ 2], KRYPTOS_RIPEMD_K1, 11, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f1, ctx->input.block[14], KRYPTOS_RIPEMD_K1,  7, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f1, ctx->input.block[11], KRYPTOS_RIPEMD_K1, 13, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f1, ctx->input.block[ 8], KRYPTOS_RIPEMD_K1, 12, D);

    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f3, ctx->input.block[ 6], KRYPTOS_RIPEMD_K1_,  9, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f3, ctx->input.block[11], KRYPTOS_RIPEMD_K1_, 13, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f3, ctx->input.block[ 3], KRYPTOS_RIPEMD_K1_, 15, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f3, ctx->input.block[ 7], KRYPTOS_RIPEMD_K1_,  7, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f3, ctx->input.block[ 0], KRYPTOS_RIPEMD_K1_, 12, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f3, ctx->input.block[13], KRYPTOS_RIPEMD_K1_,  8, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f3, ctx->input.block[ 5], KRYPTOS_RIPEMD_K1_,  9, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f3, ctx->input.block[10], KRYPTOS_RIPEMD_K1_, 11, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f3, ctx->input.block[14], KRYPTOS_RIPEMD_K1_,  7, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f3, ctx->input.block[15], KRYPTOS_RIPEMD_K1_,  7, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f3, ctx->input.block[ 8], KRYPTOS_RIPEMD_K1_, 12, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f3, ctx->input.block[12], KRYPTOS_RIPEMD_K1_,  7, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f3, ctx->input.block[ 4], KRYPTOS_RIPEMD_K1_,  6, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f3, ctx->input.block[ 9], KRYPTOS_RIPEMD_K1_, 15, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f3, ctx->input.block[ 1], KRYPTOS_RIPEMD_K1_, 13, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f3, ctx->input.block[ 2], KRYPTOS_RIPEMD_K1_, 11, D_);

    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f2, ctx->input.block[ 3], KRYPTOS_RIPEMD_K2, 11, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f2, ctx->input.block[10], KRYPTOS_RIPEMD_K2, 13, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f2, ctx->input.block[14], KRYPTOS_RIPEMD_K2,  6, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f2, ctx->input.block[ 4], KRYPTOS_RIPEMD_K2,  7, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f2, ctx->input.block[ 9], KRYPTOS_RIPEMD_K2, 14, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f2, ctx->input.block[15], KRYPTOS_RIPEMD_K2,  9, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f2, ctx->input.block[ 8], KRYPTOS_RIPEMD_K2, 13, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f2, ctx->input.block[ 1], KRYPTOS_RIPEMD_K2, 15, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f2, ctx->input.block[ 2], KRYPTOS_RIPEMD_K2, 14, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f2, ctx->input.block[ 7], KRYPTOS_RIPEMD_K2,  8, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f2, ctx->input.block[ 0], KRYPTOS_RIPEMD_K2, 13, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f2, ctx->input.block[ 6], KRYPTOS_RIPEMD_K2,  6, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f2, ctx->input.block[13], KRYPTOS_RIPEMD_K2,  5, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f2, ctx->input.block[11], KRYPTOS_RIPEMD_K2, 12, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f2, ctx->input.block[ 5], KRYPTOS_RIPEMD_K2,  7, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f2, ctx->input.block[12], KRYPTOS_RIPEMD_K2,  5, C);

    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f2, ctx->input.block[15], KRYPTOS_RIPEMD_K2_,  9, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f2, ctx->input.block[ 5], KRYPTOS_RIPEMD_K2_,  7, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f2, ctx->input.block[ 1], KRYPTOS_RIPEMD_K2_, 15, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f2, ctx->input.block[ 3], KRYPTOS_RIPEMD_K2_, 11, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f2, ctx->input.block[ 7], KRYPTOS_RIPEMD_K2_,  8, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f2, ctx->input.block[14], KRYPTOS_RIPEMD_K2_,  6, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f2, ctx->input.block[ 6], KRYPTOS_RIPEMD_K2_,  6, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f2, ctx->input.block[ 9], KRYPTOS_RIPEMD_K2_, 14, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f2, ctx->input.block[11], KRYPTOS_RIPEMD_K2_, 12, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f2, ctx->input.block[ 8], KRYPTOS_RIPEMD_K2_, 13, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f2, ctx->input.block[12], KRYPTOS_RIPEMD_K2_,  5, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f2, ctx->input.block[ 2], KRYPTOS_RIPEMD_K2_, 14, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f2, ctx->input.block[10], KRYPTOS_RIPEMD_K2_, 13, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f2, ctx->input.block[ 0], KRYPTOS_RIPEMD_K2_, 13, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f2, ctx->input.block[ 4], KRYPTOS_RIPEMD_K2_,  7, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f2, ctx->input.block[13], KRYPTOS_RIPEMD_K2_,  5, C_);

    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f3, ctx->input.block[ 1], KRYPTOS_RIPEMD_K3, 11, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f3, ctx->input.block[ 9], KRYPTOS_RIPEMD_K3, 12, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f3, ctx->input.block[11], KRYPTOS_RIPEMD_K3, 14, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f3, ctx->input.block[10], KRYPTOS_RIPEMD_K3, 15, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f3, ctx->input.block[ 0], KRYPTOS_RIPEMD_K3, 14, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f3, ctx->input.block[ 8], KRYPTOS_RIPEMD_K3, 15, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f3, ctx->input.block[12], KRYPTOS_RIPEMD_K3,  9, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f3, ctx->input.block[ 4], KRYPTOS_RIPEMD_K3,  8, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f3, ctx->input.block[13], KRYPTOS_RIPEMD_K3,  9, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f3, ctx->input.block[ 3], KRYPTOS_RIPEMD_K3, 14, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f3, ctx->input.block[ 7], KRYPTOS_RIPEMD_K3,  5, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f3, ctx->input.block[15], KRYPTOS_RIPEMD_K3,  6, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f3, ctx->input.block[14], KRYPTOS_RIPEMD_K3,  8, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f3, ctx->input.block[ 5], KRYPTOS_RIPEMD_K3,  6, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f3, ctx->input.block[ 6], KRYPTOS_RIPEMD_K3,  5, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f3, ctx->input.block[ 2], KRYPTOS_RIPEMD_K3, 12, B);

    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f1, ctx->input.block[ 8], KRYPTOS_RIPEMD_K3_, 15, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f1, ctx->input.block[ 6], KRYPTOS_RIPEMD_K3_,  5, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f1, ctx->input.block[ 4], KRYPTOS_RIPEMD_K3_,  8, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f1, ctx->input.block[ 1], KRYPTOS_RIPEMD_K3_, 11, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f1, ctx->input.block[ 3], KRYPTOS_RIPEMD_K3_, 14, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f1, ctx->input.block[11], KRYPTOS_RIPEMD_K3_, 14, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f1, ctx->input.block[15], KRYPTOS_RIPEMD_K3_,  6, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f1, ctx->input.block[ 0], KRYPTOS_RIPEMD_K3_, 14, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f1, ctx->input.block[ 5], KRYPTOS_RIPEMD_K3_,  6, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f1, ctx->input.block[12], KRYPTOS_RIPEMD_K3_,  9, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f1, ctx->input.block[ 2], KRYPTOS_RIPEMD_K3_, 12, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f1, ctx->input.block[13], KRYPTOS_RIPEMD_K3_,  9, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f1, ctx->input.block[ 9], KRYPTOS_RIPEMD_K3_, 12, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f1, ctx->input.block[ 7], KRYPTOS_RIPEMD_K3_,  5, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f1, ctx->input.block[10], KRYPTOS_RIPEMD_K3_, 15, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f1, ctx->input.block[14], KRYPTOS_RIPEMD_K3_,  8, B_);

    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f4, ctx->input.block[ 4], KRYPTOS_RIPEMD_K4,  9, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f4, ctx->input.block[ 0], KRYPTOS_RIPEMD_K4, 15, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f4, ctx->input.block[ 5], KRYPTOS_RIPEMD_K4,  5, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f4, ctx->input.block[ 9], KRYPTOS_RIPEMD_K4, 11, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f4, ctx->input.block[ 7], KRYPTOS_RIPEMD_K4,  6, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f4, ctx->input.block[12], KRYPTOS_RIPEMD_K4,  8, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f4, ctx->input.block[ 2], KRYPTOS_RIPEMD_K4, 13, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f4, ctx->input.block[10], KRYPTOS_RIPEMD_K4, 12, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f4, ctx->input.block[14], KRYPTOS_RIPEMD_K4,  5, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f4, ctx->input.block[ 1], KRYPTOS_RIPEMD_K4, 12, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f4, ctx->input.block[ 3], KRYPTOS_RIPEMD_K4, 13, A);
    kryptos_ripemd160_line_proc(A, B, C, D, kryptos_ripemd_f4, ctx->input.block[ 8], KRYPTOS_RIPEMD_K4, 14, E);
    kryptos_ripemd160_line_proc(E, A, B, C, kryptos_ripemd_f4, ctx->input.block[11], KRYPTOS_RIPEMD_K4, 11, D);
    kryptos_ripemd160_line_proc(D, E, A, B, kryptos_ripemd_f4, ctx->input.block[ 6], KRYPTOS_RIPEMD_K4,  8, C);
    kryptos_ripemd160_line_proc(C, D, E, A, kryptos_ripemd_f4, ctx->input.block[15], KRYPTOS_RIPEMD_K4,  5, B);
    kryptos_ripemd160_line_proc(B, C, D, E, kryptos_ripemd_f4, ctx->input.block[13], KRYPTOS_RIPEMD_K4,  6, A);

    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f0, ctx->input.block[12], KRYPTOS_RIPEMD_K4_,  8, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f0, ctx->input.block[15], KRYPTOS_RIPEMD_K4_,  5, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f0, ctx->input.block[10], KRYPTOS_RIPEMD_K4_, 12, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f0, ctx->input.block[ 4], KRYPTOS_RIPEMD_K4_,  9, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f0, ctx->input.block[ 1], KRYPTOS_RIPEMD_K4_, 12, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f0, ctx->input.block[ 5], KRYPTOS_RIPEMD_K4_,  5, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f0, ctx->input.block[ 8], KRYPTOS_RIPEMD_K4_, 14, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f0, ctx->input.block[ 7], KRYPTOS_RIPEMD_K4_,  6, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f0, ctx->input.block[ 6], KRYPTOS_RIPEMD_K4_,  8, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f0, ctx->input.block[ 2], KRYPTOS_RIPEMD_K4_, 13, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f0, ctx->input.block[13], KRYPTOS_RIPEMD_K4_,  6, A_);
    kryptos_ripemd160_line_proc(A_, B_, C_, D_, kryptos_ripemd_f0, ctx->input.block[14], KRYPTOS_RIPEMD_K4_,  5, E_);
    kryptos_ripemd160_line_proc(E_, A_, B_, C_, kryptos_ripemd_f0, ctx->input.block[ 0], KRYPTOS_RIPEMD_K4_, 15, D_);
    kryptos_ripemd160_line_proc(D_, E_, A_, B_, kryptos_ripemd_f0, ctx->input.block[ 3], KRYPTOS_RIPEMD_K4_, 13, C_);
    kryptos_ripemd160_line_proc(C_, D_, E_, A_, kryptos_ripemd_f0, ctx->input.block[ 9], KRYPTOS_RIPEMD_K4_, 11, B_);
    kryptos_ripemd160_line_proc(B_, C_, D_, E_, kryptos_ripemd_f0, ctx->input.block[11], KRYPTOS_RIPEMD_K4_, 11, A_);

    T = ctx->state[1] + D_ + C;
    ctx->state[1] = ctx->state[2] + E_ + D;
    ctx->state[2] = ctx->state[3] + A_ + E;
    ctx->state[3] = ctx->state[4] + B_ + A;
    ctx->state[4] = ctx->state[0] + C_ + B;
    ctx->state[0] = T;

    T = A = A_ = B = B_ = C = C_ = D = D_ = E = E_ = 0;

    if (ctx->paddin2times) {
        kryptos_hash_ld_u8buf_as_u32_blocks("", 0, ctx->input.block, 16, kryptos_ripemd_block_index_decision_table);
        kryptos_ripemd160_do_block(ctx);
    }
}

#undef kryptos_ripemd_f0

#undef kryptos_ripemd_f1

#undef kryptos_ripemd_f2

#undef kryptos_ripemd_f3

#undef kryptos_ripemd_f4

#undef kryptos_ripemd_u32_rev

#undef KRYPTOS_RIPEMD_K0

#undef KRYPTOS_RIPEMD_K1

#undef KRYPTOS_RIPEMD_K2

#undef KRYPTOS_RIPEMD_K3

#undef KRYPTOS_RIPEMD_K4

#undef KRYPTOS_RIPEMD_K0_

#undef KRYPTOS_RIPEMD_K1_

#undef KRYPTOS_RIPEMD_K2_

#undef KRYPTOS_RIPEMD_K3_

#undef KRYPTOS_RIPEMD_K4_

#undef kryptos_ripemd_rol

#undef kryptos_ripemd160_line_proc

#undef kryptos_ripemd128_line_proc

#undef KRYPTOS_RIPEMD_BYTES_PER_BLOCK

#undef KRYPTOS_RIPEMD_LEN_BLOCK_OFFSET
