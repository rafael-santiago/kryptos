/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_md4.h>
#include <kryptos_hash_common.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_memory.h>
#include <kryptos_hex.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// INFO(Rafael): MD4 round functions. Maybe some of them could be simplified a little. If speed is a real critical
//               issue to your state of things.

#define kryptos_md4_F(x, y, z) ( ( (x) & (y) ) | ( (~(x)) & (z) ) )

#define kryptos_md4_G(x, y, z) ( ( (x) & (y) ) | ( (x) & (z) ) | ( (y) &  (z) ) )

#define kryptos_md4_H(x, y, z) ( (x) ^ (y)  ^ (z) )

// INFO(Rafael): Deltas for each round.

#define KRYPTOS_MD4DELTA0 0x00000000

#define KRYPTOS_MD4DELTA1 0x5A827999

#define KRYPTOS_MD4DELTA2 0x6ED9EBA1

// INFO(Rafael): General md4 macro stuff.

#define kryptos_md4_rotl(x, s) ( ( (x) << (s) ) | ( (x) >> (32 - (s)) ) )

#define kryptos_md4_step(a, b, c, d, f, x, delta, s) ( (a) = kryptos_md4_rotl(a + f(b, c, d) + x + delta, s) )

#define kryptos_md4_u32_rev(x) ( ((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8 ) | ( (x) << 24 ) )

#define KRYPTOS_MD4_LEN_BLOCK_OFFSET 56

#define KRYPTOS_MD4_BYTES_PER_BLOCK 64

#define KRYPTOS_MD4_HASH_SIZE 16

struct kryptos_md4_input_message {
    kryptos_u32_t block[16];
};

struct kryptos_md4_ctx {
    struct kryptos_md4_input_message input;
    kryptos_u32_t state[4];
    kryptos_u8_t *message;
    kryptos_u64_t curr_len, total_len;
    int paddin2times;
};

static size_t kryptos_md4_block_index_decision_table[KRYPTOS_MD4_BYTES_PER_BLOCK] = {
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

static void kryptos_md4_init(struct kryptos_md4_ctx *ctx);

static void kryptos_md4_do_block(struct kryptos_md4_ctx *ctx);

KRYPTOS_DECL_HASH_MESSAGE_PROCESSOR(md4, kryptos_md4_ctx, ctx)

KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR(md4, kryptos_md4_ctx, ctx,
                                    KRYPTOS_MD4_BYTES_PER_BLOCK,
                                    16, 32,
                                    kryptos_md4_init(ctx),
                                    kryptos_md4_do_block(ctx),
                                    kryptos_md4_block_index_decision_table)

KRYPTOS_IMPL_HASH_SIZE(md4, KRYPTOS_MD4_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(md4, KRYPTOS_MD4_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(md4, ktask, kryptos_md4_ctx, ctx, md4_hash_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3; // INFO(Rafael): Should be expressed in bits.
                            },
                            kryptos_md4_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(KRYPTOS_MD4_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_md4_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_MD4_HASH_SIZE;
                                kryptos_cpy_u32_as_big_endian(     (*ktask)->out, 16, kryptos_md4_u32_rev(ctx.state[0]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  4, 12, kryptos_md4_u32_rev(ctx.state[1]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  8,  8, kryptos_md4_u32_rev(ctx.state[2]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 12,  4, kryptos_md4_u32_rev(ctx.state[3]));
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_MD4_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_md4_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_MD4_HASH_SIZE << 1;
                                kryptos_u32_to_hex(     (*ktask)->out, 33, kryptos_md4_u32_rev(ctx.state[0]));
                                kryptos_u32_to_hex((*ktask)->out +  8, 25, kryptos_md4_u32_rev(ctx.state[1]));
                                kryptos_u32_to_hex((*ktask)->out + 16, 17, kryptos_md4_u32_rev(ctx.state[2]));
                                kryptos_u32_to_hex((*ktask)->out + 24,  9, kryptos_md4_u32_rev(ctx.state[3]));
                            })


static void kryptos_md4_init(struct kryptos_md4_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->paddin2times = 0;
}

static void kryptos_md4_do_block(struct kryptos_md4_ctx *ctx) {
    kryptos_u32_t AA, BB, CC, DD;

    if (ctx->curr_len < KRYPTOS_MD4_BYTES_PER_BLOCK) {
        kryptos_hash_apply_pad_on_u32_block(ctx->input.block, 16,
                                            kryptos_md4_block_index_decision_table,
                                            ctx->curr_len, ctx->total_len,
                                            &ctx->paddin2times, 0x80,
                                            KRYPTOS_MD4_LEN_BLOCK_OFFSET);
        if (!ctx->paddin2times) {
            AA = ctx->input.block[14];
            // INFO(Rafael): This is pretty damn crazy. Errr.. Sorry!
            //               I will save your sanity from any explanation. 8S
            ctx->input.block[14] = kryptos_md4_u32_rev(ctx->input.block[15]);
            ctx->input.block[15] = kryptos_md4_u32_rev(AA);
        }
    }

    AA = ctx->state[0];
    BB = ctx->state[1];
    CC = ctx->state[2];
    DD = ctx->state[3];

    ctx->input.block[ 0] = kryptos_md4_u32_rev(ctx->input.block[ 0]);
    ctx->input.block[ 1] = kryptos_md4_u32_rev(ctx->input.block[ 1]);
    ctx->input.block[ 2] = kryptos_md4_u32_rev(ctx->input.block[ 2]);
    ctx->input.block[ 3] = kryptos_md4_u32_rev(ctx->input.block[ 3]);
    ctx->input.block[ 4] = kryptos_md4_u32_rev(ctx->input.block[ 4]);
    ctx->input.block[ 5] = kryptos_md4_u32_rev(ctx->input.block[ 5]);
    ctx->input.block[ 6] = kryptos_md4_u32_rev(ctx->input.block[ 6]);
    ctx->input.block[ 7] = kryptos_md4_u32_rev(ctx->input.block[ 7]);
    ctx->input.block[ 8] = kryptos_md4_u32_rev(ctx->input.block[ 8]);
    ctx->input.block[ 9] = kryptos_md4_u32_rev(ctx->input.block[ 9]);
    ctx->input.block[10] = kryptos_md4_u32_rev(ctx->input.block[10]);
    ctx->input.block[11] = kryptos_md4_u32_rev(ctx->input.block[11]);
    ctx->input.block[12] = kryptos_md4_u32_rev(ctx->input.block[12]);
    ctx->input.block[13] = kryptos_md4_u32_rev(ctx->input.block[13]);
    ctx->input.block[14] = kryptos_md4_u32_rev(ctx->input.block[14]);
    ctx->input.block[15] = kryptos_md4_u32_rev(ctx->input.block[15]);

    // INFO(Rafael): The following is only about the main block processing loop
    //               "unrolled" as three main "acts", ugly but fast.
    //               There is no secret.

    // INFO(Rafael): Step one.
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_F, ctx->input.block[ 0], KRYPTOS_MD4DELTA0,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_F, ctx->input.block[ 1], KRYPTOS_MD4DELTA0,  7);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_F, ctx->input.block[ 2], KRYPTOS_MD4DELTA0, 11);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_F, ctx->input.block[ 3], KRYPTOS_MD4DELTA0, 19);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_F, ctx->input.block[ 4], KRYPTOS_MD4DELTA0,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_F, ctx->input.block[ 5], KRYPTOS_MD4DELTA0,  7);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_F, ctx->input.block[ 6], KRYPTOS_MD4DELTA0, 11);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_F, ctx->input.block[ 7], KRYPTOS_MD4DELTA0, 19);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_F, ctx->input.block[ 8], KRYPTOS_MD4DELTA0,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_F, ctx->input.block[ 9], KRYPTOS_MD4DELTA0,  7);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_F, ctx->input.block[10], KRYPTOS_MD4DELTA0, 11);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_F, ctx->input.block[11], KRYPTOS_MD4DELTA0, 19);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_F, ctx->input.block[12], KRYPTOS_MD4DELTA0,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_F, ctx->input.block[13], KRYPTOS_MD4DELTA0,  7);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_F, ctx->input.block[14], KRYPTOS_MD4DELTA0, 11);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_F, ctx->input.block[15], KRYPTOS_MD4DELTA0, 19);

    // INFO(Rafael): Step two.
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_G, ctx->input.block[ 0], KRYPTOS_MD4DELTA1,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_G, ctx->input.block[ 4], KRYPTOS_MD4DELTA1,  5);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_G, ctx->input.block[ 8], KRYPTOS_MD4DELTA1,  9);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_G, ctx->input.block[12], KRYPTOS_MD4DELTA1, 13);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_G, ctx->input.block[ 1], KRYPTOS_MD4DELTA1,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_G, ctx->input.block[ 5], KRYPTOS_MD4DELTA1,  5);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_G, ctx->input.block[ 9], KRYPTOS_MD4DELTA1,  9);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_G, ctx->input.block[13], KRYPTOS_MD4DELTA1, 13);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_G, ctx->input.block[ 2], KRYPTOS_MD4DELTA1,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_G, ctx->input.block[ 6], KRYPTOS_MD4DELTA1,  5);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_G, ctx->input.block[10], KRYPTOS_MD4DELTA1,  9);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_G, ctx->input.block[14], KRYPTOS_MD4DELTA1, 13);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_G, ctx->input.block[ 3], KRYPTOS_MD4DELTA1,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_G, ctx->input.block[ 7], KRYPTOS_MD4DELTA1,  5);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_G, ctx->input.block[11], KRYPTOS_MD4DELTA1,  9);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_G, ctx->input.block[15], KRYPTOS_MD4DELTA1, 13);

    // INFO(Rafael): Step three.
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_H, ctx->input.block[ 0], KRYPTOS_MD4DELTA2,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_H, ctx->input.block[ 8], KRYPTOS_MD4DELTA2,  9);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_H, ctx->input.block[ 4], KRYPTOS_MD4DELTA2, 11);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_H, ctx->input.block[12], KRYPTOS_MD4DELTA2, 15);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_H, ctx->input.block[ 2], KRYPTOS_MD4DELTA2,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_H, ctx->input.block[10], KRYPTOS_MD4DELTA2,  9);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_H, ctx->input.block[ 6], KRYPTOS_MD4DELTA2, 11);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_H, ctx->input.block[14], KRYPTOS_MD4DELTA2, 15);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_H, ctx->input.block[ 1], KRYPTOS_MD4DELTA2,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_H, ctx->input.block[ 9], KRYPTOS_MD4DELTA2,  9);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_H, ctx->input.block[ 5], KRYPTOS_MD4DELTA2, 11);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_H, ctx->input.block[13], KRYPTOS_MD4DELTA2, 15);
    kryptos_md4_step(AA, BB, CC, DD, kryptos_md4_H, ctx->input.block[ 3], KRYPTOS_MD4DELTA2,  3);
    kryptos_md4_step(DD, AA, BB, CC, kryptos_md4_H, ctx->input.block[11], KRYPTOS_MD4DELTA2,  9);
    kryptos_md4_step(CC, DD, AA, BB, kryptos_md4_H, ctx->input.block[ 7], KRYPTOS_MD4DELTA2, 11);
    kryptos_md4_step(BB, CC, DD, AA, kryptos_md4_H, ctx->input.block[15], KRYPTOS_MD4DELTA2, 15);

    ctx->state[0] += AA;
    ctx->state[1] += BB;
    ctx->state[2] += CC;
    ctx->state[3] += DD;

    AA = BB = CC = DD = 0;

    if (ctx->paddin2times) {
        kryptos_hash_ld_u8buf_as_u32_blocks((kryptos_u8_t *)"", 0, ctx->input.block, 16,
                                            kryptos_md4_block_index_decision_table);
        kryptos_md4_do_block(ctx);
    }
}

#undef kryptos_md4_F

#undef kryptos_md4_G

#undef kryptos_md4_H

#undef KRYPTOS_MD4DELTA0

#undef KRYPTOS_MD4DELTA1

#undef KRYPTOS_MD4DELTA2

#undef kryptos_md4_rotl

#undef kryptos_md4_step

#undef kryptos_md4_u32_rev

#undef KRYPTOS_MD4_LEN_BLOCK_OFFSET

#undef KRYPTOS_MD4_BYTES_PER_BLOCK
