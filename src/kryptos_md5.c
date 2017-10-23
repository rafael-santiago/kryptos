/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_md5.h>
#include <kryptos_hash_common.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_memory.h>
#include <kryptos_hex.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// INFO(Rafael): Round functions.

#define kryptos_md5_F(x, y, z) ( ( (x) & (y) ) | ( (~(x)) & (z) ) )

#define kryptos_md5_G(x, y, z) ( ( (x) & (z) ) | ( (y) & (~(z)) ) )

#define kryptos_md5_H(x, y, z) ( (x) ^ (y)  ^ (z) )

#define kryptos_md5_I(x, y, z) ( (y) ^ ( (x) | (~(z)) ) )

#define kryptos_md5_ROTL(x, s) ( ( (x) << (s) ) | ( (x) >> (32 - (s)) ) )

#define kryptos_md5_u32_rev(x) ( ((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24) )

#define kryptos_md5_step(a, b, c, d, f, x, t, s) ( (a) = (b) + kryptos_md5_ROTL(a + f(b, c, d) + x + t, s) )

#define KRYPTOS_MD5_BYTES_PER_BLOCK 64

#define KRYPTOS_MD5_LEN_BLOCK_OFFSET 56 // INFO(Rafael): BYTES_PER_BLOCK - 8...

#define KRYPTOS_MD5_HASH_SIZE 16

struct kryptos_md5_input_message {
    kryptos_u32_t block[16];
};

struct kryptos_md5_ctx {
    struct kryptos_md5_input_message input;
    kryptos_u32_t state[4];
    kryptos_u8_t *message;
    kryptos_u64_t total_len, curr_len;
    int paddin2times;
};

static size_t kryptos_md5_block_index_decision_table[64] = {
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

static void kryptos_md5_init(struct kryptos_md5_ctx *ctx);

static void kryptos_md5_do_block(struct kryptos_md5_ctx *ctx);

KRYPTOS_DECL_HASH_MESSAGE_PROCESSOR(md5, kryptos_md5_ctx, ctx);

KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR(md5, kryptos_md5_ctx, ctx, KRYPTOS_MD5_BYTES_PER_BLOCK, 16, 32,
                                    kryptos_md5_init(ctx), kryptos_md5_do_block(ctx), kryptos_md5_block_index_decision_table)

KRYPTOS_IMPL_HASH_SIZE(md5, KRYPTOS_MD5_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(md5, KRYPTOS_MD5_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(md5, ktask, kryptos_md5_ctx, ctx, md5_hash_epilogue,
                            {
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3;
                            },
                            kryptos_md5_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(KRYPTOS_MD5_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_md5_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_MD5_HASH_SIZE;
                                kryptos_cpy_u32_as_big_endian(     (*ktask)->out, 16, kryptos_md5_u32_rev(ctx.state[0]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  4, 12, kryptos_md5_u32_rev(ctx.state[1]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  8,  8, kryptos_md5_u32_rev(ctx.state[2]));
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 12,  4, kryptos_md5_u32_rev(ctx.state[3]));
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_MD5_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_md5_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_MD5_HASH_SIZE << 1;
                                kryptos_u32_to_hex(     (*ktask)->out, 33, kryptos_md5_u32_rev(ctx.state[0]));
                                kryptos_u32_to_hex((*ktask)->out +  8, 25, kryptos_md5_u32_rev(ctx.state[1]));
                                kryptos_u32_to_hex((*ktask)->out + 16, 17, kryptos_md5_u32_rev(ctx.state[2]));
                                kryptos_u32_to_hex((*ktask)->out + 24,  9, kryptos_md5_u32_rev(ctx.state[3]));
                            })

static void kryptos_md5_init(struct kryptos_md5_ctx *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->paddin2times = 0;
}

static void kryptos_md5_do_block(struct kryptos_md5_ctx *ctx) {
    kryptos_u32_t AA, BB, CC, DD;

    if (ctx->curr_len < KRYPTOS_MD5_BYTES_PER_BLOCK) {
        kryptos_hash_apply_pad_on_u32_block(ctx->input.block, 16,
                                            kryptos_md5_block_index_decision_table,
                                            ctx->curr_len, ctx->total_len, &ctx->paddin2times,
                                            KRYPTOS_MD5_LEN_BLOCK_OFFSET);
        if (!ctx->paddin2times) {
            AA = ctx->input.block[14];
            ctx->input.block[14] = kryptos_md5_u32_rev(ctx->input.block[15]);
            ctx->input.block[15] = kryptos_md5_u32_rev(AA);
        }
    }

    AA = ctx->state[0];
    BB = ctx->state[1];
    CC = ctx->state[2];
    DD = ctx->state[3];

    ctx->input.block[ 0] = kryptos_md5_u32_rev(ctx->input.block[ 0]);
    ctx->input.block[ 1] = kryptos_md5_u32_rev(ctx->input.block[ 1]);
    ctx->input.block[ 2] = kryptos_md5_u32_rev(ctx->input.block[ 2]);
    ctx->input.block[ 3] = kryptos_md5_u32_rev(ctx->input.block[ 3]);
    ctx->input.block[ 4] = kryptos_md5_u32_rev(ctx->input.block[ 4]);
    ctx->input.block[ 5] = kryptos_md5_u32_rev(ctx->input.block[ 5]);
    ctx->input.block[ 6] = kryptos_md5_u32_rev(ctx->input.block[ 6]);
    ctx->input.block[ 7] = kryptos_md5_u32_rev(ctx->input.block[ 7]);
    ctx->input.block[ 8] = kryptos_md5_u32_rev(ctx->input.block[ 8]);
    ctx->input.block[ 9] = kryptos_md5_u32_rev(ctx->input.block[ 9]);
    ctx->input.block[10] = kryptos_md5_u32_rev(ctx->input.block[10]);
    ctx->input.block[11] = kryptos_md5_u32_rev(ctx->input.block[11]);
    ctx->input.block[12] = kryptos_md5_u32_rev(ctx->input.block[12]);
    ctx->input.block[13] = kryptos_md5_u32_rev(ctx->input.block[13]);
    ctx->input.block[14] = kryptos_md5_u32_rev(ctx->input.block[14]);
    ctx->input.block[15] = kryptos_md5_u32_rev(ctx->input.block[15]);

    // INFO(Rafael): Step 1.
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_F, ctx->input.block[ 0], 0xD76AA478,  7);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_F, ctx->input.block[ 1], 0xE8C7B756, 12);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_F, ctx->input.block[ 2], 0x242070DB, 17);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_F, ctx->input.block[ 3], 0xC1BDCEEE, 22);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_F, ctx->input.block[ 4], 0xF57C0FAF,  7);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_F, ctx->input.block[ 5], 0x4787C62A, 12);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_F, ctx->input.block[ 6], 0xA8304613, 17);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_F, ctx->input.block[ 7], 0xFD469501, 22);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_F, ctx->input.block[ 8], 0x698098d8, 7);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_F, ctx->input.block[ 9], 0x8B44F7AF, 12);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_F, ctx->input.block[10], 0xFFFF5BB1, 17);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_F, ctx->input.block[11], 0x895CD7BE, 22);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_F, ctx->input.block[12], 0x6B901122, 7);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_F, ctx->input.block[13], 0xFD987193, 12);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_F, ctx->input.block[14], 0xA679438E, 17);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_F, ctx->input.block[15], 0x49B40821, 22);

    // INFO(Rafael): Step 2.
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_G, ctx->input.block[ 1], 0xF61E2562,  5);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_G, ctx->input.block[ 6], 0xC040B340,  9);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_G, ctx->input.block[11], 0x265E5A51, 14);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_G, ctx->input.block[ 0], 0xE9B6C7AA, 20);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_G, ctx->input.block[ 5], 0xD62F105D,  5);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_G, ctx->input.block[10], 0x02441453,  9);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_G, ctx->input.block[15], 0xD8A1E681, 14);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_G, ctx->input.block[ 4], 0xE7D3FBC8, 20);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_G, ctx->input.block[ 9], 0x21E1CDE6,  5);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_G, ctx->input.block[14], 0xC33707D6,  9);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_G, ctx->input.block[ 3], 0xF4D50D87, 14);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_G, ctx->input.block[ 8], 0x455A14ED, 20);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_G, ctx->input.block[13], 0xA9E3E905,  5);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_G, ctx->input.block[ 2], 0xFCEFA3f8,  9);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_G, ctx->input.block[ 7], 0x676F02D9, 14);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_G, ctx->input.block[12], 0x8D2A4C8A, 20);

    // INFO(Rafael): Step 3.
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_H, ctx->input.block[ 5], 0xFFFA3942,  4);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_H, ctx->input.block[ 8], 0x8771F681, 11);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_H, ctx->input.block[11], 0x6D9D6122, 16);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_H, ctx->input.block[14], 0xFDE5380C, 23);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_H, ctx->input.block[ 1], 0xA4BEEA44,  4);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_H, ctx->input.block[ 4], 0x4BDECFA9, 11);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_H, ctx->input.block[ 7], 0xF6BB4B60, 16);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_H, ctx->input.block[10], 0xBEBFBC70, 23);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_H, ctx->input.block[13], 0x289B7EC6,  4);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_H, ctx->input.block[ 0], 0xEAA127FA, 11);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_H, ctx->input.block[ 3], 0xD4EF3085, 16);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_H, ctx->input.block[ 6], 0x04881D05, 23);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_H, ctx->input.block[ 9], 0xD9D4D039,  4);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_H, ctx->input.block[12], 0xE6DB99E5, 11);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_H, ctx->input.block[15], 0x1FA27CF8, 16);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_H, ctx->input.block[ 2], 0xC4AC5665, 23);

    // INFO(Rafael): Step 4.
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_I, ctx->input.block[ 0], 0xF4292244,  6);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_I, ctx->input.block[ 7], 0x432AFF97, 10);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_I, ctx->input.block[14], 0xAB9423A7, 15);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_I, ctx->input.block[ 5], 0xFC93A039, 21);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_I, ctx->input.block[12], 0x655B59C3,  6);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_I, ctx->input.block[ 3], 0x8F0CCC92, 10);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_I, ctx->input.block[10], 0xFFEFF47D, 15);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_I, ctx->input.block[ 1], 0x85845DD1, 21);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_I, ctx->input.block[ 8], 0x6FA87E4F,  6);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_I, ctx->input.block[15], 0xFE2CE6E0, 10);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_I, ctx->input.block[ 6], 0xA3014314, 15);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_I, ctx->input.block[13], 0x4E0811A1, 21);
    kryptos_md5_step(AA, BB, CC, DD, kryptos_md5_I, ctx->input.block[ 4], 0xF7537E82,  6);
    kryptos_md5_step(DD, AA, BB, CC, kryptos_md5_I, ctx->input.block[11], 0xBD3AF235, 10);
    kryptos_md5_step(CC, DD, AA, BB, kryptos_md5_I, ctx->input.block[ 2], 0x2AD7D2BB, 15);
    kryptos_md5_step(BB, CC, DD, AA, kryptos_md5_I, ctx->input.block[ 9], 0xEB86D391, 21);

    ctx->state[0] += AA;
    ctx->state[1] += BB;
    ctx->state[2] += CC;
    ctx->state[3] += DD;

    AA = BB = CC = DD = 0;

    if (ctx->paddin2times) {
        kryptos_hash_ld_u8buf_as_u32_blocks((kryptos_u8_t *)"", 0, ctx->input.block, 16,
                                            kryptos_md5_block_index_decision_table);
        kryptos_md5_do_block(ctx);
    }
}

#undef kryptos_md5_F

#undef kryptos_md5_G

#undef kryptos_md5_H

#undef kryptos_md5_I

#undef kryptos_md5_ROTL

#undef kryptos_md5_u32_rev

#undef kryptos_md5_step

#undef KRYPTOS_MD5_BYTES_PER_BLOCK

#undef KRYPTOS_MD5_LEN_BLOCK_OFFSET
