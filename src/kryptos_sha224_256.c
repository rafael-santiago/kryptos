/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_sha224_256.h>
#include <kryptos_hash_common.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_memory.h>
#include <kryptos_hex.h>
#include <string.h>

#define kryptos_sha224_256_CH(x, y, z) ( ( (x) & (y) ) ^ ( (~(x)) & (z) ) )

#define kryptos_sha224_256_MAJ(x, y, z) ( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) )

#define kryptos_sha224_256_ROTR(x, lv) ( ( (x) >> (lv) ) | ( (x) << ( (sizeof(x) << 3) - (lv) ) ) )

#define kryptos_sha224_256_BSIG0(x) ( kryptos_sha224_256_ROTR(x,  2) ^\
                                      kryptos_sha224_256_ROTR(x, 13) ^\
                                      kryptos_sha224_256_ROTR(x, 22) )

#define kryptos_sha224_256_BSIG1(x) ( kryptos_sha224_256_ROTR(x,  6) ^\
                                      kryptos_sha224_256_ROTR(x, 11) ^\
                                      kryptos_sha224_256_ROTR(x, 25) )

#define kryptos_sha224_256_SSIG0(x) ( kryptos_sha224_256_ROTR(x,  7) ^\
                                      kryptos_sha224_256_ROTR(x, 18) ^\
                                      ( (x) >> 3 ) )

#define kryptos_sha224_256_SSIG1(x) ( kryptos_sha224_256_ROTR(x, 17) ^\
                                      kryptos_sha224_256_ROTR(x, 19) ^\
                                      ( (x) >> 10 ) )

#define KRYPTOS_SHA224_256_LEN_BLOCK_OFFSET 56

static kryptos_u32_t kryptos_sha224_256_K[] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25b, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

// INFO(Rafael): These structs and enums could be shared into something like "kryptos_sha_common.h", however my main intention
//               in this library is to make the things (i.e. the algorithms) more self-contained.
//               Also bad changes will screw up less ;)

typedef enum {
    k224Bits = 0,
    k256Bits,
    kBitsNr
}kryptos_sha224_256_bitsize_t;

struct kryptos_sha224_256_input_message {
    kryptos_u32_t block[16];
};

struct kryptos_sha224_256_ctx {
    kryptos_u32_t state[8];
    struct kryptos_sha224_256_input_message input;
    kryptos_u8_t *message;
    kryptos_u64_t curr_len;
    kryptos_u64_t total_len;
    int paddin2times;
    kryptos_sha224_256_bitsize_t bitsize;
};

static void kryptos_sha224_init(struct kryptos_sha224_256_ctx *ctx);

static void kryptos_sha256_init(struct kryptos_sha224_256_ctx *ctx);

static void kryptos_sha224_256_do_block(struct kryptos_sha224_256_ctx *ctx);

static void kryptos_sha224_256_process_message(struct kryptos_sha224_256_ctx *ctx);

typedef void (*kryptos_sha224_256_init_func)(struct kryptos_sha224_256_ctx *ctx);

static kryptos_sha224_256_init_func kryptos_sha224_256_init[kBitsNr] = {
    kryptos_sha224_init, kryptos_sha256_init
};

static size_t kryptos_sha224_256_block_index_decision_table[64] = {
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

KRYPTOS_IMPL_HASH_PROCESSOR(sha224, ktask, kryptos_sha224_256_ctx, ctx, sha224_hash_epilogue,
                            {
                                ctx.bitsize = k224Bits; // INFO(Rafael): Let's request a 224-bit output.
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3; // INFO(Rafael): The length should be always in bits.
                            },
                            kryptos_sha224_256_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(28);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha224_hash_epilogue;
                                }
                                (*ktask)->out_size = 28;
                                kryptos_cpy_u32_as_big_endian(     (*ktask)->out, 28, ctx.state[0]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  4, 24, ctx.state[1]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  8, 20, ctx.state[2]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 12, 16, ctx.state[3]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 16, 12, ctx.state[4]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 20,  8, ctx.state[5]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 24,  4, ctx.state[6]);
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(57);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha224_hash_epilogue;
                                }
                                (*ktask)->out_size = 56;
                                kryptos_u32_to_hex(     (*ktask)->out, 57, ctx.state[0]);
                                kryptos_u32_to_hex((*ktask)->out +  8, 49, ctx.state[1]);
                                kryptos_u32_to_hex((*ktask)->out + 16, 41, ctx.state[2]);
                                kryptos_u32_to_hex((*ktask)->out + 24, 33, ctx.state[3]);
                                kryptos_u32_to_hex((*ktask)->out + 32, 25, ctx.state[4]);
                                kryptos_u32_to_hex((*ktask)->out + 40, 17, ctx.state[5]);
                                kryptos_u32_to_hex((*ktask)->out + 48,  9, ctx.state[6]);
                            })

KRYPTOS_IMPL_HASH_PROCESSOR(sha256, ktask, kryptos_sha224_256_ctx, ctx, sha256_hash_epilogue,
                            {
                                ctx.bitsize = k256Bits; // INFO(Rafael): Let's request a 256-bit output.
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3; // INFO(Rafael): The length should be always in bits.
                            },
                            kryptos_sha224_256_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(32);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha256_hash_epilogue;
                                }
                                (*ktask)->out_size = 32;
                                kryptos_cpy_u32_as_big_endian(     (*ktask)->out, 32, ctx.state[0]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  4, 28, ctx.state[1]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out +  8, 24, ctx.state[2]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 12, 20, ctx.state[3]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 16, 16, ctx.state[4]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 20, 12, ctx.state[5]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 24,  8, ctx.state[6]);
                                kryptos_cpy_u32_as_big_endian((*ktask)->out + 28,  4, ctx.state[7]);
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(65);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha256_hash_epilogue;
                                }
                                (*ktask)->out_size = 64;
                                kryptos_u32_to_hex(     (*ktask)->out, 65, ctx.state[0]);
                                kryptos_u32_to_hex((*ktask)->out +  8, 57, ctx.state[1]);
                                kryptos_u32_to_hex((*ktask)->out + 16, 49, ctx.state[2]);
                                kryptos_u32_to_hex((*ktask)->out + 24, 41, ctx.state[3]);
                                kryptos_u32_to_hex((*ktask)->out + 32, 33, ctx.state[4]);
                                kryptos_u32_to_hex((*ktask)->out + 40, 25, ctx.state[5]);
                                kryptos_u32_to_hex((*ktask)->out + 48, 17, ctx.state[6]);
                                kryptos_u32_to_hex((*ktask)->out + 56,  9, ctx.state[7]);
                            })

static void kryptos_sha224_init(struct kryptos_sha224_256_ctx *ctx) {
    ctx->state[0] = 0xC1059ED8;
    ctx->state[1] = 0x367CD507;
    ctx->state[2] = 0x3070DD17;
    ctx->state[3] = 0xF70E5939;
    ctx->state[4] = 0xFFC00B31;
    ctx->state[5] = 0x68581511;
    ctx->state[6] = 0x64F98FA7;
    ctx->state[7] = 0xBEFA4FA4;
    ctx->paddin2times = 0;
}

static void kryptos_sha256_init(struct kryptos_sha224_256_ctx *ctx) {
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
    ctx->paddin2times = 0;
}

static void kryptos_sha224_256_do_block(struct kryptos_sha224_256_ctx *ctx) {
    kryptos_u32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    size_t t;

    if (ctx->curr_len < 64) {
        kryptos_hash_apply_pad_on_u32_block(ctx->input.block, 16,
                                            kryptos_sha224_256_block_index_decision_table,
                                            ctx->curr_len, ctx->total_len, &ctx->paddin2times,
                                            KRYPTOS_SHA224_256_LEN_BLOCK_OFFSET);
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

    for (t = 16; t < 64; t++) {
        W[t] = kryptos_sha224_256_SSIG1(W[t -  2]) + W[t -  7] +
               kryptos_sha224_256_SSIG0(W[t - 15]) + W[t - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (t = 0; t < 64; t++) {
        T1 = h + kryptos_sha224_256_BSIG1(e) + kryptos_sha224_256_CH(e, f, g) + kryptos_sha224_256_K[t] + W[t];
        T2 = kryptos_sha224_256_BSIG0(a) + kryptos_sha224_256_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    T1 = T2 = a = b = c = d = e = f = g = h = 0;
    memset(W, 0, sizeof(W));
    t = 0;

    if (ctx->paddin2times) {
        kryptos_hash_ld_u8buf_as_u32_blocks("", 0,
                                            ctx->input.block, 16,
                                            kryptos_sha224_256_block_index_decision_table);
        kryptos_sha224_256_do_block(ctx);
    }
}

static void kryptos_sha224_256_process_message(struct kryptos_sha224_256_ctx *ctx) {
    kryptos_u32_t i, l = ctx->total_len >> 3;
    kryptos_u8_t buffer[65];

    // INFO(Rafael): Actually this the only difference between sha-224 and sha-256
    //               besides the length of the output, of course.
    kryptos_sha224_256_init[ctx->bitsize](ctx);

    ctx->curr_len = 0;

    if (l > 0) {
        memset(buffer, 0, sizeof(buffer));
        for (i = 0; i <= l; i++) {
            if (ctx->curr_len < 64 && i != l) {
                buffer[ctx->curr_len++] = ctx->message[i];
            } else {
                kryptos_hash_ld_u8buf_as_u32_blocks(buffer, ctx->curr_len,
                                                    ctx->input.block, 16,
                                                    kryptos_sha224_256_block_index_decision_table);
                kryptos_sha224_256_do_block(ctx);
                ctx->curr_len = 0;
                memset(buffer, 0, sizeof(buffer));
                if (i != l) {
                    buffer[ctx->curr_len++] = ctx->message[i];
                }
            }
        }
        i = l = 0;
    } else {
        kryptos_hash_ld_u8buf_as_u32_blocks("", 0,
                                            ctx->input.block, 16,
                                            kryptos_sha224_256_block_index_decision_table);
        kryptos_sha224_256_do_block(ctx);
    }
}

#undef kryptos_sha224_256_CH

#undef kryptos_sha224_256_MAJ

#undef kryptos_sha224_256_ROTR

#undef kryptos_sha224_256_BSIG0

#undef kryptos_sha224_256_BSIG1

#undef kryptos_sha224_256_SSIG0

#undef kryptos_sha224_256_SSIG1

#undef KRYPTOS_SHA224_256_LEN_BLOCK_OFFSET
