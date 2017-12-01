/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_sha384_512.h>
#include <kryptos_hash_common.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_hex.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define kryptos_sha384_512_CH(x, y, z) ( ( (x) & (y) ) ^ ( (~(x)) & (z) ) )

#define kryptos_sha384_512_MAJ(x, y, z) ( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) )

#define kryptos_sha384_512_ROTR(x, l) ( ( (x) >> (l) ) | ( (x) << ( (sizeof(x) << 3) - (l) ) ) )

#define kryptos_sha384_512_BSIG0(x) ( kryptos_sha384_512_ROTR(x, 28) ^\
                                      kryptos_sha384_512_ROTR(x, 34) ^\
                                      kryptos_sha384_512_ROTR(x, 39) )

#define kryptos_sha384_512_BSIG1(x) ( kryptos_sha384_512_ROTR(x, 14) ^\
                                      kryptos_sha384_512_ROTR(x, 18) ^\
                                      kryptos_sha384_512_ROTR(x, 41) )

#define kryptos_sha384_512_SSIG0(x) ( kryptos_sha384_512_ROTR(x, 1) ^\
                                      kryptos_sha384_512_ROTR(x, 8) ^\
                                      ( (x) >> 7 ) )

#define kryptos_sha384_512_SSIG1(x) ( kryptos_sha384_512_ROTR(x, 19) ^\
                                      kryptos_sha384_512_ROTR(x, 61) ^\
                                      ( (x) >> 6 ) )

#define KRYPTOS_SHA384_512_BYTES_PER_BLOCK 128

#define KRYPTOS_SHA384_512_LEN_BLOCK_OFFSET 120

#define KRYPTOS_SHA384_HASH_SIZE 48

#define KRYPTOS_SHA512_HASH_SIZE 64

static kryptos_u64_t kryptos_sha384_512_K[80] = {
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};

typedef enum {
    k384Bits = 0,
    k512Bits,
    kBitsNr
}kryptos_sha384_512_bitsize_t;

struct kryptos_sha384_512_input_message {
    kryptos_u64_t block[16];
};

struct kryptos_sha384_512_ctx {
    kryptos_u64_t state[8];
    struct kryptos_sha384_512_input_message input;
    kryptos_u8_t *message;
    kryptos_u64_t curr_len, total_len;
    int paddin2times;
    kryptos_sha384_512_bitsize_t bitsize;
};

static void kryptos_sha384_init(struct kryptos_sha384_512_ctx *ctx);

static void kryptos_sha512_init(struct kryptos_sha384_512_ctx *ctx);

static void kryptos_sha384_512_do_block(struct kryptos_sha384_512_ctx *ctx);

typedef void (*kryptos_sha384_512_init_func)(struct kryptos_sha384_512_ctx *ctx);

static kryptos_sha384_512_init_func kryptos_sha384_512_init[kBitsNr] = {
    kryptos_sha384_init, kryptos_sha512_init
};

static size_t kryptos_sha384_512_block_index_decision_table[KRYPTOS_SHA384_512_BYTES_PER_BLOCK] = {
     0,  0,  0,  0,  0,  0,  0,  0,
     1,  1,  1,  1,  1,  1,  1,  1,
     2,  2,  2,  2,  2,  2,  2,  2,
     3,  3,  3,  3,  3,  3,  3,  3,
     4,  4,  4,  4,  4,  4,  4,  4,
     5,  5,  5,  5,  5,  5,  5,  5,
     6,  6,  6,  6,  6,  6,  6,  6,
     7,  7,  7,  7,  7,  7,  7,  7,
     8,  8,  8,  8,  8,  8,  8,  8,
     9,  9,  9,  9,  9,  9,  9,  9,
    10, 10, 10, 10, 10, 10, 10, 10,
    11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12,
    13, 13, 13, 13, 13, 13, 13, 13,
    14, 14, 14, 14, 14, 14, 14, 14,
    15, 15, 15, 15, 15, 15, 15, 15
};

KRYPTOS_DECL_HASH_MESSAGE_PROCESSOR(sha384_512, kryptos_sha384_512_ctx, ctx)

KRYPTOS_IMPL_HASH_MESSAGE_PROCESSOR(sha384_512, kryptos_sha384_512_ctx, ctx,
                                    KRYPTOS_SHA384_512_BYTES_PER_BLOCK,
                                    16, 64,
                                    kryptos_sha384_512_init[ctx->bitsize](ctx),
                                    kryptos_sha384_512_do_block(ctx),
                                    kryptos_sha384_512_block_index_decision_table)

KRYPTOS_IMPL_HASH_SIZE(sha384, KRYPTOS_SHA384_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(sha384, KRYPTOS_SHA384_512_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(sha384, ktask, kryptos_sha384_512_ctx, ctx, sha384_hash_epilogue,
                            {
                                ctx.bitsize = k384Bits; // INFO(Rafael): Let's request a 384-bit output.
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3; // INFO(Rafael): The length should be always in bits.
                            },
                            kryptos_sha384_512_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(KRYPTOS_SHA384_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha384_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA384_HASH_SIZE;
                                kryptos_cpy_u64_as_big_endian(     (*ktask)->out, 48, ctx.state[0]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out +  8, 40, ctx.state[1]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 16, 32, ctx.state[2]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 24, 24, ctx.state[3]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 32, 16, ctx.state[4]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 40,  8, ctx.state[5]);
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_SHA384_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha384_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA384_HASH_SIZE << 1;
                                kryptos_u64_to_hex(     (*ktask)->out, 97, ctx.state[0]);
                                kryptos_u64_to_hex((*ktask)->out + 16, 81, ctx.state[1]);
                                kryptos_u64_to_hex((*ktask)->out + 32, 65, ctx.state[2]);
                                kryptos_u64_to_hex((*ktask)->out + 48, 49, ctx.state[3]);
                                kryptos_u64_to_hex((*ktask)->out + 64, 33, ctx.state[4]);
                                kryptos_u64_to_hex((*ktask)->out + 80, 17, ctx.state[5]);
                            })

KRYPTOS_IMPL_HASH_SIZE(sha512, KRYPTOS_SHA512_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(sha512, KRYPTOS_SHA384_512_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(sha512, ktask, kryptos_sha384_512_ctx, ctx, sha512_hash_epilogue,
                            {
                                ctx.bitsize = k512Bits; // INFO(Rafael): Let's request a 512-bit output.
                                ctx.message = (*ktask)->in;
                                ctx.total_len = (*ktask)->in_size << 3; // INFO(Rafael): The length should be always in bits.
                            },
                            kryptos_sha384_512_process_message(&ctx),
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg(KRYPTOS_SHA512_HASH_SIZE);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha512_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA512_HASH_SIZE;
                                kryptos_cpy_u64_as_big_endian(     (*ktask)->out, 64, ctx.state[0]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out +  8, 56, ctx.state[1]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 16, 48, ctx.state[2]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 24, 40, ctx.state[3]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 32, 32, ctx.state[4]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 40, 24, ctx.state[5]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 48, 16, ctx.state[6]);
                                kryptos_cpy_u64_as_big_endian((*ktask)->out + 56,  8, ctx.state[7]);
                            },
                            {
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((KRYPTOS_SHA512_HASH_SIZE << 1) + 1);
                                if ((*ktask)->out == NULL) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_sha512_hash_epilogue;
                                }
                                (*ktask)->out_size = KRYPTOS_SHA512_HASH_SIZE << 1;
                                kryptos_u64_to_hex(      (*ktask)->out, 129, ctx.state[0]);
                                kryptos_u64_to_hex((*ktask)->out +  16, 113, ctx.state[1]);
                                kryptos_u64_to_hex((*ktask)->out +  32,  97, ctx.state[2]);
                                kryptos_u64_to_hex((*ktask)->out +  48,  81, ctx.state[3]);
                                kryptos_u64_to_hex((*ktask)->out +  64,  65, ctx.state[4]);
                                kryptos_u64_to_hex((*ktask)->out +  80,  49, ctx.state[5]);
                                kryptos_u64_to_hex((*ktask)->out +  96,  33, ctx.state[6]);
                                kryptos_u64_to_hex((*ktask)->out + 112,  17, ctx.state[7]);
                            })

static void kryptos_sha384_init(struct kryptos_sha384_512_ctx *ctx) {
    ctx->state[0] = 0xCBBB9D5DC1059ED8;
    ctx->state[1] = 0x629A292A367CD507;
    ctx->state[2] = 0x9159015A3070DD17;
    ctx->state[3] = 0x152FECD8F70E5939;
    ctx->state[4] = 0x67332667FFC00B31;
    ctx->state[5] = 0x8EB44A8768581511;
    ctx->state[6] = 0xDB0C2E0D64F98FA7;
    ctx->state[7] = 0x47B5481DBEFA4FA4;
    ctx->paddin2times = 0;
}

static void kryptos_sha512_init(struct kryptos_sha384_512_ctx *ctx) {
    ctx->state[0] = 0x6A09E667F3BCC908;
    ctx->state[1] = 0xBB67AE8584CAA73B;
    ctx->state[2] = 0x3C6EF372FE94F82B;
    ctx->state[3] = 0xA54FF53A5F1D36F1;
    ctx->state[4] = 0x510E527FADE682D1;
    ctx->state[5] = 0x9B05688C2B3E6C1F;
    ctx->state[6] = 0x1F83D9ABFB41BD6B;
    ctx->state[7] = 0x5BE0CD19137E2179;
    ctx->paddin2times = 0;
}

static void kryptos_sha384_512_do_block(struct kryptos_sha384_512_ctx *ctx) {
    kryptos_u64_t W[80];
    kryptos_u64_t T1, T2, a, b, c, d, e, f, g, h;
    size_t t;

    if (ctx->curr_len < KRYPTOS_SHA384_512_BYTES_PER_BLOCK) {
        kryptos_hash_apply_pad_on_u64_block(ctx->input.block, 16,
                                            kryptos_sha384_512_block_index_decision_table,
                                            ctx->curr_len, ctx->total_len, &ctx->paddin2times,
                                            KRYPTOS_SHA384_512_LEN_BLOCK_OFFSET);
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
        W[t] = kryptos_sha384_512_SSIG1(W[t -  2]) + W[t -  7] +
               kryptos_sha384_512_SSIG0(W[t - 15]) + W[t - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (t = 0; t < 80; t++) {
        T1 = h + kryptos_sha384_512_BSIG1(e) + kryptos_sha384_512_CH(e, f, g) + kryptos_sha384_512_K[t] + W[t];
        T2 = kryptos_sha384_512_BSIG0(a) + kryptos_sha384_512_MAJ(a, b, c);
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
    t = 0;
    memset(W, 0, sizeof(W));

    if (ctx->paddin2times) {
        kryptos_hash_ld_u8buf_as_u64_blocks((kryptos_u8_t *)"", 0,
                                            ctx->input.block, 16,
                                            kryptos_sha384_512_block_index_decision_table);
        kryptos_sha384_512_do_block(ctx);
    }
}

#undef kryptos_sha384_512_CH

#undef kryptos_sha384_512_MAJ

#undef kryptos_sha384_512_ROTR

#undef kryptos_sha384_512_BSIG0

#undef kryptos_sha384_512_BSIG1

#undef kryptos_sha384_512_SSIG0

#undef kryptos_sha384_512_SSIG1

#undef KRYPTOS_SHA384_512_LEN_BLOCK_OFFSET

#undef KRYPTOS_SHA384_HASH_SIZE

#undef KRYPTOS_SHA512_HASH_SIZE
