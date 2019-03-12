/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_blake2.h>
#include <kryptos_hash_common.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_hex.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif
#include <inttypes.h>

static kryptos_u8_t kryptos_blake2_SIGMA_state[10][16] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
    11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
     7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
     9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
     2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
    12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
    13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
     6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
    10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0
};

static kryptos_u8_t kryptos_blake2b_R[4] = { 32, 24, 16, 63 };
static kryptos_u8_t kryptos_blake2s_R[4] = { 16, 12,  8,  7 };

static kryptos_u64_t kryptos_blake2b_IV[8] = {
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

static kryptos_u32_t kryptos_blake2s_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

struct kryptos_blake2b_ctx {
    kryptos_u64_t h[8], m[16], v[16];
    kryptos_u64_t *IV;
    kryptos_u64_t t[2];
    int f;
};

struct kryptos_blake2s_ctx {
    kryptos_u32_t h[8], m[16], v[16];
    kryptos_u32_t *IV;
    kryptos_u32_t t[2];
    int f;
};

struct kryptos_blake2_ctx {
    kryptos_u8_t *input;
    kryptos_u8_t *key;
    size_t ll, kk, nn, bb;
    kryptos_u8_t *h;
    size_t h_size;
};

#define KRYPTOS_BLAKE2S_BYTES_PER_BLOCK  64

#define KRYPTOS_BLAKE2B_BYTES_PER_BLOCK 128

#define KRYPTOS_BLAKE2S224_HASH_SIZE 28

#define KRYPTOS_BLAKE2S256_HASH_SIZE 32

#define KRYPTOS_BLAKE2B384_HASH_SIZE 48

#define KRYPTOS_BLAKE2B512_HASH_SIZE 64

#define kryptos_blake2_R(var, n) kryptos_ ## var ## _R[n - 1]

#define kryptos_blake2_ROT(x, y) ( ( (x) >> (y) ) | ( (x) << ( (sizeof(x) << 3) - (y) ) ) )

#define kryptos_blake2_G(v, a, b, c, d, x, y, var) {\
    v[a] += v[b] + x;\
    v[d] ^= v[a];\
    v[d] = kryptos_blake2_ROT(v[d], kryptos_blake2_R(var, 1));\
    v[c] += v[d];\
    v[b] ^= v[c];\
    v[b] = kryptos_blake2_ROT(v[b], kryptos_blake2_R(var, 2));\
    v[a] += v[b] + y;\
    v[d] ^= v[a];\
    v[d] = kryptos_blake2_ROT(v[d], kryptos_blake2_R(var, 3));\
    v[c] += v[d];\
    v[b] ^= v[c];\
    v[b] = kryptos_blake2_ROT(v[b], kryptos_blake2_R(var, 4));\
}

#define kryptos_blake2_SIGMA(r, c) kryptos_blake2_SIGMA_state[r][c]

#define kryptos_blake2b_F(c) {\
    c->v[ 0] = c->h[ 0];\
    c->v[ 1] = c->h[ 1];\
    c->v[ 2] = c->h[ 2];\
    c->v[ 3] = c->h[ 3];\
    c->v[ 4] = c->h[ 4];\
    c->v[ 5] = c->h[ 5];\
    c->v[ 6] = c->h[ 6];\
    c->v[ 7] = c->h[ 7];\
    c->v[ 8] = c->IV[0];\
    c->v[ 9] = c->IV[1];\
    c->v[10] = c->IV[2];\
    c->v[11] = c->IV[3];\
    c->v[12] = c->IV[4];\
    c->v[13] = c->IV[5];\
    c->v[14] = c->IV[6];\
    c->v[15] = c->IV[7];\
    c->v[12] ^= c->t[0];\
    c->v[13] ^= c->t[1];\
    if (c->f) {\
        c->v[14] = ~c->v[14];\
    }\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(0,  0)], c->m[kryptos_blake2_SIGMA(0,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(0,  2)], c->m[kryptos_blake2_SIGMA(0,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(0,  4)], c->m[kryptos_blake2_SIGMA(0,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(0,  6)], c->m[kryptos_blake2_SIGMA(0,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(0,  8)], c->m[kryptos_blake2_SIGMA(0,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(0, 10)], c->m[kryptos_blake2_SIGMA(0, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(0, 12)], c->m[kryptos_blake2_SIGMA(0, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(0, 14)], c->m[kryptos_blake2_SIGMA(0, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(1,  0)], c->m[kryptos_blake2_SIGMA(1,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(1,  2)], c->m[kryptos_blake2_SIGMA(1,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(1,  4)], c->m[kryptos_blake2_SIGMA(1,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(1,  6)], c->m[kryptos_blake2_SIGMA(1,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(1,  8)], c->m[kryptos_blake2_SIGMA(1,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(1, 10)], c->m[kryptos_blake2_SIGMA(1, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(1, 12)], c->m[kryptos_blake2_SIGMA(1, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(1, 14)], c->m[kryptos_blake2_SIGMA(1, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(2,  0)], c->m[kryptos_blake2_SIGMA(2,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(2,  2)], c->m[kryptos_blake2_SIGMA(2,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(2,  4)], c->m[kryptos_blake2_SIGMA(2,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(2,  6)], c->m[kryptos_blake2_SIGMA(2,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(2,  8)], c->m[kryptos_blake2_SIGMA(2,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(2, 10)], c->m[kryptos_blake2_SIGMA(2, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(2, 12)], c->m[kryptos_blake2_SIGMA(2, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(2, 14)], c->m[kryptos_blake2_SIGMA(2, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(3,  0)], c->m[kryptos_blake2_SIGMA(3,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(3,  2)], c->m[kryptos_blake2_SIGMA(3,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(3,  4)], c->m[kryptos_blake2_SIGMA(3,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(3,  6)], c->m[kryptos_blake2_SIGMA(3,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(3,  8)], c->m[kryptos_blake2_SIGMA(3,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(3, 10)], c->m[kryptos_blake2_SIGMA(3, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(3, 12)], c->m[kryptos_blake2_SIGMA(3, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(3, 14)], c->m[kryptos_blake2_SIGMA(3, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(4,  0)], c->m[kryptos_blake2_SIGMA(4,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(4,  2)], c->m[kryptos_blake2_SIGMA(4,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(4,  4)], c->m[kryptos_blake2_SIGMA(4,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(4,  6)], c->m[kryptos_blake2_SIGMA(4,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(4,  8)], c->m[kryptos_blake2_SIGMA(4,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(4, 10)], c->m[kryptos_blake2_SIGMA(4, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(4, 12)], c->m[kryptos_blake2_SIGMA(4, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(4, 14)], c->m[kryptos_blake2_SIGMA(4, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(5,  0)], c->m[kryptos_blake2_SIGMA(5,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(5,  2)], c->m[kryptos_blake2_SIGMA(5,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(5,  4)], c->m[kryptos_blake2_SIGMA(5,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(5,  6)], c->m[kryptos_blake2_SIGMA(5,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(5,  8)], c->m[kryptos_blake2_SIGMA(5,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(5, 10)], c->m[kryptos_blake2_SIGMA(5, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(5, 12)], c->m[kryptos_blake2_SIGMA(5, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(5, 14)], c->m[kryptos_blake2_SIGMA(5, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(6,  0)], c->m[kryptos_blake2_SIGMA(6,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(6,  2)], c->m[kryptos_blake2_SIGMA(6,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(6,  4)], c->m[kryptos_blake2_SIGMA(6,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(6,  6)], c->m[kryptos_blake2_SIGMA(6,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(6,  8)], c->m[kryptos_blake2_SIGMA(6,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(6, 10)], c->m[kryptos_blake2_SIGMA(6, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(6, 12)], c->m[kryptos_blake2_SIGMA(6, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(6, 14)], c->m[kryptos_blake2_SIGMA(6, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(7,  0)], c->m[kryptos_blake2_SIGMA(7,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(7,  2)], c->m[kryptos_blake2_SIGMA(7,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(7,  4)], c->m[kryptos_blake2_SIGMA(7,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(7,  6)], c->m[kryptos_blake2_SIGMA(7,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(7,  8)], c->m[kryptos_blake2_SIGMA(7,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(7, 10)], c->m[kryptos_blake2_SIGMA(7, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(7, 12)], c->m[kryptos_blake2_SIGMA(7, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(7, 14)], c->m[kryptos_blake2_SIGMA(7, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(8,  0)], c->m[kryptos_blake2_SIGMA(8,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(8,  2)], c->m[kryptos_blake2_SIGMA(8,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(8,  4)], c->m[kryptos_blake2_SIGMA(8,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(8,  6)], c->m[kryptos_blake2_SIGMA(8,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(8,  8)], c->m[kryptos_blake2_SIGMA(8,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(8, 10)], c->m[kryptos_blake2_SIGMA(8, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(8, 12)], c->m[kryptos_blake2_SIGMA(8, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(8, 14)], c->m[kryptos_blake2_SIGMA(8, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(9,  0)], c->m[kryptos_blake2_SIGMA(9,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(9,  2)], c->m[kryptos_blake2_SIGMA(9,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(9,  4)], c->m[kryptos_blake2_SIGMA(9,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(9,  6)], c->m[kryptos_blake2_SIGMA(9,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(9,  8)], c->m[kryptos_blake2_SIGMA(9,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(9, 10)], c->m[kryptos_blake2_SIGMA(9, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(9, 12)], c->m[kryptos_blake2_SIGMA(9, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(9, 14)], c->m[kryptos_blake2_SIGMA(9, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(0,  0)], c->m[kryptos_blake2_SIGMA(0,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(0,  2)], c->m[kryptos_blake2_SIGMA(0,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(0,  4)], c->m[kryptos_blake2_SIGMA(0,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(0,  6)], c->m[kryptos_blake2_SIGMA(0,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(0,  8)], c->m[kryptos_blake2_SIGMA(0,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(0, 10)], c->m[kryptos_blake2_SIGMA(0, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(0, 12)], c->m[kryptos_blake2_SIGMA(0, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(0, 14)], c->m[kryptos_blake2_SIGMA(0, 15)], blake2b);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(1,  0)], c->m[kryptos_blake2_SIGMA(1,  1)], blake2b);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(1,  2)], c->m[kryptos_blake2_SIGMA(1,  3)], blake2b);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(1,  4)], c->m[kryptos_blake2_SIGMA(1,  5)], blake2b);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(1,  6)], c->m[kryptos_blake2_SIGMA(1,  7)], blake2b);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(1,  8)], c->m[kryptos_blake2_SIGMA(1,  9)], blake2b);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(1, 10)], c->m[kryptos_blake2_SIGMA(1, 11)], blake2b);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(1, 12)], c->m[kryptos_blake2_SIGMA(1, 13)], blake2b);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(1, 14)], c->m[kryptos_blake2_SIGMA(1, 15)], blake2b);\
    c->h[0] ^= c->v[0] ^ c->v[ 8];\
    c->h[1] ^= c->v[1] ^ c->v[ 9];\
    c->h[2] ^= c->v[2] ^ c->v[10];\
    c->h[3] ^= c->v[3] ^ c->v[11];\
    c->h[4] ^= c->v[4] ^ c->v[12];\
    c->h[5] ^= c->v[5] ^ c->v[13];\
    c->h[6] ^= c->v[6] ^ c->v[14];\
    c->h[7] ^= c->v[7] ^ c->v[15];\
}

#define kryptos_blake2s_F(c) {\
    c->v[ 0] = c->h[ 0];\
    c->v[ 1] = c->h[ 1];\
    c->v[ 2] = c->h[ 2];\
    c->v[ 3] = c->h[ 3];\
    c->v[ 4] = c->h[ 4];\
    c->v[ 5] = c->h[ 5];\
    c->v[ 6] = c->h[ 6];\
    c->v[ 7] = c->h[ 7];\
    c->v[ 8] = c->IV[0];\
    c->v[ 9] = c->IV[1];\
    c->v[10] = c->IV[2];\
    c->v[11] = c->IV[3];\
    c->v[12] = c->IV[4];\
    c->v[13] = c->IV[5];\
    c->v[14] = c->IV[6];\
    c->v[15] = c->IV[7];\
    c->v[12] ^= c->t[0];\
    c->v[13] ^= c->t[1];\
    if (c->f) {\
        c->v[14] = ~c->v[14];\
    }\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(0,  0)], c->m[kryptos_blake2_SIGMA(0,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(0,  2)], c->m[kryptos_blake2_SIGMA(0,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(0,  4)], c->m[kryptos_blake2_SIGMA(0,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(0,  6)], c->m[kryptos_blake2_SIGMA(0,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(0,  8)], c->m[kryptos_blake2_SIGMA(0,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(0, 10)], c->m[kryptos_blake2_SIGMA(0, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(0, 12)], c->m[kryptos_blake2_SIGMA(0, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(0, 14)], c->m[kryptos_blake2_SIGMA(0, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(1,  0)], c->m[kryptos_blake2_SIGMA(1,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(1,  2)], c->m[kryptos_blake2_SIGMA(1,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(1,  4)], c->m[kryptos_blake2_SIGMA(1,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(1,  6)], c->m[kryptos_blake2_SIGMA(1,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(1,  8)], c->m[kryptos_blake2_SIGMA(1,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(1, 10)], c->m[kryptos_blake2_SIGMA(1, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(1, 12)], c->m[kryptos_blake2_SIGMA(1, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(1, 14)], c->m[kryptos_blake2_SIGMA(1, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(2,  0)], c->m[kryptos_blake2_SIGMA(2,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(2,  2)], c->m[kryptos_blake2_SIGMA(2,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(2,  4)], c->m[kryptos_blake2_SIGMA(2,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(2,  6)], c->m[kryptos_blake2_SIGMA(2,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(2,  8)], c->m[kryptos_blake2_SIGMA(2,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(2, 10)], c->m[kryptos_blake2_SIGMA(2, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(2, 12)], c->m[kryptos_blake2_SIGMA(2, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(2, 14)], c->m[kryptos_blake2_SIGMA(2, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(3,  0)], c->m[kryptos_blake2_SIGMA(3,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(3,  2)], c->m[kryptos_blake2_SIGMA(3,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(3,  4)], c->m[kryptos_blake2_SIGMA(3,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(3,  6)], c->m[kryptos_blake2_SIGMA(3,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(3,  8)], c->m[kryptos_blake2_SIGMA(3,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(3, 10)], c->m[kryptos_blake2_SIGMA(3, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(3, 12)], c->m[kryptos_blake2_SIGMA(3, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(3, 14)], c->m[kryptos_blake2_SIGMA(3, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(4,  0)], c->m[kryptos_blake2_SIGMA(4,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(4,  2)], c->m[kryptos_blake2_SIGMA(4,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(4,  4)], c->m[kryptos_blake2_SIGMA(4,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(4,  6)], c->m[kryptos_blake2_SIGMA(4,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(4,  8)], c->m[kryptos_blake2_SIGMA(4,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(4, 10)], c->m[kryptos_blake2_SIGMA(4, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(4, 12)], c->m[kryptos_blake2_SIGMA(4, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(4, 14)], c->m[kryptos_blake2_SIGMA(4, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(5,  0)], c->m[kryptos_blake2_SIGMA(5,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(5,  2)], c->m[kryptos_blake2_SIGMA(5,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(5,  4)], c->m[kryptos_blake2_SIGMA(5,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(5,  6)], c->m[kryptos_blake2_SIGMA(5,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(5,  8)], c->m[kryptos_blake2_SIGMA(5,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(5, 10)], c->m[kryptos_blake2_SIGMA(5, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(5, 12)], c->m[kryptos_blake2_SIGMA(5, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(5, 14)], c->m[kryptos_blake2_SIGMA(5, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(6,  0)], c->m[kryptos_blake2_SIGMA(6,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(6,  2)], c->m[kryptos_blake2_SIGMA(6,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(6,  4)], c->m[kryptos_blake2_SIGMA(6,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(6,  6)], c->m[kryptos_blake2_SIGMA(6,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(6,  8)], c->m[kryptos_blake2_SIGMA(6,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(6, 10)], c->m[kryptos_blake2_SIGMA(6, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(6, 12)], c->m[kryptos_blake2_SIGMA(6, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(6, 14)], c->m[kryptos_blake2_SIGMA(6, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(7,  0)], c->m[kryptos_blake2_SIGMA(7,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(7,  2)], c->m[kryptos_blake2_SIGMA(7,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(7,  4)], c->m[kryptos_blake2_SIGMA(7,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(7,  6)], c->m[kryptos_blake2_SIGMA(7,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(7,  8)], c->m[kryptos_blake2_SIGMA(7,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(7, 10)], c->m[kryptos_blake2_SIGMA(7, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(7, 12)], c->m[kryptos_blake2_SIGMA(7, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(7, 14)], c->m[kryptos_blake2_SIGMA(7, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(8,  0)], c->m[kryptos_blake2_SIGMA(8,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(8,  2)], c->m[kryptos_blake2_SIGMA(8,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(8,  4)], c->m[kryptos_blake2_SIGMA(8,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(8,  6)], c->m[kryptos_blake2_SIGMA(8,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(8,  8)], c->m[kryptos_blake2_SIGMA(8,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(8, 10)], c->m[kryptos_blake2_SIGMA(8, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(8, 12)], c->m[kryptos_blake2_SIGMA(8, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(8, 14)], c->m[kryptos_blake2_SIGMA(8, 15)], blake2s);\
    kryptos_blake2_G(c->v,  0,  4,  8, 12, c->m[kryptos_blake2_SIGMA(9,  0)], c->m[kryptos_blake2_SIGMA(9,  1)], blake2s);\
    kryptos_blake2_G(c->v,  1,  5,  9, 13, c->m[kryptos_blake2_SIGMA(9,  2)], c->m[kryptos_blake2_SIGMA(9,  3)], blake2s);\
    kryptos_blake2_G(c->v,  2,  6, 10, 14, c->m[kryptos_blake2_SIGMA(9,  4)], c->m[kryptos_blake2_SIGMA(9,  5)], blake2s);\
    kryptos_blake2_G(c->v,  3,  7, 11, 15, c->m[kryptos_blake2_SIGMA(9,  6)], c->m[kryptos_blake2_SIGMA(9,  7)], blake2s);\
    kryptos_blake2_G(c->v,  0,  5, 10, 15, c->m[kryptos_blake2_SIGMA(9,  8)], c->m[kryptos_blake2_SIGMA(9,  9)], blake2s);\
    kryptos_blake2_G(c->v,  1,  6, 11, 12, c->m[kryptos_blake2_SIGMA(9, 10)], c->m[kryptos_blake2_SIGMA(9, 11)], blake2s);\
    kryptos_blake2_G(c->v,  2,  7,  8, 13, c->m[kryptos_blake2_SIGMA(9, 12)], c->m[kryptos_blake2_SIGMA(9, 13)], blake2s);\
    kryptos_blake2_G(c->v,  3,  4,  9, 14, c->m[kryptos_blake2_SIGMA(9, 14)], c->m[kryptos_blake2_SIGMA(9, 15)], blake2s);\
    c->h[0] ^= c->v[0] ^ c->v[ 8];\
    c->h[1] ^= c->v[1] ^ c->v[ 9];\
    c->h[2] ^= c->v[2] ^ c->v[10];\
    c->h[3] ^= c->v[3] ^ c->v[11];\
    c->h[4] ^= c->v[4] ^ c->v[12];\
    c->h[5] ^= c->v[5] ^ c->v[13];\
    c->h[6] ^= c->v[6] ^ c->v[14];\
    c->h[7] ^= c->v[7] ^ c->v[15];\
}

#define kryptos_blake2_init(c, kk, nn, iv) {\
    c->IV = &iv[0];\
    c->h[0] = c->IV[0];\
    c->h[1] = c->IV[1];\
    c->h[2] = c->IV[2];\
    c->h[3] = c->IV[3];\
    c->h[4] = c->IV[4];\
    c->h[5] = c->IV[5];\
    c->h[6] = c->IV[6];\
    c->h[7] = c->IV[7];\
    c->h[0] ^= 0x01010000 ^ (kk << 8) ^ nn;\
    c->f = 0;\
}\

#define kryptos_blake2_get_next_m_chunk(m, h, t, gf, rev) {\
    if (h != t) {\
        if (t - h >= sizeof(m)) {\
            m = gf(h, t - h);\
            h += sizeof(m);\
        } else {\
            m = 0;\
            while (h != t) {\
                m = (m << 8) | *h;\
                h++;\
            }\
            m = rev(m);\
        }\
    } else {\
        m = 0;\
    }\
}

static void kryptos_blake2b(struct kryptos_blake2_ctx *data);

static void kryptos_blake2s(struct kryptos_blake2_ctx *data);

KRYPTOS_IMPL_HASH_SIZE(blake2s256, KRYPTOS_BLAKE2S256_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(blake2s256, KRYPTOS_BLAKE2S_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(blake2s256, ktask, kryptos_blake2_ctx, ctx, blake2s256_epilogue,
                            {
                                ctx.input = (*ktask)->in;
                                ctx.key = (*ktask)->key;
                                ctx.bb = KRYPTOS_BLAKE2S_BYTES_PER_BLOCK;
                                ctx.nn = KRYPTOS_BLAKE2S256_HASH_SIZE;
                                ctx.kk = (*ktask)->key_size;
                                ctx.ll = (*ktask)->in_size;
                            },
                            kryptos_blake2s(&ctx),
                            {
                                if (ctx.h == NULL || ctx.h_size != KRYPTOS_BLAKE2S256_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_blake2s256_epilogue;
                                }
                                (*ktask)->out = ctx.h;
                                (*ktask)->out_size = ctx.h_size;
                                ctx.h = NULL;
                            },
                            {
                                if (ctx.h == NULL || ctx.h_size != KRYPTOS_BLAKE2S256_HASH_SIZE) {
                                    goto kryptos_blake2s256_no_memory;
                                }
                                (*ktask)->out_size = KRYPTOS_BLAKE2S256_HASH_SIZE << 1;
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((*ktask)->out_size + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_blake2s256_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_blake2s256_epilogue;
                                }
                                kryptos_u64_to_hex((*ktask)->out      , 65, ((kryptos_u64_t)ctx.h[  0]) << 56 |
                                                                            ((kryptos_u64_t)ctx.h[  1]) << 48 |
                                                                            ((kryptos_u64_t)ctx.h[  2]) << 40 |
                                                                            ((kryptos_u64_t)ctx.h[  3]) << 32 |
                                                                            ((kryptos_u64_t)ctx.h[  4]) << 24 |
                                                                            ((kryptos_u64_t)ctx.h[  5]) << 16 |
                                                                            ((kryptos_u64_t)ctx.h[  6]) <<  8 |
                                                                            ((kryptos_u64_t)ctx.h[  7]));
                                kryptos_u64_to_hex((*ktask)->out +  16, 49, ((kryptos_u64_t)ctx.h[  8]) << 56 |
                                                                            ((kryptos_u64_t)ctx.h[  9]) << 48 |
                                                                            ((kryptos_u64_t)ctx.h[ 10]) << 40 |
                                                                            ((kryptos_u64_t)ctx.h[ 11]) << 32 |
                                                                            ((kryptos_u64_t)ctx.h[ 12]) << 24 |
                                                                            ((kryptos_u64_t)ctx.h[ 13]) << 16 |
                                                                            ((kryptos_u64_t)ctx.h[ 14]) <<  8 |
                                                                            ((kryptos_u64_t)ctx.h[ 15]));
                                kryptos_u64_to_hex((*ktask)->out +  32, 33, ((kryptos_u64_t)ctx.h[ 16]) << 56 |
                                                                            ((kryptos_u64_t)ctx.h[ 17]) << 48 |
                                                                            ((kryptos_u64_t)ctx.h[ 18]) << 40 |
                                                                            ((kryptos_u64_t)ctx.h[ 19]) << 32 |
                                                                            ((kryptos_u64_t)ctx.h[ 20]) << 24 |
                                                                            ((kryptos_u64_t)ctx.h[ 21]) << 16 |
                                                                            ((kryptos_u64_t)ctx.h[ 22]) <<  8 |
                                                                            ((kryptos_u64_t)ctx.h[ 23]));
                                kryptos_u64_to_hex((*ktask)->out +  48, 17, ((kryptos_u64_t)ctx.h[ 24]) << 56 |
                                                                            ((kryptos_u64_t)ctx.h[ 25]) << 48 |
                                                                            ((kryptos_u64_t)ctx.h[ 26]) << 40 |
                                                                            ((kryptos_u64_t)ctx.h[ 27]) << 32 |
                                                                            ((kryptos_u64_t)ctx.h[ 28]) << 24 |
                                                                            ((kryptos_u64_t)ctx.h[ 29]) << 16 |
                                                                            ((kryptos_u64_t)ctx.h[ 30]) <<  8 |
                                                                            ((kryptos_u64_t)ctx.h[ 31]));
                                kryptos_freeseg(ctx.h, ctx.h_size);
                            })

KRYPTOS_IMPL_HASH_SIZE(blake2b512, KRYPTOS_BLAKE2B512_HASH_SIZE)

KRYPTOS_IMPL_HASH_INPUT_SIZE(blake2b512, KRYPTOS_BLAKE2B_BYTES_PER_BLOCK)

KRYPTOS_IMPL_HASH_PROCESSOR(blake2b512, ktask, kryptos_blake2_ctx, ctx, blake2b512_epilogue,
                            {
                                ctx.input = (*ktask)->in;
                                ctx.key = (*ktask)->key;
                                ctx.bb = KRYPTOS_BLAKE2B_BYTES_PER_BLOCK;
                                ctx.nn = KRYPTOS_BLAKE2B512_HASH_SIZE;
                                ctx.kk = (*ktask)->key_size;
                                ctx.ll = (*ktask)->in_size;
                            },
                            kryptos_blake2b(&ctx),
                            {
                                if (ctx.h == NULL || ctx.h_size != KRYPTOS_BLAKE2B512_HASH_SIZE) {
                                    (*ktask)->out_size = 0;
                                    (*ktask)->result = kKryptosProcessError;
                                    (*ktask)->result_verbose = "No memory to get a valid output.";
                                    goto kryptos_blake2b512_epilogue;
                                }
                                (*ktask)->out = ctx.h;
                                (*ktask)->out_size = ctx.h_size;
                                ctx.h = NULL;
                            },
                            {
                                if (ctx.h == NULL || ctx.h_size != KRYPTOS_BLAKE2B512_HASH_SIZE) {
                                    goto kryptos_blake2b512_no_memory;
                                }
                                (*ktask)->out_size = KRYPTOS_BLAKE2B512_HASH_SIZE << 1;
                                (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((*ktask)->out_size + 1);
                                if ((*ktask)->out == NULL) {
                                    kryptos_blake2b512_no_memory:
                                        (*ktask)->out_size = 0;
                                        (*ktask)->result = kKryptosProcessError;
                                        (*ktask)->result_verbose = "No memory to get a valid output.";
                                        goto kryptos_blake2b512_epilogue;
                                }
                                kryptos_u64_to_hex((*ktask)->out      , 129,  ((kryptos_u64_t)ctx.h[  0]) << 56 |
                                                                              ((kryptos_u64_t)ctx.h[  1]) << 48 |
                                                                              ((kryptos_u64_t)ctx.h[  2]) << 40 |
                                                                              ((kryptos_u64_t)ctx.h[  3]) << 32 |
                                                                              ((kryptos_u64_t)ctx.h[  4]) << 24 |
                                                                              ((kryptos_u64_t)ctx.h[  5]) << 16 |
                                                                              ((kryptos_u64_t)ctx.h[  6]) <<  8 |
                                                                              ((kryptos_u64_t)ctx.h[  7]));
                                kryptos_u64_to_hex((*ktask)->out +  16,  113, ((kryptos_u64_t)ctx.h[  8]) << 56 |
                                                                              ((kryptos_u64_t)ctx.h[  9]) << 48 |
                                                                              ((kryptos_u64_t)ctx.h[ 10]) << 40 |
                                                                              ((kryptos_u64_t)ctx.h[ 11]) << 32 |
                                                                              ((kryptos_u64_t)ctx.h[ 12]) << 24 |
                                                                              ((kryptos_u64_t)ctx.h[ 13]) << 16 |
                                                                              ((kryptos_u64_t)ctx.h[ 14]) <<  8 |
                                                                              ((kryptos_u64_t)ctx.h[ 15]));
                                kryptos_u64_to_hex((*ktask)->out +  32,   97, ((kryptos_u64_t)ctx.h[ 16]) << 56 |
                                                                              ((kryptos_u64_t)ctx.h[ 17]) << 48 |
                                                                              ((kryptos_u64_t)ctx.h[ 18]) << 40 |
                                                                              ((kryptos_u64_t)ctx.h[ 19]) << 32 |
                                                                              ((kryptos_u64_t)ctx.h[ 20]) << 24 |
                                                                              ((kryptos_u64_t)ctx.h[ 21]) << 16 |
                                                                              ((kryptos_u64_t)ctx.h[ 22]) <<  8 |
                                                                              ((kryptos_u64_t)ctx.h[ 23]));
                                kryptos_u64_to_hex((*ktask)->out +  48,   81, ((kryptos_u64_t)ctx.h[ 24]) << 56 |
                                                                              ((kryptos_u64_t)ctx.h[ 25]) << 48 |
                                                                              ((kryptos_u64_t)ctx.h[ 26]) << 40 |
                                                                              ((kryptos_u64_t)ctx.h[ 27]) << 32 |
                                                                              ((kryptos_u64_t)ctx.h[ 28]) << 24 |
                                                                              ((kryptos_u64_t)ctx.h[ 29]) << 16 |
                                                                              ((kryptos_u64_t)ctx.h[ 30]) <<  8 |
                                                                              ((kryptos_u64_t)ctx.h[ 31]));
                                kryptos_u64_to_hex((*ktask)->out +  64,   65, ((kryptos_u64_t)ctx.h[ 32]) << 56 |
                                                                              ((kryptos_u64_t)ctx.h[ 33]) << 48 |
                                                                              ((kryptos_u64_t)ctx.h[ 34]) << 40 |
                                                                              ((kryptos_u64_t)ctx.h[ 35]) << 32 |
                                                                              ((kryptos_u64_t)ctx.h[ 36]) << 24 |
                                                                              ((kryptos_u64_t)ctx.h[ 37]) << 16 |
                                                                              ((kryptos_u64_t)ctx.h[ 38]) <<  8 |
                                                                              ((kryptos_u64_t)ctx.h[ 39]));
                                kryptos_u64_to_hex((*ktask)->out +  80,   49, ((kryptos_u64_t)ctx.h[ 40]) << 56 |
                                                                              ((kryptos_u64_t)ctx.h[ 41]) << 48 |
                                                                              ((kryptos_u64_t)ctx.h[ 42]) << 40 |
                                                                              ((kryptos_u64_t)ctx.h[ 43]) << 32 |
                                                                              ((kryptos_u64_t)ctx.h[ 44]) << 24 |
                                                                              ((kryptos_u64_t)ctx.h[ 45]) << 16 |
                                                                              ((kryptos_u64_t)ctx.h[ 46]) <<  8 |
                                                                              ((kryptos_u64_t)ctx.h[ 47]));
                                kryptos_u64_to_hex((*ktask)->out +  96,   33, ((kryptos_u64_t)ctx.h[ 48]) << 56 |
                                                                              ((kryptos_u64_t)ctx.h[ 49]) << 48 |
                                                                              ((kryptos_u64_t)ctx.h[ 50]) << 40 |
                                                                              ((kryptos_u64_t)ctx.h[ 51]) << 32 |
                                                                              ((kryptos_u64_t)ctx.h[ 52]) << 24 |
                                                                              ((kryptos_u64_t)ctx.h[ 53]) << 16 |
                                                                              ((kryptos_u64_t)ctx.h[ 54]) <<  8 |
                                                                              ((kryptos_u64_t)ctx.h[ 55]));
                                kryptos_u64_to_hex((*ktask)->out + 112,   17, ((kryptos_u64_t)ctx.h[ 56]) << 56 |
                                                                              ((kryptos_u64_t)ctx.h[ 57]) << 48 |
                                                                              ((kryptos_u64_t)ctx.h[ 58]) << 40 |
                                                                              ((kryptos_u64_t)ctx.h[ 59]) << 32 |
                                                                              ((kryptos_u64_t)ctx.h[ 60]) << 24 |
                                                                              ((kryptos_u64_t)ctx.h[ 61]) << 16 |
                                                                              ((kryptos_u64_t)ctx.h[ 62]) <<  8 |
                                                                              ((kryptos_u64_t)ctx.h[ 63]));
                                kryptos_freeseg(ctx.h, ctx.h_size);
                            })

static void kryptos_blake2s(struct kryptos_blake2_ctx *data) {
    struct kryptos_blake2s_ctx b, *p = &b;
    size_t dd, i, t;
    kryptos_u8_t *in, *in_head = NULL, *in_tail = NULL, temp[4];

    data->h_size = 0;

    kryptos_blake2_init(p, data->kk, data->nn, kryptos_blake2s_IV);

    dd = ((data->kk > 0) ? KRYPTOS_BLAKE2S_BYTES_PER_BLOCK : 0) + data->ll;

    if (dd == 0) {
        // INFO(Rafael): 'However, in the special case of an unkeyed empty message (kk = 0 and
        //                        ll = 0), we still set dd = 1 and d[0] consists of all zeros.'
        dd = 1;
    }

    // INFO(Rafael): When the hash is keyed the key block must be processed as the first block.

    while (dd % KRYPTOS_BLAKE2S_BYTES_PER_BLOCK) {
        dd++;
    }

    if ((in_head = (kryptos_u8_t *) kryptos_newseg(dd)) == NULL) {
        goto kryptos_blake2s_epilogue;
    }

    in = in_head;
    in_tail = in_head + dd;

    memset(in_head, 0, dd);

    dd /= KRYPTOS_BLAKE2S_BYTES_PER_BLOCK;

    if (data->kk > 0) {
        memcpy(in_head, data->key, data->kk);
        memcpy(in_head + KRYPTOS_BLAKE2S_BYTES_PER_BLOCK, data->input, data->ll);
    } else {
        memcpy(in_head, data->input, data->ll);
    }

    p->t[0] = KRYPTOS_BLAKE2S_BYTES_PER_BLOCK;
    p->t[1] = 0;

    kryptos_blake2_get_next_m_chunk(p->m[ 0], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 1], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 2], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 3], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 4], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 5], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 6], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 7], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 8], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 9], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[10], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[11], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[12], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[13], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[14], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
    kryptos_blake2_get_next_m_chunk(p->m[15], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);

    if (dd > 1) {
        for (i = 0; i < dd - 1; i++) {

            kryptos_blake2s_F(p);

            p->t[0] += KRYPTOS_BLAKE2S_BYTES_PER_BLOCK;

            if (p->t[0] < KRYPTOS_BLAKE2S_BYTES_PER_BLOCK) {
                p->t[1] += 1;
            }

            kryptos_blake2_get_next_m_chunk(p->m[ 0], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 1], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 2], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 3], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 4], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 5], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 6], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 7], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 8], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 9], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[10], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[11], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[12], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[13], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[14], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
            kryptos_blake2_get_next_m_chunk(p->m[15], in, in_tail, kryptos_get_u32_as_little_endian, kryptos_u32_rev);
        }
    }

    p->f = 1;

    if (data->kk == 0) {
        p->t[0] = data->ll;
        p->t[1] = 0;
    } else {
        p->t[0] = data->ll + KRYPTOS_BLAKE2S_BYTES_PER_BLOCK;
        p->t[1] = 0;
    }

    kryptos_blake2s_F(p);

    if ((data->h = (kryptos_u8_t *) kryptos_newseg(data->nn)) == NULL) {
        goto kryptos_blake2s_epilogue;
    }

    i = 0;
    t = 0;

    while (data->h_size < data->nn && i < 8) {
        kryptos_cpy_u32_as_big_endian(temp, sizeof(temp), kryptos_u32_rev(p->h[i]));
        for (t = 0; t < 4 && data->h_size < data->nn; t++, data->h_size++) {
            data->h[data->h_size] = temp[t];
        }
        i++;
    }

kryptos_blake2s_epilogue:

    if (in_head != NULL) {
        kryptos_freeseg(in_head, in_tail - in_head);
    }

    memset(temp, 0, sizeof(temp));
    memset(p, 0, sizeof(struct kryptos_blake2s_ctx));
    i = t = dd = 0;
    in_head = in_tail = in = NULL;
}

static void kryptos_blake2b(struct kryptos_blake2_ctx *data) {
    struct kryptos_blake2b_ctx b, *p = &b;
    size_t dd, i, t;
    kryptos_u8_t *in, *in_head = NULL, *in_tail = NULL, temp[8];

    data->h_size = 0;

    kryptos_blake2_init(p, data->kk, data->nn, kryptos_blake2b_IV);

    dd = ((data->kk > 0) ? KRYPTOS_BLAKE2B_BYTES_PER_BLOCK : 0) + data->ll;

    if (dd == 0) {
        // INFO(Rafael): 'However, in the special case of an unkeyed empty message (kk = 0 and
        //                        ll = 0), we still set dd = 1 and d[0] consists of all zeros.'
        dd = 1;
    }

    // INFO(Rafael): When the hash is keyed the key block must be processed as the first block.

    while (dd % KRYPTOS_BLAKE2B_BYTES_PER_BLOCK) {
        dd++;
    }

    if ((in_head = (kryptos_u8_t *) kryptos_newseg(dd)) == NULL) {
        goto kryptos_blake2b_epilogue;
    }

    in = in_head;
    in_tail = in_head + dd;

    memset(in_head, 0, dd);

    dd /= KRYPTOS_BLAKE2B_BYTES_PER_BLOCK;

    if (data->kk > 0) {
        memcpy(in_head, data->key, data->kk);
        memcpy(in_head + KRYPTOS_BLAKE2B_BYTES_PER_BLOCK, data->input, data->ll);
    } else {
        memcpy(in_head, data->input, data->ll);
    }

    p->t[0] = KRYPTOS_BLAKE2B_BYTES_PER_BLOCK;
    p->t[1] = 0;

    kryptos_blake2_get_next_m_chunk(p->m[ 0], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 1], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 2], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 3], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 4], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 5], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 6], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 7], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 8], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[ 9], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[10], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[11], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[12], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[13], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[14], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
    kryptos_blake2_get_next_m_chunk(p->m[15], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);

    if (dd > 1) {
        for (i = 0; i < dd - 1; i++) {

            kryptos_blake2b_F(p);

            p->t[0] += KRYPTOS_BLAKE2B_BYTES_PER_BLOCK;

            if (p->t[0] < KRYPTOS_BLAKE2B_BYTES_PER_BLOCK) {
                p->t[1] += 1;
            }

            kryptos_blake2_get_next_m_chunk(p->m[ 0], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 1], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 2], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 3], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 4], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 5], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 6], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 7], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 8], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[ 9], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[10], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[11], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[12], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[13], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[14], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
            kryptos_blake2_get_next_m_chunk(p->m[15], in, in_tail, kryptos_get_u64_as_little_endian, kryptos_u64_rev);
        }
    }

    p->f = 1;

    if (data->kk == 0) {
        p->t[0] = data->ll;
        p->t[1] = 0;
    } else {
        p->t[0] = data->ll + KRYPTOS_BLAKE2B_BYTES_PER_BLOCK;
        p->t[1] = 0;
    }

    kryptos_blake2b_F(p);

    if ((data->h = (kryptos_u8_t *) kryptos_newseg(data->nn)) == NULL) {
        goto kryptos_blake2b_epilogue;
    }

    i = 0;
    t = 0;

    while (data->h_size < data->nn && i < 8) {
        kryptos_cpy_u64_as_big_endian(temp, sizeof(temp), kryptos_u64_rev(p->h[i]));
        for (t = 0; t < 8 && data->h_size < data->nn; t++, data->h_size++) {
            data->h[data->h_size] = temp[t];
        }
        i++;
    }

kryptos_blake2b_epilogue:

    if (in_head != NULL) {
        kryptos_freeseg(in_head, in_tail - in_head);
    }

    memset(temp, 0, sizeof(temp));
    memset(p, 0, sizeof(struct kryptos_blake2s_ctx));
    i = t = dd = 0;
    in_head = in_tail = in = NULL;
}

#undef KRYPTOS_BLAKE2S_BYTES_PER_BLOCK

#undef KRYPTOS_BLAKE2B_BYTES_PER_BLOCK

#undef KRYPTOS_BLAKE2S224_HASH_SIZ

#undef KRYPTOS_BLAKE2S256_HASH_SIZE

#undef KRYPTOS_BLAKE2B384_HASH_SIZE

#undef KRYPTOS_BLAKE2B512_HASH_SIZE

#undef kryptos_blake2_R

#undef kryptos_blake2_ROT

#undef kryptos_blake2_G

#undef kryptos_blake2_SIGMA

#undef kryptos_blake2b_F

#undef kryptos_blake2s_F

#undef kryptos_blake2_init

#undef kryptos_blake2_get_next_m_chunk
