/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_gcm_utils.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_memory.h>
#include <string.h>

struct gcm_ghash_block_ctx {
    kryptos_u32_t u32[4];
};

static void kryptos_gcm_ghash(const kryptos_u8_t *h,
                              const kryptos_u8_t *a, const size_t a_size,
                              const kryptos_u8_t *c, const size_t c_size, kryptos_u8_t *y);

void kryptos_gcm_gf_mul(const kryptos_u32_t *x, const kryptos_u32_t *y, kryptos_u32_t *z) {
    kryptos_u32_t v[4], t[4];
    size_t i;

    z[0] = z[1] = z[2] = z[3] = 0;
    v[0] = y[0]; v[1] = y[1]; v[2] = y[2]; v[3] = y[3];
    t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3];

#define kryptos_gcm_lsh128(b) {\
    b[0] = (b[0] << 1) | (b[1] >> 31);\
    b[1] = (b[1] << 1) | (b[2] >> 31);\
    b[2] = (b[2] << 1) | (b[3] >> 31);\
    b[3] <<= 1;\
}

#define kryptos_gcm_rsh128(b) {\
    b[3] = (b[2] << 31) | (b[3] >> 1);\
    b[2] = (b[1] << 31) | (b[2] >> 1);\
    b[1] = (b[0] << 31) | (b[1] >> 1);\
    b[0] >>= 1;\
}

    for (i = 0; i < 128; i++) {
        if (t[0] >> 31) {
            z[0] ^= v[0];
            z[1] ^= v[1];
            z[2] ^= v[2];
            z[3] ^= v[3];
        }

        if (v[3] & 0x1) {
            kryptos_gcm_rsh128(v);
            v[0] ^= 0xE1000000;
        } else {
            kryptos_gcm_rsh128(v);
        }

        kryptos_gcm_lsh128(t);
    }

    v[0] = v[1] = v[2] = v[3] = 0;

#undef kryptos_gcm_lsh128

#undef kryptos_gcm_rsh128
}

static void kryptos_gcm_ghash(const kryptos_u8_t *h,
                              const kryptos_u8_t *a, const size_t a_size,
                              const kryptos_u8_t *c, const size_t c_size, kryptos_u8_t *y) {
    kryptos_u32_t H[4];
    kryptos_u64_t l[2];
    size_t block_nr, b, offset;
    struct gcm_ghash_block_ctx *X = NULL, *A = NULL, *C = NULL, L;

    y = NULL;

    H[0] = kryptos_get_u32_as_big_endian(h, 16);
    H[1] = kryptos_get_u32_as_big_endian(h +  4, 12);
    H[2] = kryptos_get_u32_as_big_endian(h +  8,  8);
    H[3] = kryptos_get_u32_as_big_endian(h + 12,  4);

    block_nr = a_size + c_size;

#define GCM_GHASH_BLOCK(d, i) (d)[(i)].u32

#define GCM_GHASH_WORD(d, i, j) (d)[(i)].u32[(j)]

#define GCM_GHASH_LD_BYTES(ctx, buf, buf_size, off, ctr) {\
    ctr = 0;\
    off = 0;\
    while (off < buf_size) {\
        GCM_GHASH_WORD(A, ctr, 0) = kryptos_get_u32_as_big_endian(buf + off, buf_size - off);\
        off += 4;\
        if (offset == buf_size) {\
            continue;\
        }\
        GCM_GHASH_WORD(A, ctr, 1) = kryptos_get_u32_as_big_endian(buf + off, buf_size - off);\
        offset += 4;\
        if (off == buf_size) {\
            continue;\
        }\
        GCM_GHASH_WORD(A, ctr, 2) = kryptos_get_u32_as_big_endian(buf + off, buf_size - off);\
        offset += 4;\
        if (off == buf_size) {\
            continue;\
        }\
        GCM_GHASH_WORD(A, ctr, 3) = kryptos_get_u32_as_big_endian(buf + off, buf_size - off);\
        ctr++;\
    }\
}

    X = (struct gcm_ghash_block_ctx *) kryptos_newseg(sizeof(struct gcm_ghash_block_ctx) * (block_nr + 1));

    if (X == NULL) {
        goto kryptos_gcm_ghash_epilogue;
    }

    A = (struct gcm_ghash_block_ctx *) kryptos_newseg(sizeof(struct gcm_ghash_block_ctx) * a_size);

    if (A == NULL) {
        goto kryptos_gcm_ghash_epilogue;
    }

    memset(A, 0, sizeof(struct gcm_ghash_block_ctx) * a_size);

    GCM_GHASH_LD_BYTES(A, a, a_size, offset, b)

    C = (struct gcm_ghash_block_ctx *) kryptos_newseg(sizeof(struct gcm_ghash_block_ctx) * c_size);

    if (C == NULL) {
        goto kryptos_gcm_ghash_epilogue;
    }

    memset(C, 0, sizeof(struct gcm_ghash_block_ctx) * c_size);

    GCM_GHASH_LD_BYTES(C, c, c_size, offset, b)

    GCM_GHASH_WORD(X, 0, 0) = GCM_GHASH_WORD(X, 0, 1) = GCM_GHASH_WORD(X, 0, 2) = GCM_GHASH_WORD(X, 0, 3) = 0;

    for (b = 1; b < block_nr; b++) {
        if (b >= 1 && b < a_size) {
            // INFO(Rafael): 'X_i = (X_{i-1} ^ A_i) x H', and also,
            //               'X_i = (X_{m - 1} ^ (A*_{m}||0^{128-v})) x H'. Because 'A' was previously padded.
            GCM_GHASH_WORD(X, b, 0) = GCM_GHASH_WORD(X, b - 1, 0) ^ GCM_GHASH_WORD(A, b, 0);
            GCM_GHASH_WORD(X, b, 1) = GCM_GHASH_WORD(X, b - 1, 1) ^ GCM_GHASH_WORD(A, b, 1);
            GCM_GHASH_WORD(X, b, 2) = GCM_GHASH_WORD(X, b - 1, 2) ^ GCM_GHASH_WORD(A, b, 2);
            GCM_GHASH_WORD(X, b, 3) = GCM_GHASH_WORD(X, b - 1, 3) ^ GCM_GHASH_WORD(A, b, 3);
        } else {
            // INFO(Rafael): 'X_i = (X_{i-1} ^ C_{i - m}) x H', and also,
            //               'X_i = (X_{i-1} ^ (C*_{n}||0^{128-u})) x H'. Because 'C' was previously padded.
            GCM_GHASH_WORD(X, b, 0) = GCM_GHASH_WORD(X, b - 1, 0) ^ GCM_GHASH_WORD(C, b - a_size, 0);
            GCM_GHASH_WORD(X, b, 1) = GCM_GHASH_WORD(X, b - 1, 1) ^ GCM_GHASH_WORD(C, b - a_size, 1);
            GCM_GHASH_WORD(X, b, 2) = GCM_GHASH_WORD(X, b - 1, 0) ^ GCM_GHASH_WORD(C, b - a_size, 2);
            GCM_GHASH_WORD(X, b, 3) = GCM_GHASH_WORD(X, b - 1, 0) ^ GCM_GHASH_WORD(C, b - a_size, 3);
        }
        kryptos_gcm_gf_mul(GCM_GHASH_BLOCK(X, b), H, GCM_GHASH_BLOCK(X, b));
    }

    // INFO(Rafael): 'X_i = (X_{m + n} ^ (len(A)||len(C))) x H'.

    l[0] = (kryptos_u64_t) a_size;
    l[1] = (kryptos_u64_t) c_size;

    L.u32[0] = l[0] >> 32;
    L.u32[1] = l[0] & 0xFFFFFF;
    L.u32[2] = l[1] >> 32;
    L.u32[3] = l[1] & 0xFFFFFF;

    GCM_GHASH_WORD(X, block_nr, 0) = GCM_GHASH_WORD(X, block_nr - 1, 0) ^ GCM_GHASH_WORD(&L, 0, 0);
    GCM_GHASH_WORD(X, block_nr, 1) = GCM_GHASH_WORD(X, block_nr - 1, 1) ^ GCM_GHASH_WORD(&L, 0, 1);
    GCM_GHASH_WORD(X, block_nr, 2) = GCM_GHASH_WORD(X, block_nr - 1, 2) ^ GCM_GHASH_WORD(&L, 0, 2);
    GCM_GHASH_WORD(X, block_nr, 3) = GCM_GHASH_WORD(X, block_nr - 1, 3) ^ GCM_GHASH_WORD(&L, 0, 3);
    kryptos_gcm_gf_mul(GCM_GHASH_BLOCK(X, block_nr), H, GCM_GHASH_BLOCK(X, block_nr));

    // INFO(Rafael): Considering 'y' fits, at least, 16 bytes (our 128-bit GHASH output).

    kryptos_cpy_u32_as_big_endian(y, 16, GCM_GHASH_WORD(X, block_nr, 0));
    kryptos_cpy_u32_as_big_endian(y +  4, 12, GCM_GHASH_WORD(X, block_nr, 1));
    kryptos_cpy_u32_as_big_endian(y +  8,  8, GCM_GHASH_WORD(X, block_nr, 2));
    kryptos_cpy_u32_as_big_endian(y + 12,  4, GCM_GHASH_WORD(X, block_nr, 3));

    l[0] = l[1] = 0;
    L.u32[0] = L.u32[1] = L.u32[2] = L.u32[3] = 0;

#undef GCM_GHASH_BLOCK
#undef GCM_GHASH_WORD
#undef GCM_GHASH_LD_BYTES

kryptos_gcm_ghash_epilogue:

    if (X != NULL) {
        kryptos_freeseg(X, sizeof(struct gcm_ghash_block_ctx) * (block_nr + 1));
    }

    if (A != NULL) {
        kryptos_freeseg(A, sizeof(struct gcm_ghash_block_ctx) * a_size);
    }

}
