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
#include <kryptos.h>
#if !defined(KRYPTOS_KERNEL_MODE)
# include <string.h>
#endif

struct gcm_ghash_block_ctx {
    kryptos_u32_t u32[4];
};

static int kryptos_gcm_ghash(const kryptos_u8_t *h,
                             const kryptos_u8_t *a, const size_t a_size,
                             const kryptos_u8_t *c, const size_t c_size, kryptos_u8_t *y);

static kryptos_task_result_t kryptos_gcm_tag(kryptos_u8_t *c, const size_t c_size,
                                             const size_t iv_size,
                                             kryptos_u8_t *key, const size_t key_size,
                                             const kryptos_u8_t *a, const size_t a_size,
                                             kryptos_gcm_e_func E, void *E_arg, kryptos_u8_t *tag);

/*static void print_buf(kryptos_u8_t *buf, size_t buf_size) {
    kryptos_u8_t *bp, *bp_end;
    bp = buf;
    bp_end = bp + buf_size;
    while (bp != bp_end) {
        printf("%.2X", *bp);
        bp++;
    }
}*/

kryptos_task_result_t kryptos_gcm_auth(kryptos_u8_t **c, size_t *c_size,
                                       const size_t iv_size,
                                       kryptos_u8_t *key, const size_t key_size,
                                       const kryptos_u8_t *a, const size_t a_size,
                                       kryptos_gcm_e_func E, void *E_arg) {
    kryptos_u8_t tag[16];
    kryptos_task_result_t result;
    kryptos_u8_t *nc;

    if ((result = kryptos_gcm_tag(*c, *c_size, iv_size, key, key_size, a, a_size, E, E_arg, tag)) == kKryptosSuccess) {
        if ((nc = (kryptos_u8_t *) kryptos_newseg(*c_size + 16)) == NULL) {
            result = kKryptosProcessError;
            goto kryptos_gcm_auth_epilogue;
        }
        memcpy(nc, tag, 16);
        memcpy(nc + 16, *c, *c_size);
        kryptos_freeseg(*c, *c_size);
        *c = nc;
        *c_size += 16;
    }

kryptos_gcm_auth_epilogue:

    memset(tag, 0, sizeof(tag));

    return result;
}

kryptos_task_result_t kryptos_gcm_verify(kryptos_u8_t **c, size_t *c_size,
                                         const size_t iv_size,
                                         kryptos_u8_t *key, const size_t key_size,
                                         const kryptos_u8_t *a, const size_t a_size,
                                         kryptos_gcm_e_func E, void *E_arg) {
    kryptos_task_result_t result = kKryptosProcessError;
    kryptos_u8_t tag[16];
    kryptos_u8_t *nc;

    if (*c_size >= 16 &&
        (result = kryptos_gcm_tag(*c + 16, *c_size - 16, iv_size,
                                  key, key_size, a, a_size, E, E_arg, tag)) == kKryptosSuccess) {
        if (memcmp(tag, *c, 16) != 0) {
            result = kKryptosGMACError;
            goto kryptos_gcm_verify_epilogue;
        }

        if ((nc = (kryptos_u8_t *) kryptos_newseg(*c_size - 16)) == NULL) {
            result = kKryptosProcessError;
            goto kryptos_gcm_verify_epilogue;
        }

        memcpy(nc, *c + 16, *c_size - 16);
        kryptos_freeseg(*c, *c_size);
        *c = nc;
        *c_size -= 16;
    }

kryptos_gcm_verify_epilogue:

    memset(tag, 0, sizeof(tag));

    return result;
}

void kryptos_gcm_gf_mul(const kryptos_u32_t *x, const kryptos_u32_t *y, kryptos_u32_t *z) {
    kryptos_u32_t v[4], t[4], zz[4];
    size_t i;

    zz[0] = zz[1] = zz[2] = zz[3] = 0;
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
            zz[0] ^= v[0];
            zz[1] ^= v[1];
            zz[2] ^= v[2];
            zz[3] ^= v[3];
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

    z[0] = zz[0]; z[1] = zz[1]; z[2] = zz[2]; z[3] = zz[3];

#undef kryptos_gcm_lsh128

#undef kryptos_gcm_rsh128
}

static kryptos_task_result_t kryptos_gcm_tag(kryptos_u8_t *c, const size_t c_size,
                                             const size_t iv_size,
                                             kryptos_u8_t *key, const size_t key_size,
                                             const kryptos_u8_t *a, const size_t a_size,
                                             kryptos_gcm_e_func E, void *E_arg, kryptos_u8_t *tag) {
    kryptos_u8_t *H = NULL, *Y0 = NULL, *tp, *tp_end, *hp, *hp_end;
    kryptos_task_result_t result = kKryptosProcessError;
    size_t H_size, Y_size;

    // INFO(Rafael): By design, the iv is embedded in the ciphertext (as its first block).

    // INFO(Rafael): 'H = E(K, 0^{128})'.

    if (E == NULL || (result = E(&H, &H_size, key, key_size, E_arg)) != kKryptosSuccess) {
        goto kryptos_gcm_tag_epilogue;
    }

    if ((Y0 = (kryptos_u8_t *) kryptos_newseg(16)) == NULL) {
        goto kryptos_gcm_tag_epilogue;
    }

    // INFO(Rafael): 'Y_0 = IV||0^{31}1'. If len(IV) = 96, otherwise
    //               'Y_0 = GHASH(H, {}, IV)'.

    if (iv_size != 12) {
        if (kryptos_gcm_ghash(H, NULL, 0, c, 16, Y0) == 0) {
            goto kryptos_gcm_tag_epilogue;
        }
    } else {
        // WARN(Rafael): By design iv_size is always equals to 16. So this code, until now, will never be hit.
        memcpy(Y0, c, 12);
        Y0[12] = Y0[13] = Y0[14] = 0x00;
        Y0[15] = 0x01;
    }

    // INFO(Rafael): 'T = MSB_t(GHASH(H, A, C) ^ E(K, Y_0))'. Here we will assume t equals to 128.

    if (kryptos_gcm_ghash(H, a, a_size, c + iv_size, c_size - iv_size, tag) == 0) {
        goto kryptos_gcm_tag_epilogue;
    }

    Y_size = 16;

    if ((result = E(&Y0, &Y_size, key, key_size, E_arg)) != kKryptosSuccess) {
        goto kryptos_gcm_tag_epilogue;
    }

    tp = tag;
    tp_end = tag + 16;
    hp = Y0;
    hp_end = Y0 + 16;

    while (tp != tp_end && hp != hp_end) {
        *tp = *tp ^ *hp;
        tp++;
        hp++;
    }

    result = kKryptosSuccess;

kryptos_gcm_tag_epilogue:

    if (H != NULL) {
        kryptos_freeseg(H, H_size);
    }

    if (Y0 != NULL) {
        kryptos_freeseg(Y0, 16);
    }

    return result;
}

static int kryptos_gcm_ghash(const kryptos_u8_t *h,
                             const kryptos_u8_t *a, const size_t a_size,
                             const kryptos_u8_t *c, const size_t c_size, kryptos_u8_t *y) {
    kryptos_u32_t H[4], X[4];
    kryptos_u64_t l[2];
    size_t b, offset;
    struct gcm_ghash_block_ctx *A = NULL, *C = NULL, L;
    struct gcm_ghash_data_ancillary_ctx {
        struct gcm_ghash_block_ctx *block;
        size_t block_size;
    } ublocks[3], *ubp, *ubp_end;
    kryptos_u8_t *temp = NULL;
    size_t temp_size[2] = { 0, 0 }, A_size = 0, C_size = 0;
    int no_error = 0;

    H[0] = kryptos_get_u32_as_big_endian(h, 16);
    H[1] = kryptos_get_u32_as_big_endian(h +  4, 12);
    H[2] = kryptos_get_u32_as_big_endian(h +  8,  8);
    H[3] = kryptos_get_u32_as_big_endian(h + 12,  4);

#define GCM_GHASH_WORD(d, i, j) (d)[(i)].u32[(j)]

#define GCM_GHASH_LD_BYTES(ctx, buf, buf_size, off, ctr) {\
    ctr = 0;\
    off = 0;\
    while (off < buf_size) {\
        GCM_GHASH_WORD(ctx, ctr, 0) = kryptos_get_u32_as_big_endian(buf + off, buf_size - off);\
        off += 4;\
        if (offset == buf_size) {\
            continue;\
        }\
        GCM_GHASH_WORD(ctx, ctr, 1) = kryptos_get_u32_as_big_endian(buf + off, buf_size - off);\
        offset += 4;\
        if (off == buf_size) {\
            continue;\
        }\
        GCM_GHASH_WORD(ctx, ctr, 2) = kryptos_get_u32_as_big_endian(buf + off, buf_size - off);\
        offset += 4;\
        if (off == buf_size) {\
            continue;\
        }\
        GCM_GHASH_WORD(ctx, ctr, 3) = kryptos_get_u32_as_big_endian(buf + off, buf_size - off);\
        off += 4;\
        ctr++;\
    }\
}

    if (a_size > 0) {
        // WARN(Rafael): The original spec states that the size of the additional authenticated data
        //               can vary from 1 to 128-bits. Here I am not limiting it, thus this GHASH implementation
        //               accepts AAD buffers greater than 16 bytes. Handling the AAD as the same way of C, consuming
        //               the buffer as 128-bit blocks per iteration (XORing + GF multiplication).

        temp_size[0] = a_size;

        while ((temp_size[0] % 16)) {
            temp_size[0]++;
        }

        if ((temp = (kryptos_u8_t *) kryptos_newseg(temp_size[0])) == NULL) {
            goto kryptos_gcm_ghash_epilogue;
        }

        if (temp_size[0] != a_size) {
            memset(temp, 0, temp_size[0]);
        }

        memcpy(temp, a, a_size);

        A_size = temp_size[0] >> 4;

        A = (struct gcm_ghash_block_ctx *) kryptos_newseg(sizeof(struct gcm_ghash_block_ctx) * A_size);

        if (A == NULL) {
            goto kryptos_gcm_ghash_epilogue;
        }

        memset(A, 0, sizeof(struct gcm_ghash_block_ctx) * A_size);

        GCM_GHASH_LD_BYTES(A, temp, temp_size[0], offset, b)

        kryptos_freeseg(temp, temp_size[0]);
    }

    temp_size[1] = c_size;

    while ((temp_size[1] % 16)) {
        temp_size[1]++;
    }

    if ((temp = (kryptos_u8_t *) kryptos_newseg(temp_size[1])) == NULL) {
        goto kryptos_gcm_ghash_epilogue;
    }

    if (temp_size[1] != c_size) {
        memset(temp, 0, temp_size[1]);
    }

    memcpy(temp, c, c_size);

    C_size = temp_size[1] >> 4;

    C = (struct gcm_ghash_block_ctx *) kryptos_newseg(sizeof(struct gcm_ghash_block_ctx) * C_size);

    if (C == NULL) {
        goto kryptos_gcm_ghash_epilogue;
    }

    memset(C, 0, sizeof(struct gcm_ghash_block_ctx) * C_size);

    GCM_GHASH_LD_BYTES(C, temp, temp_size[1], offset, b)

    kryptos_freeseg(temp, temp_size[1]);
    temp = NULL;

    // INFO(Rafael): Here is my simplified version of the GHASH loop.
    //
    // The loop over ublocks[0] is equivalent to:
    //         'X_i = (X_{i-1} ^ A_i) x H', and also,
    //         'X_i = (X_{m - 1} ^ (A*_{m}||0^{128-v})) x H'. Because 'A' was previously padded.
    //
    // The loop over ublocks[1] is equivalent to:
    //          'X_i = (X_{i-1} ^ C_{i - m}) x H', and also,
    //          'X_i = (X_{i-1} ^ (C*_{n}||0^{128-u})) x H'. Because 'C' was previously padded.
    //
    // It avoids tricky and less intuitive indexing by offsets as suggested by the original spec.
    //
    // This simplification also generalizes the last step of GHASH as a last additional iteration.
    // Thus, the loop over ublocks[2] is equivalent to:
    //          'X_i = (X_{m + n} ^ (len(A)||len(C))) x H'.
    //

    ublocks[0].block = A;
    ublocks[0].block_size = A_size;
    ublocks[1].block = C;
    ublocks[1].block_size = C_size;

    l[0] = (kryptos_u64_t) a_size << 3;
    l[1] = (kryptos_u64_t) c_size << 3;

    L.u32[0] = l[0] >> 32;
    L.u32[1] = l[0] & 0xFFFFFF;
    L.u32[2] = l[1] >> 32;
    L.u32[3] = l[1] & 0xFFFFFF;

    ublocks[2].block = &L;
    ublocks[2].block_size = 1;

    ubp = &ublocks[0];
    ubp_end = ubp + 3;

    X[0] = X[1] = X[2] = X[3] = 0;

    while (ubp != ubp_end) {
        for (b = 0; b < ubp->block_size; b++) {
            X[0] ^= GCM_GHASH_WORD(ubp->block, b, 0);
            X[1] ^= GCM_GHASH_WORD(ubp->block, b, 1);
            X[2] ^= GCM_GHASH_WORD(ubp->block, b, 2);
            X[3] ^= GCM_GHASH_WORD(ubp->block, b, 3);
            kryptos_gcm_gf_mul(X, H, X);
        }
        ubp++;
    }

    /* ----- DEPRECATED -----
    // WARN(Rafael): The old GHASH loop based on the spec. I find it worse than the current one. Deprecated.
    for (b = 1; b < block_nr; b++) {
        if (b >= 1 && (b - 1) < A_size) {
            // INFO(Rafael): 'X_i = (X_{i-1} ^ A_i) x H', and also,
            //               'X_i = (X_{m - 1} ^ (A*_{m}||0^{128-v})) x H'. Because 'A' was previously padded.
            X[0] ^= GCM_GHASH_WORD(A, b - 1, 0);
            X[1] ^= GCM_GHASH_WORD(A, b - 1, 1);
            X[2] ^= GCM_GHASH_WORD(A, b - 1, 2);
            X[3] ^= GCM_GHASH_WORD(A, b - 1, 3);
        } else {
            // INFO(Rafael): 'X_i = (X_{i-1} ^ C_{i - m}) x H', and also,
            //               'X_i = (X_{i-1} ^ (C*_{n}||0^{128-u})) x H'. Because 'C' was previously padded.
            X[0] ^= GCM_GHASH_WORD(C, b - A_size - 1, 0);
            X[1] ^= GCM_GHASH_WORD(C, b - A_size - 1, 1);
            X[2] ^= GCM_GHASH_WORD(C, b - A_size - 1, 2);
            X[3] ^= GCM_GHASH_WORD(C, b - A_size - 1, 3);
        }
        kryptos_gcm_gf_mul(X, H, X);
    }

    // INFO(Rafael): 'X_i = (X_{m + n} ^ (len(A)||len(C))) x H'.

    l[0] = (kryptos_u64_t) a_size << 3;
    l[1] = (kryptos_u64_t) c_size << 3;

    L.u32[0] = l[0] >> 32;
    L.u32[1] = l[0] & 0xFFFFFF;
    L.u32[2] = l[1] >> 32;
    L.u32[3] = l[1] & 0xFFFFFF;

    X[0] ^= GCM_GHASH_WORD(&L, 0, 0);
    X[1] ^= GCM_GHASH_WORD(&L, 0, 1);
    X[2] ^= GCM_GHASH_WORD(&L, 0, 2);
    X[3] ^= GCM_GHASH_WORD(&L, 0, 3);
    kryptos_gcm_gf_mul(X, H, X); ----- DEPRECATED -----*/

    // INFO(Rafael): Considering 'y' fits, at least, 16 bytes (our 128-bit GHASH output).

    kryptos_cpy_u32_as_big_endian(y, 16, X[0]);
    kryptos_cpy_u32_as_big_endian(y +  4, 12, X[1]);
    kryptos_cpy_u32_as_big_endian(y +  8,  8, X[2]);
    kryptos_cpy_u32_as_big_endian(y + 12,  4, X[3]);

    l[0] = l[1] = 0;
    L.u32[0] = L.u32[1] = L.u32[2] = L.u32[3] = 0;

    no_error = 1;

#undef GCM_GHASH_WORD
#undef GCM_GHASH_LD_BYTES

kryptos_gcm_ghash_epilogue:

    if (A != NULL) {
        kryptos_freeseg(A, sizeof(struct gcm_ghash_block_ctx) * A_size);
    }

    if (C != NULL) {
        kryptos_freeseg(C, sizeof(struct gcm_ghash_block_ctx) * C_size);
    }

    if (temp != NULL) {
        kryptos_freeseg(temp, (temp_size[0] != 0) ? temp_size[0] : temp_size[1]);
    }

    return no_error;
}
