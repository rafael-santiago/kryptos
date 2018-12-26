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
            result = kKryptosProcessError;
            goto kryptos_gcm_verify_epilogue;
        }

        if ((nc = (kryptos_u8_t *) kryptos_newseg(*c_size - 16)) == NULL) {
            result = kKryptosProcessError;
            goto kryptos_gcm_verify_epilogue;
        }

        memcpy(nc, *c, *c_size - 16);
        kryptos_freeseg(*c, *c_size);
        *c = nc;
        *c_size -= 16;
    }

kryptos_gcm_verify_epilogue:

    memset(tag, 0, sizeof(tag));

    return result;
}

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

static kryptos_task_result_t kryptos_gcm_tag(kryptos_u8_t *c, const size_t c_size,
                                             const size_t iv_size,
                                             kryptos_u8_t *key, const size_t key_size,
                                             const kryptos_u8_t *a, const size_t a_size,
                                             kryptos_gcm_e_func E, void *E_arg, kryptos_u8_t *tag) {
    kryptos_u8_t *H = NULL, *Y0 = NULL, *tp, *tp_end, *hp, *hp_end;
    kryptos_task_result_t result = kKryptosProcessError;
    size_t H_size, Y_size;

    // INFO(Rafael): 'H = E(K, 0^{128})'.

    if (E == NULL || E(&H, &H_size, key, key_size, E_arg) != kKryptosSuccess) {
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
        if ((Y0 = (kryptos_u8_t *) kryptos_newseg(16)) == NULL) {
            goto kryptos_gcm_tag_epilogue;
        }
        memcpy(Y0, c, 12);
        Y0[12] = Y0[13] = Y0[14] = 0x00;
        Y0[15] = 0x01;
    }

    // INFO(Rafael): 'T = MSB_t(GHASH(H, A, C) ^ E(K, Y_0))'. Here we will assume t equals to 128.

    if (kryptos_gcm_ghash(H, a, a_size + 16, c, c_size - 16, tag) == 0) {
        goto kryptos_gcm_tag_epilogue;
    }

    Y_size = 16;

    if (E(&Y0, &Y_size, key, key_size, E_arg) != kKryptosSuccess) {
        goto kryptos_gcm_tag_epilogue;
    }

    tp = tag;
    tp_end = tag + 16;
    hp = H;
    hp_end = H + H_size;

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
    kryptos_u32_t H[4];
    kryptos_u64_t l[2];
    size_t block_nr, b, offset;
    struct gcm_ghash_block_ctx *X = NULL, *A = NULL, *C = NULL, L;
    kryptos_u8_t *temp = NULL;
    size_t temp_size[2] = { 0, 0 };
    int no_error = 0;

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

    if (a_size > 0) {
        temp_size[0] = a_size;

        while ((temp_size[0] % 4)) {
            temp_size[0]++;
        }

        block_nr = temp_size[0];

        if ((temp = (kryptos_u8_t *) kryptos_newseg(temp_size[0])) == NULL) {
            goto kryptos_gcm_ghash_epilogue;
        }

        if (temp_size[0] != a_size) {
            memset(temp, 0, temp_size[0]);
        }

        memcpy(temp, a, a_size);

        A = (struct gcm_ghash_block_ctx *) kryptos_newseg(sizeof(struct gcm_ghash_block_ctx) * (temp_size[0] >> 2));

        if (A == NULL) {
            goto kryptos_gcm_ghash_epilogue;
        }

        memset(A, 0, sizeof(struct gcm_ghash_block_ctx) * (temp_size[0] >> 2));

        GCM_GHASH_LD_BYTES(A, temp, temp_size[0], offset, b)

        kryptos_freeseg(temp, temp_size[0]);
    }

    temp_size[1] = c_size;

    while ((temp_size[1] % 4)) {
        temp_size[1]++;
    }

    if ((temp = (kryptos_u8_t *) kryptos_newseg(temp_size[1])) == NULL) {
        goto kryptos_gcm_ghash_epilogue;
    }

    block_nr += temp_size[1];

    if (temp_size[1] != c_size) {
        memset(temp, 0, temp_size[1]);
    }

    memcpy(temp, c, c_size);

    C = (struct gcm_ghash_block_ctx *) kryptos_newseg(sizeof(struct gcm_ghash_block_ctx) * (temp_size[1] >> 4));

    if (C == NULL) {
        goto kryptos_gcm_ghash_epilogue;
    }

    memset(C, 0, sizeof(struct gcm_ghash_block_ctx) * (temp_size[1] >> 4));

    GCM_GHASH_LD_BYTES(C, temp, temp_size[1], offset, b)

    kryptos_freeseg(temp, temp_size[1]);
    temp = NULL;

    block_nr >>= 2;
    X = (struct gcm_ghash_block_ctx *) kryptos_newseg(sizeof(struct gcm_ghash_block_ctx) * (block_nr + 1));

    if (X == NULL) {
        goto kryptos_gcm_ghash_epilogue;
    }


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

    l[0] = (kryptos_u64_t) a_size << 3;
    l[1] = (kryptos_u64_t) c_size << 3;

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

    no_error = 1;

#undef GCM_GHASH_BLOCK
#undef GCM_GHASH_WORD
#undef GCM_GHASH_LD_BYTES

kryptos_gcm_ghash_epilogue:

    if (X != NULL) {
        kryptos_freeseg(X, sizeof(struct gcm_ghash_block_ctx) * (block_nr + 1));
    }

    if (A != NULL) {
        kryptos_freeseg(A, sizeof(struct gcm_ghash_block_ctx) * (temp[0] >> 2));
    }

    if (c != NULL) {
        kryptos_freeseg(C, sizeof(struct gcm_ghash_block_ctx) * (temp[1] >> 2));
    }

    if (temp != NULL) {
        kryptos_freeseg(temp, (temp_size[0] != 0) ? temp_size[0] : temp_size[1]);
    }

    return no_error;
}
