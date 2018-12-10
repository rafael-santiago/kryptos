/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_gcm_utils.h>

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

    v[0] = v[1] = v[2] = v[3] =
    t[0] = t[1] = t[2] = t[3] = 0;
}

#undef kryptos_gcm_lsh128

#undef kryptos_gcm_rsh128
