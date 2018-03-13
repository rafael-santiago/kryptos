/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_iv_utils.h>

kryptos_u8_t *kryptos_apply_iv(kryptos_u8_t *block, const kryptos_u8_t *iv, const size_t size) {
    const kryptos_u8_t *iv_p, *iv_end;
    kryptos_u8_t *block_p;

    iv_p = iv;
    iv_end = iv_p + size;

    block_p = block;

    while (iv_p != iv_end) {
        *block_p = *block_p ^ *iv_p;
        iv_p++;
        block_p++;
    }

    return block;
}

void kryptos_iv_data_flush(kryptos_u8_t *iv, const kryptos_u8_t *y, const size_t size) {
    const kryptos_u8_t *y_p;
    kryptos_u8_t *iv_p, *iv_end;

    iv_p = iv;
    iv_end = iv_p + size;

    y_p = y;

    while (iv_p != iv_end) {
        *iv_p = *y_p;
        iv_p++;
        y_p++;
    }
}

void kryptos_iv_inc_u32(kryptos_u8_t *iv, const size_t iv_size) {
    kryptos_u32_t u32_ctr = (kryptos_u32_t) iv[iv_size - 4] << 24 |
                            (kryptos_u32_t) iv[iv_size - 3] << 16 |
                            (kryptos_u32_t) iv[iv_size - 2] <<  8 |
                            (kryptos_u32_t) iv[iv_size - 1];

    u32_ctr += 1;

    iv[iv_size - 4] = u32_ctr >> 24;
    iv[iv_size - 3] = (u32_ctr & 0xFF0000) >> 16;
    iv[iv_size - 2] = (u32_ctr & 0xFF00) >> 8;
    iv[iv_size - 1] = u32_ctr & 0xFF;
}
