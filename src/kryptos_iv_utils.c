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

    while (iv != iv_p) {
        *block_p ^= *iv_p;
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
