/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_block_parser.h>

kryptos_u8_t *kryptos_block_parser(kryptos_u8_t *out, const size_t block_size,
                                   kryptos_u8_t *in, kryptos_u8_t *in_end, kryptos_u8_t **next) {
    kryptos_u8_t *out_p, *in_p;
    kryptos_u8_t *temp_next;

    if (in == NULL || in == in_end || next == NULL) {
        return NULL;
    }

    in_p = in;
    temp_next = in_p + block_size;
    if (temp_next > in_end) {
        temp_next = in_end;
    }
    out_p = out;

    while (in_p != temp_next) {
        *out_p = *in_p;
        in_p++;
        out_p++;
    }

    *next = temp_next;
    temp_next = NULL;

    return out;
}
