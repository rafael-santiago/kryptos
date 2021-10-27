/*
 *                                Copyright (C) 2021 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_djb2.h>

kryptos_u64_t kryptos_djb2(const kryptos_u8_t *input, const size_t input_size) {
    kryptos_u64_t sum = 5381;
    const kryptos_u8_t *ip = NULL, *ip_end = NULL;

    if (input == NULL || input_size == 0) {
        return sum;
    }

    ip = input;
    ip_end = ip + input_size;

    while (ip != ip_end) {
        sum = ((sum << 5) + sum) + *ip;
        ip++;
    }

    return sum;
}
