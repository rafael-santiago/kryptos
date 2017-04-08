/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_endianess_utils.h>
#include <string.h>

int kryptos_little_endian_cpu(void) {
    static int kryptos_little_endian = -1;
    static kryptos_u8_t *kryptos_test_seg = "\x01\x00\x00\x00";
    if (kryptos_little_endian == -1) {
        kryptos_little_endian = *(int *)kryptos_test_seg;
    }
    return (kryptos_little_endian == 1);
}

kryptos_u32_t kryptos_get_u32_as_big_endian(const kryptos_u8_t *data, const size_t data_size) {
    kryptos_u32_t value = 0;

    if ((data + sizeof(kryptos_u32_t)) > data + data_size) {
        return 0;
    }

    if (kryptos_little_endian_cpu()) {
        value = (kryptos_u32_t)(*(data)) << 24 |
                (kryptos_u32_t)(*(data + 1)) << 16 |
                (kryptos_u32_t)(*(data + 2)) <<  8 |
                (kryptos_u32_t)(*(data + 3));
    } else {
        value = *(kryptos_u32_t *)value;
    }

    return value;
}

kryptos_u8_t *kryptos_cpy_u32_as_big_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u32_t value) {
    if ((dest + sizeof(kryptos_u32_t)) > dest + dest_size) {
        return NULL;
    }

    if (kryptos_little_endian_cpu()) {
        *(dest) = value >> 24;
        *(dest + 1) = (value >> 16);
        *(dest + 2) = (value >> 8);
        *(dest + 3) = value;
    } else {
        memcpy(dest, &value, sizeof(kryptos_u32_t));
    }

    return dest;
}
