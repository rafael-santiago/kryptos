/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_endianness_utils.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define kryptos_u32_rev(w) ( ((w) << 24) | (((w) & 0x0000ff00) << 8) | (((w) & 0x00ff0000) >> 8) | ((w) >> 24) )

int kryptos_little_endian_cpu(void) {
    static int kryptos_little_endian = -1;
    static kryptos_u8_t *kryptos_test_seg = (kryptos_u8_t *)"\x01\x00\x00\x00";
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
        value = *(const kryptos_u32_t *)data;
    }

    return value;
}

kryptos_u32_t kryptos_get_u32_as_little_endian(const kryptos_u8_t *data, const size_t data_size) {
    return kryptos_u32_rev(kryptos_get_u32_as_big_endian(data, data_size));
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

kryptos_u8_t *kryptos_cpy_u32_as_little_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u32_t value) {
    return kryptos_cpy_u32_as_big_endian(dest, dest_size, kryptos_u32_rev(value));
}

kryptos_u16_t kryptos_get_u16_as_big_endian(const kryptos_u8_t *data, const size_t data_size) {
    kryptos_u16_t value = 0;

    if ((data + sizeof(kryptos_u16_t)) > data + data_size) {
        return 0;
    }

    if (kryptos_little_endian_cpu()) {
        value = (kryptos_u16_t)(*(data)) <<  8 |
                (kryptos_u16_t)(*(data + 1));
    } else {
        value = *(const kryptos_u16_t *)data;
    }

    return value;
}

kryptos_u8_t *kryptos_cpy_u16_as_big_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u16_t value) {
    if ((dest + sizeof(kryptos_u16_t)) > dest + dest_size) {
        return NULL;
    }

    if (kryptos_little_endian_cpu()) {
        *(dest) = (value >> 8);
        *(dest + 1) = value;
    } else {
        memcpy(dest, &value, sizeof(kryptos_u16_t));
    }

    return dest;
}

kryptos_u8_t *kryptos_cpy_u64_as_big_endian(kryptos_u8_t *dest, const size_t dest_size, const kryptos_u64_t value) {
    if ((dest + sizeof(kryptos_u64_t)) > dest + dest_size) {
        return NULL;
    }

    if (kryptos_little_endian_cpu()) {
        *(dest) = value >> 56;
        *(dest + 1) = (value >> 48);
        *(dest + 2) = (value >> 40);
        *(dest + 3) = (value >> 32);
        *(dest + 4) = (value >> 24);
        *(dest + 5) = (value >> 16);
        *(dest + 6) = (value >>  8);
        *(dest + 7) = value;
    } else {
        memcpy(dest, &value, sizeof(kryptos_u64_t));
    }

    return dest;
}

#undef kryptos_u32_rev
