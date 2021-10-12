/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_hex.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <ctype.h>
#endif

#define kryptos_hex_nibble2ascii(n) ( ( (int)(n) >= 0 && (n) <= 9 ) ? 48 + (n) : 55 + (n) )

kryptos_u8_t *kryptos_u8_ptr_to_hex(const kryptos_u8_t *u8, const size_t u8_size, size_t *o_size) {
    static kryptos_u8_t nibble_lt[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    kryptos_u8_t *hex = NULL, *hp;
    const kryptos_u8_t *u8_p, *u8_p_end;

    if (o_size != NULL && u8 != NULL && u8_size > 0 && (hex = (kryptos_u8_t *)kryptos_newseg((u8_size << 1) + 1)) != NULL) {
        u8_p = u8;
        u8_p_end = u8_p + u8_size;

        hp = hex;

        while (u8_p != u8_p_end) {
            hp[0] = nibble_lt[(*u8_p) >> 0x4];
            hp[1] = nibble_lt[(*u8_p) &  0xF];
            hp += 2;
            u8_p += 1;
        }

        *o_size = hp - hex;
        *hp = 0;
    }

    return hex;
}

void kryptos_u32_to_hex(kryptos_u8_t *buf, const size_t buf_size, const kryptos_u32_t u32) {
    if (buf == NULL || buf_size < 9) {
        return;
    }

        *buf   = kryptos_hex_nibble2ascii(u32 >> 28);
    *(buf + 1) = kryptos_hex_nibble2ascii((u32 >> 24) & 0xf);
    *(buf + 2) = kryptos_hex_nibble2ascii((u32 >> 20) & 0xf);
    *(buf + 3) = kryptos_hex_nibble2ascii((u32 >> 16) & 0xf);
    *(buf + 4) = kryptos_hex_nibble2ascii((u32 >> 12) & 0xf);
    *(buf + 5) = kryptos_hex_nibble2ascii((u32 >>  8) & 0xf);
    *(buf + 6) = kryptos_hex_nibble2ascii((u32 >>  4) & 0xf);
    *(buf + 7) = kryptos_hex_nibble2ascii(u32 & 0xf);
    *(buf + 8) = 0;
}

void kryptos_u64_to_hex(kryptos_u8_t *buf, const size_t buf_size, const kryptos_u64_t u64) {
    if (buf == NULL || buf_size < 17) {
        return;
    }

         *buf   = kryptos_hex_nibble2ascii(u64 >> 60);
    *(buf +  1) = kryptos_hex_nibble2ascii((u64 >> 56) & 0xf);
    *(buf +  2) = kryptos_hex_nibble2ascii((u64 >> 52) & 0xf);
    *(buf +  3) = kryptos_hex_nibble2ascii((u64 >> 48) & 0xf);
    *(buf +  4) = kryptos_hex_nibble2ascii((u64 >> 44) & 0xf);
    *(buf +  5) = kryptos_hex_nibble2ascii((u64 >> 40) & 0xf);
    *(buf +  6) = kryptos_hex_nibble2ascii((u64 >> 36) & 0xf);
    *(buf +  7) = kryptos_hex_nibble2ascii((u64 >> 32) & 0xf);
    *(buf +  8) = kryptos_hex_nibble2ascii((u64 >> 28) & 0xf);
    *(buf +  9) = kryptos_hex_nibble2ascii((u64 >> 24) & 0xf);
    *(buf + 10) = kryptos_hex_nibble2ascii((u64 >> 20) & 0xf);
    *(buf + 11) = kryptos_hex_nibble2ascii((u64 >> 16) & 0xf);
    *(buf + 12) = kryptos_hex_nibble2ascii((u64 >> 12) & 0xf);
    *(buf + 13) = kryptos_hex_nibble2ascii((u64 >>  8) & 0xf);
    *(buf + 14) = kryptos_hex_nibble2ascii((u64 >>  4) & 0xf);
    *(buf + 15) = kryptos_hex_nibble2ascii(u64 & 0xf);
    *(buf + 16) = 0;
}

#undef kryptos_hex_nibble2ascii
