/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_hex.h>

void kryptos_u32_to_hex(kryptos_u8_t *buf, const size_t buf_size, const kryptos_u32_t u32) {
    if (buf == NULL || buf_size < 9) {
        return;
    }

#define kryptos_hex_nibble2ascii(n) ( ( (n) >= 0 && (n) <= 9 ) ? 48 + (n) : 55 + (n) )

        *buf   = kryptos_hex_nibble2ascii(u32 >> 28);
    *(buf + 1) = kryptos_hex_nibble2ascii((u32 >> 24) & 0xf);
    *(buf + 2) = kryptos_hex_nibble2ascii((u32 >> 20) & 0xf);
    *(buf + 3) = kryptos_hex_nibble2ascii((u32 >> 16) & 0xf);
    *(buf + 4) = kryptos_hex_nibble2ascii((u32 >> 12) & 0xf);
    *(buf + 5) = kryptos_hex_nibble2ascii((u32 >>  8) & 0xf);
    *(buf + 6) = kryptos_hex_nibble2ascii((u32 >>  4) & 0xf);
    *(buf + 7) = kryptos_hex_nibble2ascii(u32 & 0xf);
    *(buf + 8) = 0;

#undef kryptos_hex_nibble2ascii
}
