/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_userland_funcs.h>

#ifdef KRYPTOS_KERNEL_MODE

kryptos_u8_t toupper(const kryptos_u8_t c) {
    static kryptos_u8_t kryptos_toupper_lt[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                                                 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

    if (c >= 'a' && c <= 'z') {
        return kryptos_toupper_lt[c - 'a'];
    }

    return c;
}

#endif
