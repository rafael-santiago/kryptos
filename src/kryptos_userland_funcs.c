/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_userland_funcs.h>

#if defined(KRYPTOS_KERNEL_MODE) && !defined(__NetBSD__)

kryptos_u8_t toupper(const kryptos_u8_t c) {
    static kryptos_u8_t kryptos_toupper_lt[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                                                 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

    if (c >= 'a' && c <= 'z') {
        return kryptos_toupper_lt[c - 'a'];
    }

    return c;
}

#endif

#if defined(KRYPTOS_MITIGATE_TIMING_ATTACKS)

int memcmp(const void *s1, const void *s2, size_t n) {
    int result = 0;
    kryptos_u8_t *b1 = (kryptos_u8_t *)s1, *b2 = (kryptos_u8_t *)s2;

    while (n-- > 0) {
        result |= *(b1++) - *(b2++);
    }

    return result;
}

#endif

#if defined(KRYPTOS_ENSURE_MEMSET_CLEANUPS)
void *kryptos_memset(void *s, int c, size_t n) {
    kryptos_u8_t *bp, *bp_end, b;

    if (s == NULL) {
        return NULL;
    }

    bp = (kryptos_u8_t *)s;
    bp_end = bp + n;
    b = (kryptos_u8_t)c;

    while (bp != bp_end) {
        *bp = b;
        bp++;
    }

    return s;
}
#endif
