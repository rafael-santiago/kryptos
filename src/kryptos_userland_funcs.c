/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_userland_funcs.h>

#if defined(KRYPTOS_KERNEL_MODE) && !defined(__NetBSD__) && !defined(_WIN32)

int toupper(const int c) {
    static kryptos_u8_t kryptos_toupper_lt[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                                                 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };

    if (c >= 'a' && c <= 'z') {
        return kryptos_toupper_lt[c - 'a'];
    }

    return c;
}

#endif

int kryptos_memcmp(const void *s1, const void *s2, size_t n) {
    int result = 0;
    const kryptos_u8_t *b1 = (const kryptos_u8_t *)s1, *b2 = (const kryptos_u8_t *)s2;

    while (n-- > 0) {
        result |= *(b1++) - *(b2++);
    }

    return result;
}

void *kryptos_memset(void *s, int c, size_t n) {
#if !defined(__i386__) || defined(KRYPTOS_KERNEL_MODE)
    kryptos_u8_t *bp, *bp_end, b;
#endif

    if (s == NULL) {
        goto kryptos_memset_epilogue;
    }

#if defined(__i386__) && !defined(KRYPTOS_KERNEL_MODE)
    __asm__ __volatile__ ("pusha\n\t"
                          "cld\n\t"
                          "rep stosb\n\t"
                          "popa" : : "a"(c), "c"(n), "D"(s));
#else
    bp = (kryptos_u8_t *)s;
    bp_end = bp + n;
    b = (kryptos_u8_t)c;

    while (bp != bp_end) {
        *bp = b;
        bp++;
    }
#endif

kryptos_memset_epilogue:

    return s;
}

void *kryptos_memcpy(void *dest, const void *src, size_t n) {
#if !defined(__i386__) || defined(KRYPTOS_KERNEL_MODE)
    //void *dest_p, *src_p;
    kryptos_u8_t *dest_p;
    const kryptos_u8_t *src_p;
#endif

    if (dest == NULL) {
        goto kryptos_memcpy_epilogue;
    }

#if defined(__i386__) && !defined(KRYPTOS_KERNEL_MODE)
    __asm__ __volatile__("pusha\n\t"
                         "cld\n\t"
                         "rep movsb\n\t"
                         "popa" : : "c"(n), "D"(dest), "S"(src));
#else
    dest_p = (kryptos_u8_t *)dest;
    src_p = (const kryptos_u8_t *)src;

    while (n-- > 0) {
        *dest_p = *src_p;
        dest_p++;
        src_p++;
    }
#endif

kryptos_memcpy_epilogue:

    return dest;
}
